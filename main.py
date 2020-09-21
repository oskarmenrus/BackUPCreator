import BackUPCreator_sqlite
import datetime
import json
import random
import os
import sys
import string
import threading
import zipfile

import yadisk
from PyQt5 import QtWidgets
from pygost.gost3412 import *
from pygost.gost34112012 import *
from pygost.utils import *

import BackUPCreator_GUI
from info_messages import *


class HookLogic(QtWidgets.QMainWindow, BackUPCreator_GUI.MainWindowUi):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        with open('settings.json', 'r') as read_file:
            settings = json.load(read_file)

        self.local_copy.clicked.connect(self.local_directory)
        self.choose_folder.clicked.connect(self.show_directory)
        self.execute.clicked.connect(self.start_thread)
        self.decrypt.clicked.connect(self.files_to_decrypt)
        self.generate_key.clicked.connect(self.key_gen)
        self.my_token = settings['yDiskToken']
        self.input_key.setText(settings['default_key'])
        self.files = False
        self.local_dir = False
        self.decrypt_files = False

        info_message(self, hello_msg)
        info_message(self, welcome_msg + '\n' + separator)

    def show_directory(self):
        self.files = QtWidgets.QFileDialog.getExistingDirectory(None)
        self.decrypt_files = False
        info_message(self, 'Выбрана папка для создания архива:\n{}'.format(self.files) + '\n' + separator)

    def local_directory(self):
        self.local_dir = QtWidgets.QFileDialog.getExistingDirectory(None)
        info_message(self, 'Выбрана папка для локального хранения:\n{}'.format(self.local_dir) + '\n' + separator)

    def files_to_decrypt(self):
        self.decrypt_files = QtWidgets.QFileDialog.getOpenFileName(None)[0]
        self.files = False
        info_message(self, 'Выбран файл для расшифровки:\n{}'.format(self.decrypt_files) + '\n' + separator)

    def key_gen(self):
        def rand_string(s=''):
            while len(s) <= random.randint(16, 32):
                s += random.choice(string.ascii_letters)
            return s.encode()

        key = GOST34112012(digest_size=32)
        key.update(rand_string())
        self.input_key.setText(key.hexdigest())

    @staticmethod
    def file_len(file_path):
        file_len = len(open(file_path, 'rb').read())
        if file_len % 16 != 0:
            i = 0
            while file_len % 16 != 0:
                file_len += 1
                i += 1
            add = open(file_path, 'ab')
            add.write(b' ' * i)
            add.close()

    def back_up_creator(self, local_dir, backup, key):
        if not local_dir:
            store_place = '{}{}Backups'.format(os.path.abspath(os.curdir), os.sep)
            encrypted_place = '{}{}EncryptedFiles'.format(os.path.abspath(os.curdir), os.sep)
        else:
            store_place = local_dir + os.sep + 'Backups'
            encrypted_place = local_dir + os.sep + 'EncryptedFiles'

        if not os.path.exists(store_place):
            os.mkdir(store_place)

        zip_name = self.zip_name()
        info_message(self, 'Имя архива: {}'.format(zip_name))
        arch_path = store_place + os.sep + zip_name
        self.create_zip(zip_name, store_place, backup)
        info_message(self, 'Архив успешно создан!')
        dec_bits = self.first_bits(arch_path)
        self.file_len(arch_path)

        if self.encrypt_check.isChecked() and self.hash_check.isChecked() and self.cloud_check.isChecked():
            file_hash = self.get_hash_stribog(arch_path.replace('\\', '/'))
            info_message(self, 'Хэш файла вычислен успешно...')
            store, enc_zip_name = self.encrypt_file(key, arch_path, zip_name, encrypted_place)
            info_message(self, 'Архив успешно зашифрован!')
            enc_bits = self.first_bits(store)
            threading.Thread(target=self.ydisk_upload(store, enc_zip_name))
            info_message(self, 'Началась загрузка в облако!')
            BackUPCreator_sqlite.insert_data(bu_name=enc_zip_name, bu_key=key, bu_hash=file_hash, dec_bits=dec_bits,
                                             enc_bits=enc_bits)
            info_message(self, 'Данные успешно записаны в базу!' + '\n' + separator)

        elif self.encrypt_check.isChecked() and self.cloud_check.isChecked():
            store, enc_zip_name = self.encrypt_file(key, arch_path, zip_name, encrypted_place)
            info_message(self, 'Архив успешно зашифрован!')
            enc_bits = self.first_bits(store)
            threading.Thread(target=self.ydisk_upload(store, enc_zip_name))
            info_message(self, 'Началась загрузка в облако!')
            BackUPCreator_sqlite.insert_data(bu_name=enc_zip_name, bu_key=key, dec_bits=dec_bits, enc_bits=enc_bits)
            info_message(self, 'Данные успешно записаны в базу!' + '\n' + separator)

        elif self.hash_check.isChecked() and self.cloud_check.isChecked():
            file_hash = self.get_hash_stribog(arch_path.replace('\\', '/'))
            info_message(self, 'Хэш файла вычислен успешно...')
            threading.Thread(target=self.ydisk_upload(arch_path, zip_name))
            info_message(self, 'Началась загрузка в облако!')
            BackUPCreator_sqlite.insert_data(bu_name=zip_name, bu_hash=file_hash, dec_bits=dec_bits)
            info_message(self, 'Данные успешно записаны в базу!' + '\n' + separator)

        elif self.encrypt_check.isChecked() and self.hash_check.isChecked():
            file_hash = self.get_hash_stribog(arch_path.replace('\\', '/'))
            info_message(self, 'Хэш файла вычислен успешно...')
            store, enc_zip_name = self.encrypt_file(key, arch_path, zip_name, encrypted_place)
            info_message(self, 'Архив успешно зашифрован!')
            enc_bits = self.first_bits(store)
            BackUPCreator_sqlite.insert_data(bu_name=enc_zip_name, bu_key=key, bu_hash=file_hash, dec_bits=dec_bits,
                                             enc_bits=enc_bits)
            info_message(self, 'Данные успешно записаны в базу!' + '\n' + separator)

        elif self.encrypt_check.isChecked():
            store, enc_zip_name = self.encrypt_file(key, arch_path, zip_name, encrypted_place)
            info_message(self, 'Архив успешно зашифрован!')
            enc_bits = self.first_bits(store)
            BackUPCreator_sqlite.insert_data(bu_name=enc_zip_name, bu_key=key, dec_bits=dec_bits,
                                             enc_bits=enc_bits)
            info_message(self, 'Данные успешно записаны в базу!' + '\n' + separator)

        elif self.hash_check.isChecked():
            file_hash = self.get_hash_stribog(arch_path.replace('\\', '/'))
            info_message(self, 'Хэш файла вычислен успешно...')
            BackUPCreator_sqlite.insert_data(bu_name=zip_name, bu_hash=file_hash, dec_bits=dec_bits)
            info_message(self, 'Данные успешно записаны в базу!' + '\n' + separator)

        elif self.cloud_check.isChecked():
            threading.Thread(target=self.ydisk_upload(arch_path, zip_name))
            info_message(self, 'Началась загрузка в облако!')
            BackUPCreator_sqlite.insert_data(bu_name=zip_name, dec_bits=dec_bits)
            info_message(self, 'Данные успешно записаны в базу!' + '\n' + separator)

        else:
            BackUPCreator_sqlite.insert_data(bu_name=zip_name, dec_bits=dec_bits)
            info_message(self, 'Данные успешно записаны в базу!' + '\n' + separator)

    @staticmethod
    def create_zip(zip_name, store_place, backup):
        with zipfile.ZipFile(store_place + os.sep + zip_name, 'w') as z:
            for root, dirs, files in os.walk(backup):
                for file in files:
                    z.write(os.path.join(root, file))

    @staticmethod
    def zip_name():
        date = datetime.datetime.now()
        zip_name = 'BU_{}.{}.{}_{}-{}-{}.zip'.format(date.day, date.month, date.year, date.hour, date.minute,
                                                     date.second)
        return zip_name

    @staticmethod
    def first_bits(file):
        with open(file, 'rb') as f:
            bits = f.read(16)
        return str(bits)

    @staticmethod
    def encrypt_file(key, file_path, zip_name, encrypted_place):
        if not os.path.exists(encrypted_place):
            os.mkdir(encrypted_place)
        gost = GOST3412Kuznechik(hexdec(key))
        file = open(file_path, 'rb')
        file_2 = open('{}/encrypted_{}'.format(encrypted_place, zip_name), 'wb')

        while True:
            data = file.read(16)
            if len(data) < 16:
                file_2.close()
                break
            file_2.write(gost.encrypt(data))
        return file_2.name, os.path.basename(file_2.name)

    @staticmethod
    def decrypt_file(self, file_path, decrypted_place):
        def decrypt(key_, file_name_, file_path_, decrypted_place_):
            gost = GOST3412Kuznechik(hexdec(key_))
            file = open(file_path_, 'rb')
            file_2 = open('{}/decrypted_{}'.format(decrypted_place_, file_name_), 'wb')
            while True:
                data_ = file.read(16)
                if len(data_) < 16:
                    file_2.close()
                    break
                file_2.write(gost.decrypt(data_))
            return file_2.name

        if not decrypted_place:
            decrypted_place = '{}{}DecryptedFiles'.format(os.path.abspath(os.curdir), os.sep)
        else:
            decrypted_place = decrypted_place + os.sep + 'DecryptedFiles'
        if not os.path.exists(decrypted_place):
            os.mkdir(decrypted_place)

        file_name = os.path.basename(file_path)
        data = BackUPCreator_sqlite.find_data('bu_name', file_name)
        if not data:
            bits = self.first_bits(file_path)
            data = BackUPCreator_sqlite.find_data('enc_bits', bits)
            if not data:
                data = BackUPCreator_sqlite.find_data('dec_bits', bits)
                if data:
                    self.logs.addItem('Архив не был зашифрован!' + '\n' + separator)
            else:
                for bu_key, bu_hash in data:
                    if bu_key != 'False' and bu_hash != 'False':
                        path = decrypt(bu_key, file_name, file_path, decrypted_place)
                        hash_ = self.get_hash_stribog(path)
                        if hash_ == bu_hash:
                            self.logs.addItem(complete_msg + '\n' + separator)
                            break
                        else:
                            self.logs.addItem(error_msg + '\n' + separator)
                            break
                    if bu_key != 'False' and bu_hash == 'False':
                        decrypt(bu_key, file_name, file_path, decrypted_place)
                        self.logs.addItem('Файл успешно расшифрован, хэш отстутсвует в базе!' + '\n' + separator)
                    if bu_key == 'False' and bu_hash != 'False':
                        self.logs.addItem('Файл не был зашифрован!' + '\n' + separator)
                        hash_ = self.get_hash_stribog(file_path)
                        if hash_ == bu_hash:
                            self.logs.addItem(complete_msg + '\n' + separator)
                            break
        else:
            for bu_key, bu_hash in data:
                if bu_key != 'False' and bu_hash != 'False':
                    path = decrypt(bu_key, file_name, file_path, decrypted_place)
                    hash_ = self.get_hash_stribog(path)
                    if hash_ == bu_hash:
                        self.logs.addItem(complete_msg + '\n' + separator)
                        break
                    else:
                        self.logs.addItem(error_msg + '\n' + separator)
                        break
                if bu_key != 'False' and bu_hash == 'False':
                    decrypt(bu_key, file_name, file_path, decrypted_place)
                    self.logs.addItem('Файл успешно расшифрован, хэш отстутсвует в базе!' + '\n' + separator)
                if bu_key == 'False' and bu_hash != 'False':
                    self.logs.addItem('Файл не был зашифрован!' + '\n' + separator)
                    hash_ = self.get_hash_stribog(file_path)
                    if hash_ == bu_hash:
                        self.logs.addItem(complete_msg + '\n' + separator)
                        break

    @staticmethod
    def get_hash_stribog(file_path):
        with open(file_path, 'rb') as f:
            m = GOST34112012(digest_size=32)
            while True:
                data = f.read(8192)
                if not data:
                    break
                m.update(data)
            return m.hexdigest()

    def ydisk_upload(self, store, zip_name):
        yDisk = yadisk.YaDisk(token=self.my_token)
        if yDisk.exists('DoNotSync/BackUPCreator/'):
            yDisk.upload(store, 'DoNotSync/BackUPCreator/{}'.format(zip_name))
        else:
            yDisk.mkdir('DoNotSync/BackUPCreator/')
            yDisk.upload(store, 'DoNotSync/BackUPCreator/{}'.format(zip_name))

    def complete(self):
        if len(self.input_key.text()) != 64:
            info_message(self, 'Неверная длина ключа!')
        progress_bar(self, 100)
        try:
            if self.files:
                self.back_up_creator(self.local_dir, self.files, self.input_key.text())
            elif self.decrypt_files:
                self.decrypt_file(self, self.decrypt_files, self.local_dir)
            else:
                self.logs.addItem(empty_msg)
        except Exception as exception:
            info_message(self, separator + '\n' + 'Произошла непредвиденная ошибка!\n{}'.format(exception) + '\n' + separator)

    def start_thread(self):
        threading.Thread(target=self.complete).start()


def run():
    app = QtWidgets.QApplication(sys.argv)
    window = HookLogic()
    window.show()
    app.exec_()


if __name__ == '__main__':
    try:
        run()
    except Exception as e:
        print('Ошибка!', e)
