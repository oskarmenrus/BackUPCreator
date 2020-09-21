hello_msg = '\t         Программа запущена и готова к работе!'
welcome_msg = '\tСоздайте архив или расшифруйте созданный ранее...'
empty_msg = 'Ошибка! Выберите файлы для шифрования или расшифровки!'
error_msg = 'ОШИБКА! Что-то пошло не так...'
complete_msg = 'Расшифровка завершена успешно!'
separator = '==================================================================='


def progress_bar(self, percent):
    self.progress.setProperty('value', percent)


def info_message(self, text):
    self.logs.addItem(text)
    self.logs.scrollToBottom()
