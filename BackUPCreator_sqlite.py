import sqlite3


def insert_data(bu_name="False", bu_key="False", bu_hash="False", dec_bits="False", enc_bits="False"):
    conn = sqlite3.connect("BackUPCreator_db.db")
    cursor = conn.cursor()
    data = [(bu_name, bu_key, bu_hash, dec_bits, enc_bits)]
    cursor.executemany("INSERT INTO BackUPCreator_data VALUES (?,?,?,?,?)", data)
    conn.commit()


def find_data(parameter, arg):
    conn = sqlite3.connect("BackUPCreator_db.db")
    cursor = conn.cursor()
    sql_query = "SELECT bu_key, bu_hash FROM BackUPCreator_data WHERE {}=?".format(parameter)
    cursor.execute(sql_query, [str(arg)])
    data = cursor.fetchall()
    return data
