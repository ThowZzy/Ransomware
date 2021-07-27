import socket
import pickle

#Constantes
HEADSIZE = 10
LOCAL_IP = socket.gethostname()
PORT = 8380


def start_srv(ip=LOCAL_IP, port=PORT):
    """
    Fonction de démarrage du serveur
    :param ip: locale par defaut
    :param port: 8380 par defaut
    :return: socket du serveur
    """
    s_serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_serv.bind((ip, port))
    s_serv.listen(0)
    return s_serv


def conn_serv(ip=LOCAL_IP, port=PORT):
    """
    Fonction de connexion vers le serveur
    :param ip: locale par defaut
    :param port: 8380 par defaut
    :return: socket client
    """
    s_cli = None
    s_cli = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    try:
        s_cli.connect((ip, port))
        return s_cli
    except Exception as erreur:
        print(f"Impossible de se connecter au serveur : {erreur}")
        return None


def send_msg(s, msg):
    """
    Fonction d'envoi d'un msg (objet) en plaçant un HEAD renseigant la taille du message
    :param s: socket
    :param msg: objet (dict, liste, tuple, etc...)
    :return: néant
    """
    code=0
    msg=pickle.dumps(msg)
    size_msg = len(msg)
    data = bytes(f"{size_msg:<{HEADSIZE}}", "utf-8")+msg
    # send message
    try:
        s.send(data)
    except Exception as erreur:
        print(f"Impossible d'envoyer le message : {erreur}")
        code=1
    return code


def receiv_msg(s):
    """
    Fonction de réception de messages avec un HEAD précisant la taille du message
    :param s: socket
    :return: message recu
    """
    size_msg=None
    try:
        size_msg = s.recv(HEADSIZE)
    except Exception:
        pass

    if not size_msg:        #Si fermeture de la connexion, pas de message (message vide)
        s.close()
        return None

    size_msg = int(size_msg[:HEADSIZE])
    msg = s.recv(size_msg)
    msg = pickle.loads(msg)
    return msg


def main():
    pass

if __name__ == '__main__':
    main()

