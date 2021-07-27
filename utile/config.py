import json
import utile.security as security
import pickle

key = 'E7Z1O5w0YznEP5xB7l72WmR7HZG8Z1MESN3Pfweai7w='

conf = {
        "disks": "C:",
        "chemins": "C:\\Program Files",
        "extensions": "docx, png, txt, pdf",
        "frequence": 2,
        "cle": "AZERTY"
    }

conf_serv = {
    "CONN_RETRY": 20
}

serveur= {
    'PATHS': ['test_1', 'test_2'],
    'FILE_EXT': ['.docx', '.doc', '.txt', '.xlsx', '.xls', '.pdf'],
    'FREQ': 60, }

workstation= {
    'PATHS': ['test_1', 'test_2'],
    'FILE_EXT': ['.jpg', '.png', '.txt', '.avi', '.mp4', '.mp3', '.pdf' ],
    'FREQ': 120, }


def get_config(name):
    """
    Récupere les données chiffrées dans le fichier JSON et les renvoie déchiffrées
    :return: La config déchiffrée
    """
    try:
        with open(f"{name}.json") as json_file:
            config=json.load(json_file)
            config=security.decrypt(config, key)
            json_file.close()
            return pickle.loads(config)
    except Exception:
        return None


def write_config(data, name):
    """
    Chiffre un dictionnaire (transformé en string) et le stock dans un fichier JSON
    :param data: DICT
    :return: None
    """
    try:
        with open(f"{name}.json", "w") as json_file:
            data=security.encrypt(pickle.dumps(data), key)
            json.dump(data, json_file, indent=2)
            json_file.close()
            return 0
    except Exception:
        return 1


if __name__ == "__main__": #Code de test
    write_config(conf_serv, "serv_frontal")
    print(get_config("serv_frontal"))
    #write_config(serveur, "serveur")
    #write_config(workstation, "workstation")
