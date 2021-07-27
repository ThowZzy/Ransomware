from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import hashlib
import random
import utile.network as network


def estPremier(x):
    count = 0
    for i in range(int(x/2)):
        if x % (i+1) == 0:
            count = count+1
    return count == 1


def hellman_phase1():
    cle_prive=random.randint(1,10000)
    premier_aleatoire=0
    while not estPremier(premier_aleatoire):
        premier_aleatoire=random.randint(10, 10000)
    g_aleatoire=random.randint(1, premier_aleatoire-1)
    cle_publique=(g_aleatoire**cle_prive)%premier_aleatoire
    return cle_prive, g_aleatoire, premier_aleatoire, cle_publique


def hellman_phase2(g, p):
    cle_prive = random.randint(1, 10000)
    cle_publique=(g**cle_prive)%p
    return cle_prive, cle_publique


def hellman_phase3(cle_publique, cle_prive, p):
    cle_chiffrement= (cle_publique**cle_prive)%p
    return hashlib.sha256(bytes(cle_chiffrement)).hexdigest()


def hellman_client(s_cli):
    """
    Fonction qui crée la clé de chiffrement pour le client
    :param s_cli: Connection du client
    :return: La clé commune
    """
    g, p, cle_publique_A = network.receiv_msg(s_cli)
    cle_priveB, cle_publique_B = hellman_phase2(g, p)
    network.send_msg(s_cli, cle_publique_B)
    cle_chiffrement = hellman_phase3(cle_publique_A, cle_priveB, p)
    return cle_chiffrement


def hellman_serveur(conn):
    """
    Fonction qui crée la clé de chiffrement pour le serveur
    :param conn: Connection du serveur
    :return: La clé commune
    """
    cle_priveA, g, p, cle_publique_A = hellman_phase1()
    network.send_msg(conn, (g, p, cle_publique_A))
    cle_publique_B = network.receiv_msg(conn)
    cle_chiffrement = hellman_phase3(cle_publique_B, cle_priveA, p)
    return cle_chiffrement


def encrypt(plain_text, cle_publique):
    # generate a random salt
    salt = get_random_bytes(AES.block_size)

    # use the Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(
        cle_publique.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(plain_text)
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }


def decrypt(enc_dict, cle_publique):
    # decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])

    # generate the private key from the password and salt
    private_key = hashlib.scrypt(
        cle_publique.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted


def main(): #Code de test
    """while True:
        choice = input("\n1) Chiffrer en fournissant la clé et le texte\n2) Déchiffrer"
                       " en fournissant la clé et le texte chiffré\n3) Quitter\n\n")
        if choice=="1":
            cle=input("Clé: ")
            texte=input("Texte à chiffrer: ")
            chiffre=encrypt(texte, cle)
            print(f"Voici le texte chiffré: {chiffre}")
        elif choice=="2":
            cle = input("Clé: ")
            dico= {"cipher_text": input("Cipher: "), "salt": input("Salt: "), "nonce": input("Nonce: "),
                   "tag": input("Tag: ")}
            dechiffre = decrypt(dico, cle)
            print(f"\nVoici le texte déchiffré: {dechiffre.decode()}")
        else:
            break"""
    hellman_phase1()


if __name__ == "__main__": #Code de test
    main()