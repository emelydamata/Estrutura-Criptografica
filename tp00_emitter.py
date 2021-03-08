import os
import socket
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

''' Construção da Classe Emitter '''


class Emitter:

    def __init__(con):
        host = 'localhost'
        port = 8282
        con.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        con.address = (host, port)

    ''' Criando uma Conexão. '''

    def conexao(con):
        con.conn.connect(con.address)

        ''' Solicitação da Mensagem. '''

    def msg_emitter(con):
        con.mesg = input("Qual a Mensagem?")
        return con.mesg.encode()

    def cipher(con, key, msg):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), default_backend())
        cifrar = cipher.encryptor()
        text_cifrado = cifrar.update(msg) + cifrar.finalize()
        return iv, text_cifrado, cifrar.tag


    def execute(con):
        con.conexao()
        password = requestPassWord()
        salt = os.urandom(16)
        key = derivation(salt).derive(password)

        while 1:
            try:
                msg = con.msg_emitter()
                break
                tag_msg = authenticationMac(funcaoHash(key), msg)
                iv, ciphertext, tag_cifra = con.cipher(key, msg)
                msg_cif = salt + tag_msg + iv + tag_cifra + ciphertext
                amount_expected = len(msg_cif)
                if (amount_expected > 0):
                    con.conn.sendall(msg_cif)
                else:
                    con.finish()
            except socket.error as e:
                print("Socket error: %s" % str(e))



    ''' Encerrar a Conexão'''
    def finish(con):
        con.socket.close()
        print(' Encerrando Conexão...')

'''demais fun '''

def authenticationMac(key, source, tag=None):
    hmac_ = hmac.HMAC(key, hashes.SHA256(), default_backend())
    hmac_.update(source)
    if tag == None:
        return hmac_.finalize()
    hmac_.verify(tag)

def funcaoHash(s):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(s)
    return digest.finalize()

def requestPassWord():
    password = getpass.getpass('Insira a Password: ')
    return str.encode(password)

def derivation(salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt,
                     iterations=100000,
                     backend=default_backend())
    return kdf



def chamada():
    em = Emitter()
    em.execute()
    return

chamada()