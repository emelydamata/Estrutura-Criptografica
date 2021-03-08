import getpass
import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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

    ''' Encerrar a Conexão'''
    def finish(con):
        con.conn.close()
        print(' Encerrando Conexão... ')

    def execute(con):
        con.conexao()  # Conecta-se ao Servidor
        password = requestPassWord()
        salt = os.urandom(16)
        key = derivation(salt).derive(password)

        while True:
            msg = con.msg_emitter()

            try:

                tmsg = mac(Hash(key), msg)

                iv, ciphertext, tcif = con.cipher(key, msg)

                msgcif = salt + tmsg + iv + tcif + ciphertext
                if (len(msgcif) > 0):
                    con.conn.send(msgcif)
                    print(msgcif)
                else:
                    con.finish()
            except:
                print("Erro no Emissor")




''' Tratativa de Password '''

def requestPassWord():
    password = getpass.getpass('Insira a Password: ')
    return str.encode(password)

''' Derivação da Key:'''

def derivation(salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt,
                     iterations=100000,
                     backend=default_backend())
    return kdf

''' Autenticação '''

def mac(key, source, tag):
    hmac_ = hmac.HMAC(key, hashes.SHA256(), default_backend())
    hmac_.update(source)
    if tag == None:
        return hmac_.finalize()
    hmac_.verify(tag)

''' Hash da Mensagem'''
def Hash(s):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(s)
    return digest.finalize()

def chamada():
    em = Emitter()
    em.execute()
    return

chamada()
