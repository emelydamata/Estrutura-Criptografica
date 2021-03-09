import getpass
import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac



''' Construção da Classe Emitter '''

class Emitter:

    def __init__(self):
        host = 'localhost'
        port = 8082
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.address = (host, port)

    def conexao(self):
        self.conn.connect(self.address)

    def msg_emitter(self):
        self.mesg = input("Qual a Mensagem?")
        return self.mesg.encode()

    def encription(self, key, msg):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), default_backend())
        cifrar = cipher.encryptor()
        text_cifrado = cifrar.update(msg) + cifrar.finalize()
        return iv, text_cifrado, cifrar.tag

    def finish(self):
        self.conn.close()
        print(' Fim da Comunicação com o Receiver. ')

    def execute(self):
        self.conexao()
        password = requestPassWord()
        salt = os.urandom(16)
        key = kdf2Hmac(salt).derive(password)

        while True:
            msg = self.msg_emitter()

            try:

                t_msg = mac(Hash(key), msg)

                iv, ciphertext, t_mcif = self.encription(key, msg)

                text_cifrado = salt + t_msg + iv + t_mcif + ciphertext
                if (len(text_cifrado) > 0):
                    self.conn.send(text_cifrado)
                    print('Mensagem Cifrada para Envio:', text_cifrado)
                else:
                    self.endConnection()
            except:
                print("Erro na Comunicação")



''' Função para Solicitar uma Password ao Emitter, para efetuar a comunicação. '''

def requestPassWord():
    password = getpass.getpass()
    return str.encode(password)

'''Função para realizar a Derivação da Key - Utilizando o recurso KDF2HMAC '''

def kdf2Hmac(salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend())
    return kdf

''' Função Para Autenticação. '''

def mac(key, source, tag=None):
    h = hmac.HMAC(key, hashes.SHA256(), default_backend())
    h.update(source)
    if tag == None:
        return h.finalize()
    h.verify(tag)


'''Função Hash. '''

def Hash(s):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(s)
    return digest.finalize()

''' Função Para chamar a Execução das funções estabelecidas para a comunicação. '''

def chamada():
    em = Emitter()
    em.execute()
    return


chamada()
