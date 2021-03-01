# Imports necessários para o funcionamento do code.
import hmac
import os
import socket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass


'''Derivação de Chave a partir de uma Password'''

def derivation(secret):
    # Derive the secret so we get key and IV material for AES
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=48,
        salt=secret,
        iterations=100000,
        backend=backend
    )
    return kdf.derivation(secret)

''' Solicitação de uma Password para a derivação de chave. '''

def requestPassword():
        password = getpass.getpass()
        return str.encode(password)


'''Autenticação da Mensagem: a partir do calculo MAC retribui com uma tag. '''

def authentication(key,source, tag=None):
    h = hmac.HMAC(key,hashes.SHA256(),default_backend())
    h.update(source)
    if tag == None:
        return h.finalize()
    h.verify(tag)

''' Função de Hash: calcular a Hash. '''

def hash(s):
    digest = hashes.Hash(hashes.SHA256(),backend=default_backend())
    digest.update(s)
    return digest.finalize()


''' Criando o Emitter (o cliente que enviará as solicitações): '''


class Emitter:
    def __init__(self):
        host = 'localhost'
        port = 5000
        address = (host, port)

    def execute(self):
        pass


'''Criando o Emitter socket '''

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

''' Nesta função ocorre a criptografia da solicitação que o emitter deseja realizar,
onde o iv será gerado a partir de um random, e o modo da cifra escolhido, foi o GCM '''


def encrypt(data, secret_key, iv):
    iv = os.urandom(16)
    cipher = Cipher(algorithm=algorithms.AES(secret_key),
                    mode=modes.GCM(iv,
                                   min_tag_length=16),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    return ciphertext, encryptor.tag


def requestMessage(self):
    ''' Criação da solicitação de mensagem. '''

    while 1:
        message = input('Informe o que deseja solicitar ao Receiver: ')

        return input().encode()


def connection(self):
    ''' Solicita a Conexão com o Receiver: '''

    clientSocket.connect(self.address)

    # Conexão é estabelecida entre Emitter e Receiver:

    print(" Emitter conectado! ")


def endConnection(self):
    # Encerrar Conexão
    clientSocket.close()


def execute(self):
    # Conecta-se ao Servidor
    self.connection()
    password = requestPassword()
    salt = os.urandom(16)
    key = derivation(salt).derivation(password)

    while True:
        message = self.requestMessage()

        try:

            tagPT = authentication(Hash(key), message)

            iv, ciphertext, tagCT = self.encription(key, message)

            new_message = salt + tagPT + iv + tagCT + ciphertext
            if (len(new_message) > 0):
                self.socket.send(new_message)
            else:
                self.endConnection()
        except:
            print("Emitter Inválido.")


def mainEmitter():
    emitter = Emitter()
    emitter.execute()


mainEmitter()
