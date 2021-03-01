# Imports necessários para o funcionamento do code.
import hmac
import os
import socket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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


''' Criando o Receiver (o servidor que recebrá as solicitações): '''


class Receiver:
    def __init__(self):
        host = 'localhost'
        port = 5000
        address = (host, port)


'''Criando o Receiver socket '''

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def startSocket(self):
    ''' Associação da porta ao Receiver'''

    serverSocket.bind(address)

    '''Aguardando a comunicação por parte de um emitter'''

    serverSocket.listen(1)

    print(' Receiver disponível para conexão. ')


def decrypt(ciphertext, tag, secret_key, iv):
    cipher = Cipher(algorithm=algorithms.AES(secret_key),
                    mode=modes.GCM(iv,
                                   tag=tag),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def execute(self):
    ''' Conexão do Socket '''

    print('Executando o Receive:')

    self.startSocket()

    connection_socket, address = serverSocket.accept()

    password = requestPassword()

    ''' Conexão iniciada '''

    print(' Receiver Conectado! ')

    while 1:

        # Recepção de mensagem fornecida pelo Emitter:

        message = connection_socket.recv(2048)

        # Se não recebemos nada, interrompemos o processo:

        if not message: break

    key = kdf(salt).derivation(password)

    try:
        plaintext = self.decrypt(key, iv, tag, cipher)
        if (tagK == authentication(hash(key), plaintext)):
            print(plaintext.decode())
        else:
            print('Esta mensagem pode está corrompida. Chave não Autenticada!')
    except:
        print('Mensagem Corrompida.')
        self.endConnection(connection_socket)
        return


''' Encerrar a conexão com o Emitter '''


def endConnection(self, connection_socket):
    connection_socket.close()
    print("Fim de Conexão")
    return
