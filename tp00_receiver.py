import os
import socket
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

''' Construção da Classe Receiver '''


# var p/ uso na def execute.
lim = 2048

class Receiver:

    def __init__(con):
        host = 'localhost'
        port = 8282
        con.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Se necessário a reutilização do endereço/porta:
        con.conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,3)
        print("*** Aguardando uma Conexão com Emitter ***")
        con.address = (host, port)

    ''' Criando uma Conexão. '''

    def conexao(con):
        con.conn.bind(con.address)
        con.conn.listen(1)

    '''Decifrar a Mensagem'''

    def decipher(con,key, iv, tag, msg):
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), default_backend())
        decifrar = cipher.decryptor()
        text_limpo = decifrar.update(msg) + decifrar.finalize()
        return text_limpo

    ''' Principal: '''

    def execute(con):
        con.conexao()
        i = 0
        while (i < 1):
            print('Aguardando Mensagem...')
            connec, emitter = con.conn.accept()
            print("Conectado com: ", emitter)
            i += 1
            password = requestPassWord()
            while True:
                msg = connec.recv(lim)
                if (not msg):
                    break
                else:
                    salt = msg[0:16]
                    t = msg[16:48]
                    iv = msg[48:64]
                    tag = msg[64:80]
                    ciphertext = msg[80:]
                    key = derivation(salt).derive(password)
                try:
                    texto_limpo = con.decipher(key, iv, tag, ciphertext)
                    if (t == authenticationMac(funcaoHash(key), texto_limpo)):
                        print(texto_limpo.decode())
                    else:
                        print('Está Mensagem não Possui Chave Autenticada.')
                except:
                    print('Mensagem Corrompida!\n')
                    con.finish(connec)
            con.finish(connec)
        return

    '''Função Para Encerrar a Conexão: '''

    def finish(con,connec):
        con.conn.close()
        print(' Encerrando Conexão...')
        return


''' Tratativa de Password e a Derivação da Key: '''

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

''' Autenticação de Hash da Mensagem'''
def authenticationMac(key, source, tag):
    hmac_ = hmac.HMAC(key, hashes.SHA256(), default_backend())
    hmac_.update(source)
    if tag == None:
        return hmac_.finalize()
    hmac_.verify(tag)

def funcaoHash(s):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(s)
    return digest.finalize()



def chamada():
    rec = Receiver()
    rec.execute()
    return

chamada()
