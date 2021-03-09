import getpass
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac



''' Construção da Classe Receiver '''

class Receiver:

    def __init__(self):
        host = 'localhost'
        port = 8082
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Se necessário a reutilização do endereço/porta:
        self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("*** Aguardando uma Conexão com Emitter ***")
        self.address = (host, port)

    '''conectando  '''

    def conexao(self):
        self.conn.bind(self.address)
        self.conn.listen(1)

    ''' decifrando a mensagem '''

    def decipher(self, key, iv, tag, msg):
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), default_backend())
        decifrar = cipher.decryptor()
        text_limpo = decifrar.update(msg) + decifrar.finalize()
        return text_limpo

    ''' Fun principal'''
    def run(self):
        lim = 10000
        self.conexao()
        i = 0
        while (i < 1):
            adrr, emitter = self.conn.accept()
            print("Conectado por: ", emitter)
            i += 1
            password = requestPassWord()
            print('Aguardando alguma Mensagem...')

            while True:
                msg = adrr.recv(lim)
                if (not msg):
                    print('Nenhuma Mensagem Enviada!')
                    break
                else:
                    salt = msg[0:16]
                    tag1 = msg[16:48]
                    iv = msg[48:64]
                    tag2 = msg[64:80]
                    ciphertext = msg[80:]

                    key = kdf2Hmac(salt).derive(password)

                    try:
                        text_limpo = self.decipher(key, iv, tag2, ciphertext)
                        if (tag1 == mac(Hash(key), text_limpo)):
                            print('Está é a mensagem Decifrada: ', text_limpo.decode())
                        else:
                            print('Encerrando Conexão, falhas de autenticação')
                    except:
                        print('Comunicação Corrompida... \n')
                        self.finish(con)
            self.finish(con)
        return

    def finish(self, con):
        con.close()
        print('Fim de Comunicação com o Receiver!')
        return


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
    rec = Receiver()
    rec.run()
    return

chamada()
