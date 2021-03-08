import getpass
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac



class Receiver:


    def __init__(con):
        host = 'localhost'
        port = 8282
        con.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Se necessário a reutilização do endereço/porta:
        con.conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("*** Aguardando uma Conexão com Emitter ***")
        con.address = (host, port)

    '''conectando  '''

    def conexao(con):
        con.conn.bind(con.address)
        con.conn.listen(1)

    ''' decifrando a mensagem '''

    def decipher(con, key, iv, tag, msg):
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), default_backend())
        decifrar = cipher.decryptor()
        text_limpo = decifrar.update(msg) + decifrar.finalize()
        return text_limpo

    ''' Fun principal'''

    def execute(con):
        lim = 10000
        con.conexao()
        i = 0
        while (i < 1):
            adrr, emitter = con.conn.accept()
            print("Conectado por: ", emitter)
            i += 1
            password = requestPassWord()

            while True:
                msg = adrr.recv(lim)
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
                        text_limpo = con.decipher(key, iv, tag, ciphertext)
                        if (t == mac(Hash(key), text_limpo)):
                            print(text_limpo.decode())
                        else:
                            print('Mensagem comprometida. Chave não autenticada')
                    except:
                        print('Mensagem comprometida\n')
                        con.finish(con)
            con.finish(con)
        return

    def finish(con, connec):
        connec.close()
        print(' Encerrando Conexão...')
        return


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

''' Para atender as fun criadas '''

def chamada():
    rec = Receiver()
    rec.execute()
    return

chamada()
