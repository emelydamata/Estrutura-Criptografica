import getpass
import socket
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac


class Emitter:
    # Construtor da Classe
    def __init__(self):
        host = 'localhost'
        port = 8082
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.address = (host, port)

    # Metodo para estabelecer uma conexao
    def establish_connection(self):
        self.conn.connect(self.address)

    # Metodo para pedir ao utilizador para inserir uma mensagem
    def ask_message(self):
        mesg = input("Escreva a sua Mensagem\n")
        return mesg.encode()

    # Metodo para cifrar o criptograma
    def encrypt(self, key, msg):
        # Gerar um 'nonce'
        nonce = os.urandom(12)
        # Inicializacao do objecto AESGCM
        aes_gcm = AESGCM(key)
        # Cifragem da mensagem usando o nonce previamente gerado sem meta-data
        ct = aes_gcm.encrypt(nonce, msg, None)
        return nonce, ct

    # Metodo para encerrar a conexao
    def finish(self):
        self.conn.close()
        print('Conexao Encerrada\n')

    # Metodo para pedir ao utilizador para inserir uma password usando getpass()
    def requestPassWord(self):
        password = getpass.getpass()
        return str.encode(password)

    # Metodo para a derivacao da chave usando PBKDF2HMAC
    def pbkdf2Hmac(self, salt):
        kdf = PBKDF2HMAC(
            # Usando SHA256
            algorithm=hashes.SHA256(),
            # Chave com 32 bytes de comprimento
            length=32,
            salt=salt,
            # 100000 iteracoes (como o exemplo da literatura do cryptography.io)
            iterations=100000,
            backend=default_backend())
        return kdf

    # Metodo para gerar o HMAC da chave
    def mac(self, secret, msg):
        # Inicializacao da chave
        h = hmac.HMAC(secret, hashes.SHA256(), default_backend())
        # Obtencao da chave em bytes e nao string
        h.update(msg)
        return h.finalize()

    # Corpo da execucao
    def execute(self):
        # Estabelecimento da ligacao
        self.establish_connection()

        # Por cada mensagem:
        while True:
            # Primeiro pedimos ao utilizador a password
            password = self.requestPassWord()
            # Depois geramos um salt aleatoriamente
            salt = os.urandom(16)
            # Usando o salt e a password derivamos uma chave
            key = self.pbkdf2Hmac(salt).derive(password)
            # Usamos a chave e a password para gerar o HMAC correspondente à chave, IMPORTANTE, password poderia ser substituida por outro segredo
            key_mac = self.mac(key, password)
            # Pedimos a mensagem ao utilizador
            msg = self.ask_message()

            try:
                # Aqui usamos o metodo encrypt para obter o nonce e o criptograma concatenado com a tag usada para a autenticacao do criptograma em si
                # IMPORTANTE o nonce podia ser um counter de cada lado, mas como isto serve para mandar uma só mensagem decidimos fazer desta forma
                nonce, ciphertext_and_tag = self.encrypt(key, msg)
                # Juncao do salt (à vista), do HMAC da chave, do nonce (à vista) e do criptograma ++ tag
                bundle = salt + key_mac + nonce + ciphertext_and_tag
                self.conn.send(bundle)
                print('Mensagem Enviada')
            except:
                print("Erro na Comunicacao\n")
                self.finish()


#  Metodo para arrancar o emissor
def chamada():
    em = Emitter()
    em.execute()
    return


chamada()
