import getpass
import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac


class Receiver:
    # Construtor da Classe
    def __init__(self):
        host = 'localhost'
        port = 8082
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("Aguardando uma Conexao com Emitter\n")
        self.address = (host, port)

    # Metodo para estabelecer uma conexao
    def establish_connection(self):
        self.conn.bind(self.address)
        self.conn.listen(1)

    # Metodo para decifrar o criptograma
    def decrypt(self, key, nonce, ct_and_tag):
        # Inicializacao do objecto AESGCM
        aesgcm = AESGCM(key)
        try:
            # Decifragem do criptograma ++ tag, usando o nonce e sem meta-data
            limpo = aesgcm.decrypt(nonce, ct_and_tag, None)
            return limpo
        except:
            # Para o caso em que a chave nao e a certa (nao deveria chegar a este ponto) ou porque a tag nao e valida
            return 'Autenticacao Falhou'

    # Metodo para encerrar a conexao
    def finish(self, con):
        con.close()
        print('Fim de Comunicacao com o Receiver!\n')
        return

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

    # Metodo para validacao da chave
    def validate_key(self, key, password, key_mac):
        # Geramos o HMAC da nossa chave
        our_key_mac = self.mac(key, password)
        # Devolvemos o resultado da validacao
        return our_key_mac == key_mac

    # Corpo da execucao
    def run(self):
        # Tamanho maximo de uma mensagem recebida
        lim = 4096
        # Estabelecimento da ligacao com o emissor
        self.establish_connection()
        # Limite maximo de 1 ligacao
        i = 0
        while i < 1:
            # Aceitar a ligacao com o emissor
            adrr, emitter = self.conn.accept()
            print("Ligado a: ", emitter)
            i += 1
            j = 0
            # Por mensagem:
            while j < 100:
                # Pedimos a password ao utilizador
                tmp = "password" + str(j)
                password = tmp.encode()
                # Recebemos a mensagem
                msg = adrr.recv(lim)
                # Para o caso de haver um problema
                if not msg:
                    print('Nenhuma Mensagem Recebida!\n')
                    break
                else:
                    # Primeiros 16 bytes da mensagem sao dedicados ao salt para a derivacao da chave
                    salt = msg[0:16]
                    # Os proximos 32 bytes sao para o HMAC da chave
                    key_mac = msg[16:48]
                    # Os proximos 12 bytes sao para o nonce do AESGCM (que poderia ser um counter em cada lado)
                    nonce = msg[48:60]
                    # Apartir dai temos o criptograma ++ tag
                    ciphertext = msg[60:]

                    # Derivamos a chave de acordo com a password inserida aqui e o nonce fornecido pelo emissor
                    key = self.pbkdf2Hmac(salt).derive(password)

                    try:
                        # Validacao da mensagem recebida usando o mac enviado
                        if self.validate_key(key, password, key_mac):
                            # Se for valida nos deciframos o criptograma
                            plain_text = self.decrypt(key, nonce, ciphertext)
                            # Se nao for valida nao encerramos a ligacao, nao faz diferenca para este exercicio
                            print(plain_text.decode())
                        else:
                            print('Falha de Autenticacao')
                    except:
                        print('Comunicacao Corrompida...')
                        self.finish(self.conn)
                    j += 1
            self.finish(self.conn)
        return


#  Metodo para arrancar o recetor
def chamada():
    rec = Receiver()
    rec.run()
    return


chamada()
