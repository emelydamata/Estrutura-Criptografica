import getpass
import socket
import math
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class Receiver:
    # Construtor da Classe
    def __init__(self):
        host = 'localhost'
        port = 8082
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("Aguardando uma Conexao com Emitter\n")
        self.address = (host, port)
        self.counter = 0

    # Metodo para estabelecer uma conexao
    def establish_connection(self):
        self.conn.bind(self.address)
        self.conn.listen(1)

    # Metodo para encerrar a conexao
    def finish(self, con):
        con.close()
        print('Fim de Comunicacao com o Receiver!\n')
        return

    # Metodo para pedir ao utilizador para inserir uma password usando getpass()
    def requestPassWord(self):
        password = getpass.getpass()
        return str.encode(password)

    # Metodo para gerar as palavras a fazer XOR com a mensagem
    def shake(self, size, password):
        # Size = tamanho total das palavras
        digest = hashes.Hash(hashes.SHAKE256(size), default_backend())
        digest.update(password)
        return digest.finalize()

    # Metodo para fazer XOR da mensagem com as palavras geradas
    def xor(self, pad, message):
        size = len(message)
        xored = bytearray(size)
        word = self.counter
        position = 0
        for i in range(size):
            xored[i] = pad[word][position] ^ message[i]
            position += 1
            if position == 8:
                word += 1
                position = 0
        return xored

    # Metodo para fazer split do pad com as palavras todas
    def split(self, pad):
        n = 8
        len_pad = len(pad)
        x = [pad[i:i + n] for i in range(0, len_pad, n)]
        return x

    # Corpo da execucao
    def run(self):
        # Estabelecimento da ligacao com o emissor
        self.establish_connection()
        # Limite maximo de 1 ligacao
        i = 0
        while i < 1:
            # Aceitar a ligacao com o emissor
            adrr, emitter = self.conn.accept()
            print("Ligado a: ", emitter)
            i += 1
            # Pedir o numero de palavras
            n = int(input("N?\n"))
            # Numero máximo de palavras
            lim = pow(2, n)
            # Pedimos a password ao utilizador
            password = self.requestPassWord()
            # Geramos a lista de palavras com o shake
            pad = self.shake(lim * 8, password)
            # Separacao das palavras
            pad_words = self.split(pad)
            # Por mensagem:
            while True:
                # Recebemos a mensagem
                msg = adrr.recv(lim*8)
                # Tamanho da mensagem codificada em bytes
                msg_size = len(msg)
                # Verificar se e necessario criar um novo pad
                if (self.counter + math.ceil(msg_size/8)) > lim:
                    # Pedimos a password ao utilizador
                    password = self.requestPassWord()
                    # Geramos a lista de palavras com o shake
                    pad = self.shake(lim * 8, password)
                    # Separacao das palavras
                    pad_words = self.split(pad)
                    # Reset do Counter
                    self.counter = 0
                # Para o caso de haver um problema
                if not msg:
                    print('Nenhuma Mensagem Recebida!\n')
                    break
                else:
                    # Fazemos XOR das palavras com a mensagem
                    cleantext = self.xor(pad_words, msg)
                    self.counter += math.ceil(msg_size/8)
                    print(cleantext.decode())
            self.finish(self.conn)
        return


#  Metodo para arrancar o recetor
def chamada():
    rec = Receiver()
    rec.run()
    return


chamada()
