import getpass
import socket
import math
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class Emitter:
    # Construtor da Classe
    def __init__(self):
        host = 'localhost'
        port = 8082
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.address = (host, port)
        self.counter = 0

    # Metodo para estabelecer uma conexao
    def establish_connection(self):
        self.conn.connect(self.address)

    # Metodo para pedir ao utilizador para inserir uma mensagem
    def ask_message(self):
        mesg = input("Escreva a sua Mensagem\n")
        return mesg.encode()

    # Metodo para encerrar a conexao
    def finish(self):
        self.conn.close()
        print('Conexao Encerrada\n')

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
        word = 0
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
    def execute(self):
        # Pedir o numero de palavras
        n = int(input("N?\n"))
        # Numero maximo de palavras por conjunto de chaves
        lim = pow(2, n)
        # Estabelecimento da ligacao
        self.establish_connection()
        # Primeiro pedimos ao utilizador a password
        password = self.requestPassWord()
        # Geramos a o conteudo das palavras com o shake
        pad = self.shake(lim * 8, password)
        # Separacao das palavras
        pad_words = self.split(pad)
        # Por cada mensagem:
        while True:
            # Pedimos a mensagem ao utilizador
            msg = self.ask_message()
            # Tamanho da mensagem codificada em bytes
            msg_size = len(msg)
            if msg_size < int(lim*8):
                try:
                    if (self.counter + math.ceil(msg_size / 8)) > lim:
                        # Primeiro pedimos ao utilizador a password
                        password = self.requestPassWord()
                        # Geramos a o conteudo das palavras com o shake
                        pad = self.shake(lim * 8, password)
                        # Separacao das palavras
                        pad_words = self.split(pad)
                        self.counter = 0
                    # Fazemos XOR das palavras com a mensagem
                    ciphertext = self.xor(pad_words, msg)
                    self.counter += math.ceil(msg_size / 8)
                    if len(ciphertext) > 0:
                        self.conn.send(ciphertext)
                        print('Mensagem Enviada')
                    else:
                        self.finish()
                except:
                    print("Erro na Comunicacao\n")
            else:
                print("Mensagem demasiado grande\n")
                self.finish()




#  Metodo para arrancar o emissor
def chamada():
    em = Emitter()
    em.execute()
    return


chamada()
