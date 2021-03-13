import os
from cryptography.hazmat.primitives import hashes, hmac


class Teste:
    # Construtor da Classe
    def __init__(self):
        self.secret = os.urandom(32)
        self.msg = os.urandom(16)

    # Metodo para gerar o HMAC da chave
    def mac(self, secret, msg):
        print("1.1")
        # Inicializacao da chave
        h = hmac.HMAC(secret, hashes.SHA256())
        print("1.2")
        # Obtencao da chave em bytes e nao string
        h.update(msg)
        print("1.3")
        return h.finalize()

#  Metodo para arrancar o emissor
def chamada():
    em = Teste()
    em.mac(os.urandom(32), os.urandom(32))
    return


chamada()
