# EstrutCripto
Projetos com Notebooks Jupyter - Python - UC Estruturas Criptográficas


Trabalho Prático 0

Use a package Criptography  para 

1. Criar um comunicação privada assíncrona entre um agente Emitter e um agente Receiver que cubra os seguintes aspectos:
    1. Autenticação do criptograma e dos metadados (associated data). Usar uma cifra simétrica num dos modos stream cipher (e.g. GCM).
    2. Derivação da chave a partir de uma password  usando um KDF; ambos os agentes devem ler essa password para poder gerar a chave.
    3. Autenticação prévia da chave usando um MAC.


2. Criar uma cifra a partir de um PRG
    1. Criar um gerador pseudo-aleatório do tipo XOF (“extened output function”) usando o SHAKE256, para gerar uma sequência de palavras de 64 bits. 
        1. O gerador deve poder gerar até um limite de $$\,2^n\,$$ palavras ($$n$$ é  um parâmetro) armazenados em long integers do Python.
        2. A “seed” do gerador funciona como “password”
    b. Defina os algoritmos de cifrar e decifrar : para cifrar/decifrar uma mensagem com blocos de 64 bits, os “outputs” do gerador são usados como máscaras XOR dos blocos da mensagem. 
| Essencialmente a cifra é uma implementação do  “One Time Pad” ou “cifra de Vernam”. |

    c. Compare experimentalmente a eficiência dessa cifra com a da cifra usada no problema 1.
