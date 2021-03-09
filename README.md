# EstruturaCriptográfica

Este repositório destina-se a armazenar os trabalhos práticos executados pelo grupo 01, composto por:

Emely da Mata Mendonça - PG39286
João Pedro Dias Fernandes - A84034


O semestre segue distribuido em 04 trabalhos práticos, distribuidos entre os respetivos prazos entregas:

| Trabalho | Data da demonstração |    
| -------- | -------------------- | 
| T0       | 17 e 18 de Março     |
| T1       | 7 e 8 de Abril       |        
| T2       | 5 e 6 de Maio        |           
| T3       | 2 e 4 de Junho       | 

 O envio da documentação deve ser efetuado sempre na "SEGUNDA-FEIRA" anterior as datas de apresentação. 



00) Trabalho Prático 0:

Use a package Criptography para

Criar um comunicação privada assíncrona entre um agente Emitter e um agente Receiver que cubra os seguintes aspectos:

Autenticação do criptograma e dos metadados (associated data). Usar uma cifra simétrica num dos modos stream cipher (e.g. GCM).
Derivação da chave a partir de uma password usando um KDF; ambos os agentes devem ler essa password para poder gerar a chave.
Autenticação prévia da chave usando um MAC.
Criar uma cifra a partir de um PRG

Criar um gerador pseudo-aleatório do tipo XOF (“extened output function”) usando o SHAKE256, para gerar uma sequência de palavras de 64 bits.
O gerador deve poder gerar até um limite de $$,2^n,$$ palavras ($$n$$ é um parâmetro) armazenados em long integers do Python.
A “seed” do gerador funciona como “password” b. Defina os algoritmos de cifrar e decifrar : para cifrar/decifrar uma mensagem com blocos de 64 bits, os “outputs” do gerador são usados como máscaras XOR dos blocos da mensagem. | Essencialmente a cifra é uma implementação do “One Time Pad” ou “cifra de Vernam”. |
c. Compare experimentalmente a eficiência dessa cifra com a da cifra usada no problema 1.
