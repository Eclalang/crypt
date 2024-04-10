# Crypt library

[![Go Report Card](https://goreportcard.com/badge/github.com/Eclalang/crypt)](https://goreportcard.com/report/github.com/Eclalang/crypt)
[![codecov](https://codecov.io/gh/Eclalang/crypt/graph/badge.svg?token=YNCIYERVBO)](https://codecov.io/gh/Eclalang/crypt)

## Candidate functions :

|    Func Name    |                        Prototype                        |                                                 Description                                                  |
|:---------------:|:-------------------------------------------------------:|:------------------------------------------------------------------------------------------------------------:|
| BinaryToDecimal |        BinaryToDecimal(BinaryArray []int) int {}        |                                     Convert a binary number to decimal.                                      |
| DecimalToBinary |             DecimalToBinary(x int) []int {}             |                                      Convert a decimal number to binary                                      |
|  DecryptCaesar  | DecryptCaesar(Key int, CryptedMessage string) string {} |                                  Decrypt a message using Caesar decryption.                                  |
|   DecryptRC4    | DecryptRC4(Key string, CryptedMessage string) string {} |                                   Decrypt a message using RC4 decryption.                                    |
|   DecryptRSA    |       DecryptRSA(N, D int, message string) string       |                                    Decrypt a message using RSA Decryption                                    |
|  EncryptCaesar  |    EncryptCaesar(Key int, Message string) string {}     |                                  Encrypt a message using Caesar Encryption                                   |
|   EncryptRC4    |    EncryptRC4(Key string, Message string) string {}     |                                    Encrypt a message using RC4 Encryption                                    |
|   EncryptRSA    |       EncryptRSA(N, E int, message string) string       |                                    Encrypt a message using RSA Encryption                                    |
| GenerateKeyRSA  |         GenerateKeyRSA(p, q int) ([]int, []int)         |                                          Generates an rsa key pair                                           |
| GetNumeroASCII  |          GetNumeroASCII(caractere rune) int {}          |                                     Retrieve the ASCII number of a rune.                                     |
|     ModExp      |             ModExp(base, exp, mod int) int              |                  Calculates modular exponentiation using the fast exponentiation algorithm                   |
|  ModuloInverse  |               ModuloInverse(a, m int) int               | Calculates the modular inverse of an integer a modulo m using the extended Euclid modulo inversion algorithm |
| StringToBinary  |            StringToBinary(s string) []int {}            |                                          Convert a string to binary                                          |

