## CRYPT LIBRARY FOR ECLA


|    Func Name     |                        Prototype                        |                                                 Description                                                  |
|:----------------:|:-------------------------------------------------------:|:------------------------------------------------------------------------------------------------------------:|
| BinaryToDecimal  |        BinaryToDecimal(BinaryArray []int) int {}        |                                     Convert a binary number to decimal.                                      |
|      Bitlen      |                func bitLen(n int64) int                 |                    returns the number of bits needed to represent a 64-bit signed integer                    | 
|       clz        |                 func clz(x uint64) uint                 |                      counts the number of high-order zeros in a 64-bit unsigned integer                      |
|  DecryptCaesar   | DecryptCaesar(Key int, CryptedMessage string) string {} |                                  Decrypt a message using Caesar decryption.                                  |
|    DecryptRC4    | DecryptRC4(Key string, CryptedMessage string) string {} |                                   Decrypt a message using RC4 decryption.                                    |
|    DecryptRSA    |      EncryptRSA(N, E int64, message []byte) string      |                                    Decrypt a message using RSA Decryption                                    |
| DecimalToBinary  |             DecimalToBinary(x int) []int {}             |                                      Convert a decimal number to binary                                      |
|  EncryptCaesar   |    EncryptCaesar(Key int, Message string) string {}     |                                  Encrypt a message using Caesar Encryption                                   |
|    EncryptRC4    |    EncryptRC4(Key string, Message string) string {}     |                                    Encrypt a message using RC4 Encryption                                    |
|    EncryptRSA    |      EncryptRSA(N, E int64, message []byte) string      |                                    Encrypt a message using RSA Encryption                                    |
|  GenerateKeyRSA  |      GeneratKeyRSA(p, q int64) ([]int64, []int64)       |                                          Generates an rsa key pair                                           |
|  GetNumeroASCII  |          GetNumeroASCII(caractere rune) int {}          |                                     Retrieve the ASCII number of a rune.                                     |
|      ModExp      |        ModExp(base, exp, mod *big.Int) *big.Int         |                  Calculates modular exponentiation using the fast exponentiation algorithm                   |
| modulo inverse   |            ModuloInverse(a, m int64) int64              | calculates the modular inverse of an integer a modulo m using the extended Euclid modulo inversion algorithm |
|  StringToBinary  |            StringToBinary(s string) []int {}            |                                          Convert a string to binary                                          |

