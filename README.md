## CRYPT LIBRARY FOR ECLA


|    Func Name    |                        Prototype                        |                Description                 |
|:---------------:|:-------------------------------------------------------:|:------------------------------------------:|
| BinaryToDecimal |        BinaryToDecimal(BinaryArray []int) int {}        |    Convert a binary number to decimal.     |
|  DecryptCaesar  | DecryptCaesar(Key int, CryptedMessage string) string {} | Decrypt a message using Caesar decryption. |
|   DecryptRC4    | DecryptRC4(Key string, CryptedMessage string) string {} |  Decrypt a message using RC4 decryption.   |
| DecimalToBinary |             DecimalToBinary(x int) []int {}             |     Convert a decimal number to binary     |
|  EncryptCaesar  |    EncryptCaesar(Key int, Message string) string {}     | Encrypt a message using Caesar Encryption  |
|   EncryptRC4    |    EncryptRC4(Key string, Message string) string {}     |   Encrypt a message using RC4 Encryption   |
| GetNumeroASCII  |          GetNumeroASCII(caractere rune) int {}          |    Retrieve the ASCII number of a rune.    |
| StringToBinary  |            StringToBinary(s string) []int {}            |         Convert a string to binary         |

