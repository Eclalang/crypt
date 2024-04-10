package crypt

import "fmt"

func EncryptCaesar(cle int, OriginalMessage string) string {

	CryptedMessage := []rune{}
	//a loop which through the caracters of the string one by one
	for i := 0; i < len(OriginalMessage); i++ {
		if (OriginalMessage[i] < 'a' && OriginalMessage[i] > 'Z') || (OriginalMessage[i] < 'A' || OriginalMessage[i] > 'z') {
			//si le caractère n'est pas dans l'alphabet on le modifie pas
			CryptedMessage = append(CryptedMessage, rune(OriginalMessage[i]))
		}
		// If the character is a letter, it's shifted according to the key entered as a parameter of the function.
		if OriginalMessage[i] >= 'a' && OriginalMessage[i] <= 'z' {
			//If after modification the character is no longer within the alphabet, it is adjusted back using an addition or subtraction of 26.
			Lettre := int((OriginalMessage[i])) + cle
			for Lettre > 122 {
				Lettre -= 26
			}
			for Lettre < 97 {
				Lettre += 26
			}
			CryptedMessage = append(CryptedMessage, rune(Lettre))
		}
		//We do the same with uppercase letters.
		if OriginalMessage[i] >= 'A' && OriginalMessage[i] <= 'Z' {
			Lettre := int((OriginalMessage[i])) + cle
			for Lettre > 90 {
				Lettre -= 26
			}
			for Lettre < 65 {
				Lettre += 26
			}
			CryptedMessage = append(CryptedMessage, rune(Lettre))
		}
	}
	return string(CryptedMessage)
}

func DecryptCaesar(cle int, CryptedMessage string) string {
	OriginalMessage := []rune{}
	//a loop which through the caracters of the string one by one
	for i := 0; i < len(CryptedMessage); i++ {
		// Append the character if it's not a letter
		if (CryptedMessage[i] < 'a' && CryptedMessage[i] > 'Z') || (CryptedMessage[i] < 'A' || CryptedMessage[i] > 'z') {

			OriginalMessage = append(OriginalMessage, rune(CryptedMessage[i]))
		}
		// If the character is a letter, it's shifted according to the key entered as a parameter of the function.
		if CryptedMessage[i] >= 'a' && CryptedMessage[i] <= 'z' {
			//If after modification the character is no longer within the alphabet, it is adjusted back using an addition or subtraction of 26.
			Lettre := int((CryptedMessage[i])) - cle
			for Lettre > 122 {
				Lettre -= 26
			}
			for Lettre < 97 {
				Lettre += 26
			}
			OriginalMessage = append(OriginalMessage, rune(Lettre))
		}
		//We do the same with uppercase letters.
		if CryptedMessage[i] >= 'A' && CryptedMessage[i] <= 'Z' {
			Lettre := int((CryptedMessage[i])) - cle
			for Lettre > 90 {
				Lettre -= 26
			}
			for Lettre < 65 {
				Lettre += 26
			}
			OriginalMessage = append(OriginalMessage, rune(Lettre))
		}
	}
	return string(OriginalMessage)
}

func EncryptRC4(cle string, OriginalMessage string) string {
	//Initialization of an array with 256 elements.
	Array := [256]int{}
	for i := 0; i < 256; i++ {
		Array[i] = i
	}
	KeyArray := []rune{}
	for i := 0; i < len(cle); i++ {
		KeyArray = append(KeyArray, rune(cle[i]))

	}
	j := 0
	//Initial shuffle based on the provided key.
	for i := 0; i < 256; i++ {
		j = (j + int(Array[i]) + int(KeyArray[i%len(KeyArray)])) % 256
		Array[i], Array[j] = Array[j], Array[i]
	}
	a := 0
	b := 0
	SequenceChiffrante := []int{}
	//Generation of the cipher sequence.
	for i := 0; i < j; i++ {
		a = (a + 1) % 256
		b = (b + Array[a]) % 256
		Array[a], Array[b] = Array[b], Array[a]
		SequenceChiffrante = append(SequenceChiffrante, (Array[(Array[a]+Array[b])%256]))
	}
	for i := 0; i < 256; i++ {
		SequenceChiffrante = append(SequenceChiffrante, BinaryToDecimal(Xor(DecimalToBinary(Array[i]), DecimalToBinary(Array[j]))))
		j = (j + 1) % 256
	}
	lo := []rune(OriginalMessage)
	code := 0
	CryptedMessage := []rune{}
	i := 0
	//Encrypt each rune of the message with the generated RC4 sequence.
	for _, r := range lo {
		if GetNumeroASCII(r) != 0 {
			code = GetNumeroASCII(r)
		}
		CryptedMessage = append(CryptedMessage, rune(BinaryToDecimal(Xor(DecimalToBinary(SequenceChiffrante[i]), DecimalToBinary(code)))))
		i++
	}
	return string(CryptedMessage)
}

func DecryptRC4(cle string, CryptedMessage string) string {
	//Initialization of an array with 256 elements.
	Array := [256]int{}
	for i := 0; i < 256; i++ {
		Array[i] = i
	}
	KeyArray := []rune{}
	for i := 0; i < len(cle); i++ {
		KeyArray = append(KeyArray, rune(cle[i]))
	}
	j := 0
	//Initial shuffle based on the provided key.
	for i := 0; i < 256; i++ {
		j = (j + int(Array[i]) + int(KeyArray[i%len(KeyArray)])) % 256
		Array[i], Array[j] = Array[j], Array[i]
	}
	a := 0
	b := 0
	SequenceChiffrante := []int{}
	//Generation of the cipher sequence.
	for i := 0; i < j; i++ {
		a = (a + 1) % 256
		b = (b + Array[a]) % 256
		Array[a], Array[b] = Array[b], Array[a]
		SequenceChiffrante = append(SequenceChiffrante, (Array[(Array[a]+Array[b])%256]))
	}
	for i := 0; i < 256; i++ {
		SequenceChiffrante = append(SequenceChiffrante, BinaryToDecimal(Xor(DecimalToBinary(Array[i]), DecimalToBinary(Array[j]))))
		j = (j + 1) % 256
	}
	lo := []rune(CryptedMessage)
	code := 0
	OriginalMessage := []rune{}
	i := 0
	//Decrypt each rune of the message with the generated RC4 sequence.
	for _, r := range lo {
		if GetNumeroASCII(r) != 0 {
			code = GetNumeroASCII(r)
		}
		OriginalMessage = append(OriginalMessage, rune(BinaryToDecimal(Xor(DecimalToBinary(SequenceChiffrante[i]), DecimalToBinary(code)))))
		i++
	}
	return string(OriginalMessage)
}

func EncryptRSA(N, E int, message string) string {
	var CryptedMessage string
	var ByteMessage []byte
	for i := 0; i < len(message); i++ {
		ByteMessage = append(ByteMessage, message[i])
	}
	blockSize := 256

	//We encrypt the characters two by two.
	if len(ByteMessage) > 2 {
		numBlocks := len(ByteMessage) / 2
		if len(ByteMessage)%2 != 0 {
			numBlocks++
		}

		for i := 0; i < numBlocks; i++ {
			start := i * 2
			end := (i + 1) * 2

			if end > len(ByteMessage) {
				end = len(ByteMessage)
			}
			// Extract the current block from ByteMessage.
			block := ByteMessage[start:end]

			numMessage := int(0)
			// Convert the bytes in the block to a numerical value.
			for j := 0; j < len(block); j++ {
				numMessage = (numMessage << 8) | int(block[j])
			}

			// Encrypt the numerical value of the block using the ModExp function.
			cryptedBlock := ModExp(numMessage, E, N)

			// Append the encrypted block to the CryptedMessage string in hexadecimal format.
			CryptedMessage += fmt.Sprintf("%08x", cryptedBlock)
		}
	} else {

		for i := 0; i < len(message); i += blockSize {
			end := i + blockSize
			if end > len(message) {
				end = len(message)
			}
			// Extract the current block from the message.
			block := message[i:end]

			numMessage := int(0)
			// Convert the bytes in the block to a numerical value.
			for j := 0; j < len(block); j++ {
				numMessage = (numMessage << 8) | int(block[j])
			}

			// Encrypt the numerical value of the block using the ModExp function.
			cryptedBlock := ModExp(numMessage, E, N)

			// Append the encrypted block to the CryptedMessage string in hexadecimal format.
			CryptedMessage += fmt.Sprintf("%08x", cryptedBlock)
		}
	}

	return CryptedMessage
}

func DecryptRSA(N, D int, ciphertext string) string {
	var OriginalMessage []byte
	blockSize := 256

	// We encrypt the characters eight by eight.
	if len(ciphertext) > 8 {
		numBlocks := len(ciphertext) / 8

		for i := 0; i < numBlocks; i++ {
			start := i * 8
			end := (i + 1) * 8
			// Extract the current block from ciphertext.
			block := ciphertext[start:end]

			ciphertextBlock := int(0)
			// Parse the block from hexadecimal format to its numerical value.
			fmt.Sscanf(block, "%016x", &ciphertextBlock)

			// Decrypt the numerical value of the block using the ModExp function.
			decryptedBlock := ModExp(ciphertextBlock, D, N)

			// Extract individual bytes from the decrypted block and append them to the OriginalMessage slice.
			for j := 0; j < 8; j++ {
				OriginalMessage = append(OriginalMessage, byte(decryptedBlock>>(8*(7-j))))
			}
		}
	} else {
		for i := 0; i < len(ciphertext); i += blockSize {
			end := i + blockSize
			if end > len(ciphertext) {
				end = len(ciphertext)
			}
			// Extract the current block from ciphertext.
			block := ciphertext[i:end]

			ciphertextBlock := int(0)
			// Parse the block from hexadecimal format to its numerical value.
			fmt.Sscanf(block, "%016x", &ciphertextBlock)

			// Decrypt the numerical value of the block using the ModExp function.
			decryptedBlock := ModExp(ciphertextBlock, D, N)

			// Extract individual bytes from the decrypted block and append them to the OriginalMessage slice.
			for j := 0; j < 8; j++ {
				OriginalMessage = append(OriginalMessage, byte(decryptedBlock>>(8*(7-j))))
			}
		}
	}
	// Remove potential unwanted characters.
	var FinalMessage string
	for _, v := range OriginalMessage {
		if GetNumeroASCII(rune(v)) != 0 {
			FinalMessage += string(v)
		}
	}
	return FinalMessage
}
