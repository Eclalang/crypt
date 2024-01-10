package crypt

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
