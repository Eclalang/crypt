package crypt

func EncryptCaesar(cle int, messageDecode string) string {
	messageCode := []rune{}
	for i := 0; i < len(messageDecode); i++ {
		if (messageDecode[i] < 'a' && messageDecode[i] > 'Z') || (messageDecode[i] < 'A' || messageDecode[i] > 'z') {
			messageCode = append(messageCode, rune(messageDecode[i]))
		}
		if messageDecode[i] >= 'a' && messageDecode[i] <= 'z' {
			Lettre := int((messageDecode[i])) + cle
			for Lettre > 122 {
				Lettre -= 26
			}
			for Lettre < 97 {
				Lettre += 26
			}
			messageCode = append(messageCode, rune(Lettre))
		}
		if messageDecode[i] >= 'A' && messageDecode[i] <= 'Z' {
			Lettre := int((messageDecode[i])) + cle
			for Lettre > 90 {
				Lettre -= 26
			}
			for Lettre < 65 {
				Lettre += 26
			}
			messageCode = append(messageCode, rune(Lettre))
		}
	}
	return string(messageCode)
}

func DecryptCaesar(cle int, messageCode string) string {
	messageDecode := []rune{}
	for i := 0; i < len(messageCode); i++ {
		if (messageCode[i] < 'a' && messageCode[i] > 'Z') || (messageCode[i] < 'A' || messageCode[i] > 'z') {
			messageDecode = append(messageDecode, rune(messageCode[i]))
		}
		if messageCode[i] >= 'a' && messageCode[i] <= 'z' {
			Lettre := int((messageCode[i])) - cle
			for Lettre > 122 {
				Lettre -= 26
			}
			for Lettre < 97 {
				Lettre += 26
			}
			messageDecode = append(messageDecode, rune(Lettre))
		}
		if messageCode[i] >= 'A' && messageCode[i] <= 'Z' {
			Lettre := int((messageCode[i])) - cle
			for Lettre > 90 {
				Lettre -= 26
			}
			for Lettre < 65 {
				Lettre += 26
			}
			messageDecode = append(messageDecode, rune(Lettre))
		}
	}
	return string(messageDecode)
}

func EncryptRC4(cle string, message string) string {
	Tableau := [256]int{}
	for i := 0; i < 256; i++ {
		Tableau[i] = i
	}
	TableauCle := []rune{}
	for i := 0; i < len(cle); i++ {
		TableauCle = append(TableauCle, rune(cle[i]))
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(Tableau[i]) + int(TableauCle[i%len(TableauCle)])) % 256
		Tableau[i], Tableau[j] = Tableau[j], Tableau[i]
	}
	a := 0
	b := 0
	SequenceChiffrante := []int{}
	for i := 0; i < j; i++ {
		a = (a + 1) % 256
		b = (b + Tableau[a]) % 256
		Tableau[a], Tableau[b] = Tableau[b], Tableau[a]
		SequenceChiffrante = append(SequenceChiffrante, (Tableau[(Tableau[a]+Tableau[b])%256]))
	}
	for i := 0; i < 256; i++ {
		SequenceChiffrante = append(SequenceChiffrante, BinaireToDecimal(Xor(DecimalToBinaire(Tableau[i]), DecimalToBinaire(Tableau[j]))))
		j = (j + 1) % 256
	}
	MessageCrypte := []rune{}
	for i := 0; i < len(message); i++ {
		MessageCrypte = append(MessageCrypte, rune(BinaireToDecimal(Xor(DecimalToBinaire(SequenceChiffrante[i]), DecimalToBinaire(int(message[i]))))))
	}
	return string(MessageCrypte)
}

func DecryptRC4(cle string, messageCode string) string {
	TableauMessage := []rune{}
	MessageDecrypte := []rune{}
	for i := 0; i < len(messageCode); i++ {
		TableauMessage = append(TableauMessage, rune(messageCode[i]))
	}
	TableauCle := []rune{}
	for i := 0; i < len(cle); i++ {
		TableauCle = append(TableauCle, rune(cle[i]))
	}
	j := 0
	for i := 0; i < len(TableauMessage); i++ {
		MessageDecrypte = append(MessageDecrypte, rune(BinaireToDecimal(Xor(DecimalToBinaire(int(TableauMessage[i])), DecimalToBinaire(int(TableauCle[j]))))))
		j++
		if j == len(TableauCle) {
			j = 0
		}
	}
	return string(MessageDecrypte)
}
