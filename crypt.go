package crypt

func EncryptCaesar(cle int, messageDecode string) string {
	messageCode := []rune{}
	for i := 0; i < len(messageDecode); i++ {
		if (messageDecode[i] < 'a' && messageDecode[i] > 'Z') || (messageDecode[i] < 'A' || messageDecode[i] > 'z') {
			messageCode = append(messageCode, rune(messageDecode[i]))
		}
		if messageDecode[i] >= 'a' && messageDecode[i] <= 'z' {
			Lettre := int((messageDecode[i])) + cle
			if Lettre > 122 {
				Lettre -= 26
			}
			messageCode = append(messageCode, rune(Lettre))
		}
		if messageDecode[i] >= 'A' && messageDecode[i] <= 'Z' {
			Lettre := int((messageDecode[i])) + cle
			if Lettre > 90 {
				Lettre -= 26
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
			if Lettre < 97 {
				Lettre += 26
			}
			messageDecode = append(messageDecode, rune(Lettre))
		}
		if messageCode[i] >= 'A' && messageCode[i] <= 'Z' {
			Lettre := int((messageCode[i])) - cle
			if Lettre < 65 {
				Lettre += 26
			}
			messageDecode = append(messageDecode, rune(Lettre))
		}
	}
	return string(messageDecode)
}
