package crypt

import (
	"math"
)

// Convert a decimal number to binary
func DecimalToBinary(nombre int) []int {
	BinaryArray := [8]int{}
	compteur := 0
	i := 128
	for compteur != 8 {
		if i <= nombre {
			nombre -= i
			BinaryArray[compteur] = 1

		}
		compteur++
		i /= 2
	}
	return BinaryArray[:]
}

// Convert a binary number to decimal
func BinaryToDecimal(BinaryArray []int) int {
	nombre := 0
	exposant := 7
	for i := 0; i < 8; i++ {
		if BinaryArray[i] == 1 {
			nombre += int(math.Pow(2, float64(exposant)))

		}
		exposant--
	}
	return nombre
}

// Convert a string to binary
func StringToBinary(s string) []int {
	binRep := []int{}
	for _, char := range s {
		ascii := GetNumeroASCII(char)
		binRep = append(binRep, DecimalToBinary(ascii)...)
	}
	return binRep
}

// Retrieve the ASCII number of a rune.
func GetNumeroASCII(caractere rune) int {
	return int(caractere)
}
