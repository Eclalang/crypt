package crypt

import (
	"math"
)

func DecimalToBinaire(nombre int) []int {
	TableauBinaire := [8]int{}
	compteur := 0
	i := 128
	for compteur != 8 {
		if i <= nombre {
			nombre -= i
			TableauBinaire[compteur] = 1

		}
		compteur++
		i /= 2
	}
	return TableauBinaire[:]
}

func BinaireToDecimal(TableauBinaire []int) int {
	nombre := 0
	exposant := 7
	for i := 0; i < 8; i++ {
		if TableauBinaire[i] == 1 {
			nombre += int(math.Pow(2, float64(exposant)))

		}
		exposant--
	}
	return nombre
}
