package crypt

import "strconv"

func ModuloInverse(a, m int) int {
	m0, x0, x1 := m, 0, 1
	for a > 1 {
		q := a / m
		m, a = a%m, m
		x0, x1 = x1-q*x0, x0
	}
	if x1 < 0 {
		x1 += m0
	}
	return x1
}

func ModExp(base, exponent, modulus int) int {
	result := 1
	base = base % modulus
	for exponent > 0 {
		if exponent%2 == 1 {
			result = (result * base) % modulus
		}
		exponent = exponent >> 1
		base = (base * base) % modulus
	}
	return result
}

func intToString(val int) string {
	result := strconv.Itoa(val)
	return result
}
