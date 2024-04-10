package crypt

// Generates an rsa key pair
func GenerateKeyRSA(p, q int) ([]int, []int) {
	N := p * q
	X := (p - 1) * (q - 1)
	var E int = 65537
	var D int = ModuloInverse(E, int(X))
	publicKey := []int{N, E}
	privateKey := []int{N, D}

	return publicKey, privateKey
}

// Calculates the modular inverse of an integer a modulo m using the extended Euclid modulo inversion algorith
func ModuloInverse(a, m int) int {
	var m0, x0, x1 int = m, 0, 1
	for a > 1 {
		var q int = a / m
		m, a = a%m, m
		x0, x1 = x1-q*x0, x0
	}
	if x1 < 0 {
		x1 += m0
	}
	return x1
}

// Calculates modular exponentiation using the fast exponentiation algorithm
func ModExp(base, exp, mod int) int {
	result := int(1)
	base %= mod
	for exp > 0 {
		if exp&1 == 1 {
			result = (result * base) % mod
		}
		exp >>= 1
		base = (base * base) % mod
	}
	return result
}
