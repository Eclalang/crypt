package crypt

func GeneratKeyRSA(p, q int64) ([]int64, []int64) {
	N := p * q
	X := (p - 1) * (q - 1)
	var E int64 = 65537
	var D int64 = ModuloInverse(E, int64(X))
	publicKey := []int64{N, E}
	privateKey := []int64{N, D}

	return publicKey, privateKey
}

func ModuloInverse(a, m int64) int64 {
	var m0, x0, x1 int64 = m, 0, 1
	for a > 1 {
		var q int64 = a / m
		m, a = a%m, m
		x0, x1 = x1-q*x0, x0
	}
	if x1 < 0 {
		x1 += m0
	}
	return x1
}

func ModExp(base, exp, mod int64) int64 {
	result := int64(1)
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
