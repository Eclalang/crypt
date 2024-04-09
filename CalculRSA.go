package crypt

import (
	"math/big"
)

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

func ModExp(base, exp, mod *big.Int) *big.Int {
	result := new(big.Int).SetInt64(1)
	base = new(big.Int).Mod(base, mod)
	for exp.BitLen() > 0 {
		if exp.Bit(0) == 1 {
			result = result.Mul(result, base)
			result = result.Mod(result, mod)
		}
		exp = exp.Rsh(exp, 1)
		base = base.Mul(base, base)
		base = base.Mod(base, mod)
	}
	return result
}

func bitLen(n int64) int {
	if n == 0 {
		return 0
	}
	return 64 - int(clz(uint64(n)))
}

func clz(x uint64) uint {
	if x == 0 {
		return 64
	}
	n := uint(0)
	if x <= 0x00000000FFFFFFFF {
		n += 32
		x <<= 32
	}
	if x <= 0x0000FFFFFFFFFFFF {
		n += 16
		x <<= 16
	}
	if x <= 0x00FFFFFFFFFFFFFF {
		n += 8
		x <<= 8
	}
	if x <= 0x0FFFFFFFFFFFFFFF {
		n += 4
		x <<= 4
	}
	if x <= 0x3FFFFFFFFFFFFFFF {
		n += 2
		x <<= 2
	}
	if x <= 0x7FFFFFFFFFFFFFFF {
		n++
	}
	return n
}
