package crypt

import (
	"fmt"
	"testing"

	"github.com/Eclalang/crypt"
)

// Test the 'Encrypt' and 'Decrypt' Caesar functions.
func TestCaesar(t *testing.T) {
	key := 13
	message := "Le trafic est interrompu sur le Rer A entre nanterre prefecture et gare de lyon en raison d'un bagage oublie a Chatelet les Halles"
	expected := "Yr gensvp rfg vagreebzch fhe yr Ere N rager anagreer cersrpgher rg tner qr ylba ra envfba q'ha ontntr bhoyvr n Pungryrg yrf Unyyrf"
	got := crypt.EncryptCaesar(key, message)
	expectedDecrypt := message
	gotDecrypt := crypt.DecryptCaesar(key, got)
	t.Log("Message ", message, ", la clé caesar est", key, "\nLe message crypté est", got, "\nUne fois décrypté le message est, ", gotDecrypt)

	if expected != got {
		t.Errorf("crypt.EncryptCaesar(%v, %v) \n, got %v \n expected %v \n", key, message, got, expected)
	}
	if expectedDecrypt != gotDecrypt {
		t.Errorf("crypt.DecryptCaesar(%v, %v) \n, got %v \n expected %v \n", key, got, gotDecrypt, expectedDecrypt)
	}
}

// Test the 'Encrypt' and 'Decrypt' RC4 functions.
func TestRC4(t *testing.T) {
	cle := "^*$$1"
	message := "Ecla The Best Lang"
	expected := [][]int{
		{1, 0, 1, 0, 1, 1, 0, 0},
		{1, 1, 0, 0, 1, 1, 1, 0},
		{0, 0, 1, 0, 0, 1, 1, 1},
		{0, 1, 1, 1, 1, 0, 0, 0},
		{0, 1, 0, 0, 0, 1, 0, 1},
		{1, 0, 0, 1, 0, 1, 1, 0},
		{1, 0, 0, 0, 1, 0, 1, 1},
		{1, 0, 0, 0, 0, 0, 1, 1},
		{0, 0, 0, 1, 1, 1, 0, 0},
		{1, 1, 0, 1, 1, 1, 1, 0},
		{0, 0, 1, 1, 1, 1, 0, 0},
		{0, 0, 0, 1, 1, 1, 0, 1},
		{0, 0, 0, 1, 0, 0, 0, 0},
		{1, 0, 0, 1, 1, 0, 0, 1},
		{0, 1, 1, 0, 1, 0, 1, 1},
		{0, 1, 1, 1, 0, 1, 0, 1},
		{0, 1, 1, 0, 0, 0, 0, 0},
		{1, 0, 1, 0, 0, 1, 1, 1},
	}
	got := crypt.EncryptRC4(cle, message)
	binGot := crypt.StringToBinary(got)

	t.Log("Message:", message)
	t.Log("Clé:", cle)
	t.Log("Message crypté:", got)

	cols := 8
	var structuredGot [][]int
	for i := 0; i < len(binGot); i += cols {
		structuredGot = append(structuredGot, binGot[i:i+cols])
	}

	t.Log("Binary representation of got:", structuredGot)
	t.Log("Expected binary representation:", expected)

	if fmt.Sprintf("%v", expected) != fmt.Sprintf("%v", structuredGot) {
		t.Errorf("Erreur d'encryptage: got %v, expected %v", structuredGot, expected)
	}

	decrypted := crypt.DecryptRC4(cle, crypt.EncryptRC4(cle, message))
	if message != decrypted {
		t.Errorf("Erreur de décryptage: got %v, expected %v", decrypted, message)
	}
}
