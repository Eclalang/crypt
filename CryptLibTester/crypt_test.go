package crypt

import (
	"testing"

	"github.com/Eclalang/crypt"
)

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

func TestRC4(t *testing.T) {
	TableauTest := []rune{}
	cle := "öµ€1"
	message := "Ecla the best lang"
	for i := 0; i < len(crypt.EncryptRC4(cle, message)); i++ {
		TableauTest = append(TableauTest, rune(crypt.EncryptRC4(cle, message)[i]))
	}
	expected := "çEærÝ)!_£Å=D¸<Ï½?­"
	TableauExpected := []rune{}
	for i := 0; i < len(expected); i++ {
		TableauExpected = append(TableauExpected, rune(expected[i]))
	}
	got := TableauTest
	//expectedDecrypt := message
	//gotDecrypt := crypt.DecryptRC4(cle, expected)
	t.Log("Message ", message, ", la clé est ", cle, "\nLe message crypté est " /*, expected, "\nUne fois décrypté le message est, ", expectedDecrypt*/)
	for i := 0; i < len(TableauTest); i++ {
		if TableauExpected[i] != got[i] {
			t.Errorf("crypt.EncryptRC4(%v, %v) \n, got %v \n expected %v \n", cle, message, got, TableauExpected)
		}
	}
	//if expectedDecrypt != gotDecrypt {
	//	t.Errorf("crypt.DecryptRC4(%v, %v) \n, got %v \n expected %v \n", cle, got, gotDecrypt, expectedDecrypt)
	//}
}
