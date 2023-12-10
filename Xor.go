package crypt

func Xor(MessageBinaire []int, CleBinaire []int) []int {
	TableauCrypte := []int{}
	for i := 0; i < 8; i++ {
		if MessageBinaire[i] == 1 && CleBinaire[i] == 1 {
			TableauCrypte = append(TableauCrypte, 0)
		}
		if MessageBinaire[i] == 0 && CleBinaire[i] == 1 {
			TableauCrypte = append(TableauCrypte, 1)
		}
		if MessageBinaire[i] == 1 && CleBinaire[i] == 0 {
			TableauCrypte = append(TableauCrypte, 1)
		}
		if MessageBinaire[i] == 0 && CleBinaire[i] == 0 {
			TableauCrypte = append(TableauCrypte, 0)
		}
	}
	return TableauCrypte
}
