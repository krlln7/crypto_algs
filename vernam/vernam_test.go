package vernam

import "testing"

func TestShortEnDecriptionShortKey(t *testing.T) {
	encrypted, _ := Encrypt("DOG", "CAT")

	t.Run("Encrypt DOG with key CAT", func(t *testing.T) {
		got := ToBinaryString(encrypted)
		want := "000001110000111000010011"

		assertCorrectMessage(t, got, want)
	})
	t.Run("Decrypt encripted DOG with the same key CAT", func(t *testing.T) {
		decrypted, _ := Decrypt(encrypted, "CAT")
		got := decrypted
		want := "DOG"

		assertCorrectMessage(t, got, want)
	})
}

func assertCorrectMessage(t testing.TB, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
