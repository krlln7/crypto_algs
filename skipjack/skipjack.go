package skipjack

import (
	"io"
)

func EncryptChunk(chunk []byte) ([]byte, error) {
	return nil, nil
}

func DecryptChunk(chunk []byte) ([]byte, error) {
	return nil, nil
}

func Encrypt(r io.Reader, w io.Writer) error {
	return pipe(r, w, EncryptChunk)
}

func Decrypt(r io.Reader, w io.Writer) error {
	return pipe(r, w, DecryptChunk)
}
