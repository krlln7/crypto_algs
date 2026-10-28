package vernam

import (
	"bytes"
	"errors"
	"fmt"
)

func Encrypt(message, key string) (string, error) {
	if len(message) != len(key) {
		return "", errors.New("Length of key should match len of message")
	}
	output := make([]byte, len(message))
	for i := range message {
		output[i] = message[i] ^ key[i]
	}
	return string(output), nil
}

// Decryption == same XOR operation as Encryption
func Decrypt(cyphmessage, key string) (string, error) {
	if len(cyphmessage) != len(key) {
		return "", errors.New("Length of key should match len of cyphmessage")
	}
	output := make([]byte, len(cyphmessage))
	for i := range cyphmessage {
		output[i] = cyphmessage[i] ^ key[i]
	}
	return string(output), nil
}

func ToBinaryString(s string) string {
	var buf bytes.Buffer
	for i := 0; i < len(s); i++ {
		buf.WriteString(fmt.Sprintf("%08b", s[i]))
	}
	return buf.String()
}
