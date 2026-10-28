package skipjack

import (
	"fmt"
	"os"
)

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: go run client <encode|decode> <filename>")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 3 {
		usage()
		return
	}
	in, err := os.Open(os.Args[2])
	check(err)
	defer in.Close()

	out, err := os.Create(os.Args[1] + "_out")
	check(err)
	defer out.Close()

	switch os.Args[1] {
	case "encode":
		os.WriteFile("encode_out", Encrypt(in, out), 0644)
	case "decode":
		os.WriteFile("decode_out", Decrypt(in, out), 0644)
	default:
		usage()
		return
	}
}
