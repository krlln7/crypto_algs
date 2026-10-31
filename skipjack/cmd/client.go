package main

import (
	"fmt"
	"log"
	"os"
	"skipjack/internal"
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
	key := []byte{0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}
	if err := internal.SetKey(key); err != nil {
		log.Fatal(err)
	}

	in, err := os.Open(os.Args[2])
	internal.Check(err)
	defer in.Close()

	out, err := os.Create(os.Args[1] + "_out")
	internal.Check(err)
	defer out.Close()

	switch os.Args[1] {
	case "encode":
		internal.Encrypt(in, out)
	case "decode":
		internal.Decrypt(in, out)
	default:
		usage()
		return
	}
}
