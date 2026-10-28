package skipjack

import (
	"fmt"
	"io"
	"os"
)

const (
	chunkSize = 16 * 1024
)

func check(e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, "error:", e)
		os.Exit(1)
	}
}

// Run input r through function f and write to output w
func pipe(r io.Reader, w io.Writer, f func([]byte) ([]byte, error)) error {
	buf := make([]byte, chunkSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out, ferr := f(buf[:n])
			if ferr != nil {
				return ferr
			}
			if len(out) > 0 {
				if _, eerr := w.Write(out); eerr != nil {
					return eerr
				}
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
