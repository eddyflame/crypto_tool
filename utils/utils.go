package utils

import (
	"crypto/sha512"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func GetExePath() (string, error) {
	var exc, err = os.Executable()
	if err != nil {
		return "", err
	}

	exe_path := filepath.Dir(exc)
	fmt.Println("exe_path:", exe_path)
	return exe_path, nil
}

func IsFileExists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		} else {
			return false
		}
	}
	return true
}

func IsFileOverWrite() bool {
	var ans string

	for i := 0; i < 3; i++ {
		fmt.Printf("output file exist, overwrite [N|y]? ")
		fmt.Scan(&ans)

		switch strings.ToLower(ans) {
		case "n":
			fallthrough
		case "no":
			return false

		case "y":
			fallthrough
		case "yes":
			return true

		default:
			fmt.Println("unknown answer, try again")
			continue
		}
	}

	return false
}

func HashMac(input, salt []byte) []byte {
	var hash_data = sha512.Sum512_256(append(input, salt...))

	for i := 0; i < 10; i++ {
		var tmp_data = append(hash_data[:], salt...)
		hash_data = sha512.Sum512_256(tmp_data)
	}

	return hash_data[:]
}
