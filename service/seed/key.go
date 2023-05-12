package seed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"crypto_tool/utils"
)

const (
	seed_name    = "seed"
	reserve_path = "ctoolspace"
	seed_size    = 32
	iv_size      = 16
)

var (
	SeedService = &serverSeed{}
	code_salt   = []byte("370D11F9F9D6409E93390D66E9ADB9A8")
)

type serverSeed struct {
	code []byte
}

func (m *serverSeed) Init(key string) {
	var code = sha512.Sum512_256([]byte(key))
	m.code = code[:]
}

func (m *serverSeed) GetSeed() ([]byte, error) {
	var pname = m.getSeedPathName()
	if utils.IsFileExists(pname) {
		return m.loadSeed(pname)

	} else {
		return m.createAndSave(pname)
	}
}

func (m *serverSeed) RemoveSeed() error {
	var pname = m.getSeedPathName()
	if utils.IsFileExists(pname) {
		return os.Remove(pname)
	}

	return nil
}

func (m *serverSeed) createAndSave(pathname string) ([]byte, error) {
	var seed = make([]byte, seed_size)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		fmt.Println("generate seed error: ", err)
		return nil, err
	}

	return seed, m.saveSeed(pathname, seed)
}

func (m *serverSeed) saveSeed(pathname string, seed []byte) error {
	f, err := os.Create(pathname)
	if err != nil {
		fmt.Printf("open %s error: %v \n", pathname, err)
		return err
	}
	defer f.Close()

	// encrypt seed
	var iv = make([]byte, iv_size)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Println("generate iv error: ", err)
		return err
	}

	var skey = utils.HashMac(m.code, code_salt)
	cipher, err := m.Crypt(seed, iv, skey)
	if err != nil {
		fmt.Errorf("encrypt seed error: ", err)
		return err
	}

	fmt.Println("seed iv: ", hex.EncodeToString(skey))
	fmt.Println("seed cr: ", hex.EncodeToString(cipher))

	n, err := f.Write(append(iv, cipher...))
	if err != nil || n != len(seed) {
		return fmt.Errorf("write seed error: ", err)
	}

	return nil
}

func (m *serverSeed) loadSeed(pathname string) ([]byte, error) {
	f, err := os.Open(pathname)
	if err != nil {
		fmt.Printf("open %s error: %v \n", pathname, err)
		return nil, err
	}
	defer f.Close()

	var buf = make([]byte, iv_size+seed_size)
	n, err := f.Read(buf)
	if err != nil || n != len(buf) {
		return nil, fmt.Errorf("read seed error: ", err)
	}

	fmt.Println("seed iv: ", hex.EncodeToString(buf[:iv_size]))
	fmt.Println("seed cr: ", hex.EncodeToString(buf[iv_size:]))

	// decrypt seed
	var skey = utils.HashMac(m.code, code_salt)
	return m.Crypt(buf[iv_size:], buf[:iv_size], skey)
}

func (m *serverSeed) getSeedPathName() string {
	var cpath, err = utils.GetExePath()
	if err != nil {
		panic(err)
	}

	return filepath.Join(cpath, reserve_path, seed_name)
}

func (m *serverSeed) Crypt(input []byte, iv []byte, skey []byte) ([]byte, error) {
	var length = len(input)
	if length < 1 || len(iv) != iv_size || len(skey) != 32 {
		return nil, fmt.Errorf("param empty")
	}

	blk, err := aes.NewCipher(skey)
	if err != nil {
		fmt.Println("new cipher sm4 error: ", err)
		return nil, err
	}

	ctr := cipher.NewCTR(blk, iv)
	var output = make([]byte, length)
	ctr.XORKeyStream(output, input)

	return output, nil
}
