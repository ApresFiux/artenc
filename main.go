package artEnc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	customloghandler "github.com/apresfiux/artloghandler"
	"io"
	"io/ioutil"
)

func Encrypt(Str string, keyfile string) []byte {
	data, err := ioutil.ReadFile(keyfile)
	plaintext := []byte(Str)
	ciphertext, err := EncryptAES(data, plaintext)
	customloghandler.LogError(err, true, false)
	return ciphertext //fmt.Sprintf("%0x\n", ciphertext)
}

func Decrypt(ciphertext string, keyfile string) string {
	data, err := ioutil.ReadFile(keyfile)
	result, err := DecryptAES(data, []byte(ciphertext))
	customloghandler.LogError(err, true, false)
	return string(result)
}

var iv = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}

func EncryptAES(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func DecryptAES(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}
