package crypto_helper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}


/*
func main() {
	text := []byte("My name is Astaxief ksadjhf klsadh fksaj fhsadkj hsadklf ")
	key := []byte("the-key-has-to-be-32-bytes-long!")

	ciphertext, err := crypto_helper.Encrypt(text, key)
	if err != nil {
		// TODO: Properly handle error
		log.Fatal(err)
	}
	fmt.Printf("%s => %x\n", text, ciphertext)

	plaintext, err := crypto_helper.Decrypt(ciphertext, key)
	if err != nil {
		// TODO: Properly handle error
		log.Fatal(err)
	}
	fmt.Printf("%x => %s\n", ciphertext, plaintext)
}
*/