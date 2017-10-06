package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
)

func main() {
	var senha, decripto string
	fmt.Println("Informe sua senha para criptografá-la:")
	fmt.Scanln(&senha)
	text := []byte(senha)
	key := []byte("the-key-has-to-be-32-bytes-long!")

	ciphertext, err := encrypt(text, key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Sua senha criptografada é: %x\n", ciphertext)

	fmt.Println("Deseja decriptografá-la?")
	fmt.Scanln(&decripto)

	if decripto = "SIM" {
	plaintext, err := decrypt(ciphertext, key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Sua senha decriptografada é: %s\n", plaintext)
	}
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
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

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
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
		return nil, errors.New("Texto cifrado muito curto!")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
