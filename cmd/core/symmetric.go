package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// Encrypt plaintext (Secret message) using secret key (argon2id)
func EncryptAES(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt ciphertext using secret key (argon2id)
func DecryptAES(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	size := aesGCM.NonceSize()
	nonce, cipher := ciphertext[:size], ciphertext[size:]
	plaintext, err := aesGCM.Open(nil, nonce, cipher, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
