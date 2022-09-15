package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

func GenerateKey(passphrase string) ([]byte, error) {
	h := sha256.New()
	h.Write([]byte(passphrase))
	return h.Sum(nil), nil
}

func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}

	encrypted := gcm.Seal(nil, iv, plaintext, nil)
	encrypted = append(iv, encrypted...)
	return encrypted, nil
}

func Decrypt(encrypted []byte, key []byte) ([]byte, error) {
	if len(encrypted) < 13 {
		return nil, errors.New("invalid packet to decrypt")
	}

	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, encrypted[:12], encrypted[12:], nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
