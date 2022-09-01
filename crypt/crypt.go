package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

func GenerateKey(passphrase string, usersalt []byte) ([]byte, []byte, error) {
	var salt []byte
	if usersalt == nil {
		salt = make([]byte, 8)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	} else {
		salt = usersalt
	}

	key := pbkdf2.Key([]byte(passphrase), salt, 100, 32, sha256.New)
	return key, salt, nil
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
