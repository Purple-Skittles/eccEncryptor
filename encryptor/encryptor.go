package encryptor

import (
	"crypto/rand"
	"embed"
	"errors"
	"fmt"
	"log"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func LoadKey(keyFiles embed.FS, filename string) ([32]byte, error) {
	var key [32]byte
	data, err := keyFiles.ReadFile(filename)

	if err != nil {
		return key, fmt.Errorf("failed to read %s: %w", filename, err)
	}

	if len(data) != 32 {
		return key, errors.New("invalid key length, expected 32 bytes")
	}

	copy(key[:], data)
	return key, nil
}

// TODO: think about the error handling here
func GenerateKeyPair() ([32]byte, [32]byte) {
	var priv [32]byte

	_, err := rand.Read(priv[:])
	if err != nil {
		log.Fatalf("Error generating private key: %v", err)
	}

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		log.Fatalf("Error generating public key: %v", err)
	}

	var pubArray [32]byte
	copy(pubArray[:], pub)

	return priv, pubArray
}

func GetSharedSecret(privKey [32]byte, pubKey [32]byte) ([32]byte, error) {
	sharedSecret, err := curve25519.X25519(privKey[:], pubKey[:])
	if err != nil {
		log.Fatalf("Error generating shared secret: %v", err)
		return [32]byte{}, err
	}

	var sharedSecretArray [32]byte
	copy(sharedSecretArray[:], sharedSecret)

	return sharedSecretArray, nil
}

func Encrypt(sharedSecret [32]byte, plaintext []byte) (ciphertext []byte) {
	aead, err := chacha20poly1305.New(sharedSecret[:])
	if err != nil {
		log.Fatalf("Error creating new chacha20poly1305: %v", err)
	}

	nonce := make([]byte, aead.NonceSize()) // Use aead.NonceSize() instead of chacha20poly1305.NonceSize
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatalf("Error generating nonce: %v", err)
	}

	ciphertext = make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())

	ciphertext = append(ciphertext, nonce...)

	ciphertext = aead.Seal(ciphertext, nonce, plaintext, nil)
	return ciphertext
}
