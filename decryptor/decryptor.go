package decryptor

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

func Decrypt(sharedSecret [32]byte, ciphertext []byte) ([]byte, error) {

	aead, err := chacha20poly1305.New(sharedSecret[:])
	if err != nil {
		return nil, fmt.Errorf("Error creating new chacha20poly1305: %v", err)
	}

	// Extract the nonce from the beginning of the ciphertext
	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]

	// Decrypt the ciphertext using the extracted nonce
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("Error decrypting ciphertext: %v", err)
	}
	return plaintext, nil
}
