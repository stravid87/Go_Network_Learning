package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
)

var KeyPairS_c KeyPairSigning

var KeyPairDH_c KeyPairDH

func Decrypt(ciphertext []byte, key []byte) (string, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return "error: ", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "error: ", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize { //length of ciphertext
		return "error: ", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	byteText, err := gcm.Open(nil, nonce, ciphertext, nil)

	return string(byteText), err
}
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	// Validate key length
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("crypto/aes: invalid key size %d, want: 16, 24 or 32", len(key))
	}

	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// GenerateKeyPair generates a public and private key pair.
func GenerateSigningKeyPair() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %v", err)
	}

	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}

	KeyPairS_c.privSK_bs = privateBytes
	KeyPairS_c.pubSK_bs = publicBytes

	return nil
}

func GenerateDHKeyPair(curve ecdh.Curve) error {
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println()
		return fmt.Errorf("Error calling curve.GenerateKey: %w", err)
	}

	publicKey := privateKey.PublicKey()

	KeyPairDH_c.privDHK_ptr = privateKey
	KeyPairDH_c.pubDHK_ptr = publicKey
	//Note: for ECDH, use the crypto/ecdh package. This function returns an encoding equivalent to that of PublicKey.Bytes in crypto/ecdh.
	return nil
}

// GenerateSharedSecret generates a shared secret from own private key and other party's public key.

func GenerateSharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey)
	z, _ := elliptic.P256().ScalarMult(x, y, privateKey)

	return z.Bytes(), nil
}

// OLD IMPLEMENTATION
// func GenerateSharedSecret(privateKey, publicKey []byte) ([]byte, error) {
// 	privKey, err := x509.ParseECPrivateKey(privateKey)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse private key: %v", err)
// 	}

// 	pubKey, err := x509.ParsePKIXPublicKey(publicKey)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse public key: %v", err)
// 	}

// 	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
// 	if !ok {
// 		return nil, fmt.Errorf("public key is not of type *ecdsa.PublicKey")
// 	}

// 	z, _ := privKey.PublicKey.Curve.ScalarMult(ecdsaPubKey.X, ecdsaPubKey.Y, privKey.D.Bytes())
// 	return z.Bytes(), nil
// }
