package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

func StringToBase64(input []byte) string {
	b64str := base64.StdEncoding.EncodeToString(input)
	return b64str
}

func HashByteSlice(input []byte) ([]byte, error) {
	hash := sha256.New()
	if _, err := hash.Write(input); err != nil {
		return nil, fmt.Errorf("HashMessage of WASM module failed with error %s", err.Error())
	}
	return hash.Sum(nil), nil
}

func SignByteSliceASN1(privK *ecdsa.PrivateKey, inputHash []byte) ([]byte, error) {
	theASN1Signature, err := ecdsa.SignASN1(rand.Reader, privK, inputHash)
	if err != nil {
		return nil, fmt.Errorf("SignASN1 error: %w", err.Error())
	}
	return theASN1Signature, nil
}

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

func GenerateSigningKeyPair() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	publicKey := privateKey.Public()
	KeyPairS_c.privSK_ptr = privateKey
	KeyPairS_c.pubSK_val = publicKey
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
