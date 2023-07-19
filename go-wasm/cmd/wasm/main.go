package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"syscall/js"
)

func main() {
	c := make(chan struct{})
	js.Global().Set("getEncryptedData", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		promiseConstructor := js.Global().Get("Promise")
		promise := promiseConstructor.New(js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			resolve := args[0]
			reject := args[1]
			go func() {

				// Frontend server generates its keys
				frontendPrivate, frontendPublic, err := GenerateKeyPair()
				if err != nil {
					fmt.Println("Error generating frontend keys:", err)
					reject.Invoke(js.ValueOf(err.Error()))
					return
				}

				// The frontend server sends its public key to the backend server and receives the backend server's public key
				resp, err := http.Get("http://localhost:9091/publicKey")
				if err != nil {
					fmt.Println("Error getting backend public key:", err)
					reject.Invoke(js.ValueOf(err.Error()))
					return
				}
				// Here, we first check if resp is not nil.
				if resp != nil {
					// We also check if resp.Body is not nil before closing it.
					if resp.Body != nil {
						defer resp.Body.Close()
					}
					// Checking the HTTP status code
					if resp.StatusCode != http.StatusOK {
						fmt.Println("Server returned non-OK status: ", resp.Status)
					}
				} else {
					fmt.Println("Response is nil")
					reject.Invoke(js.ValueOf("Response is nil"))
					return
				}

				backendPublic, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Println("Error reading backend public key:", err)
					reject.Invoke(js.ValueOf(err.Error()))
					return
				}

				bytesPublicKey, err := hex.DecodeString(string(backendPublic))
				if err != nil {
					panic(err)
				}

				// The frontend server generates the shared secret
				sharedSecret, err := GenerateSharedSecret(frontendPrivate, bytesPublicKey)
				if err != nil {
					fmt.Println("Error generating shared secret:", err)
					reject.Invoke(js.ValueOf(err.Error()))
					return
				}

				// The frontend server sends its public key to the backend server and receives an encrypted message
				resp, err = http.Get("http://localhost:9091/message?publicKey=" + hex.EncodeToString(frontendPublic))
				if err != nil {
					fmt.Println("Error getting message:", err)
					reject.Invoke(js.ValueOf(err.Error()))
					return
				}
				// Duplicate the resp and resp.Body null checks for the second http.Get
				if resp != nil {
					if resp.Body != nil {
						defer resp.Body.Close()
					}
					// Checking the HTTP status code
					if resp.StatusCode != http.StatusOK {
						fmt.Println("Server returned non-OK status: ", resp.Status)
					}
				} else {
					fmt.Println("Response is nil1")
					reject.Invoke(js.ValueOf("Response is nil1"))
					return
				}
				defer resp.Body.Close()

				ciphertext, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Println("Error reading message:", err)
					reject.Invoke(js.ValueOf(err.Error()))
					return
				}

				decodedMessage := make([]byte, base64.StdEncoding.DecodedLen(len(ciphertext)))
				_, err = base64.StdEncoding.Decode(decodedMessage, ciphertext)

				decodedMessage = bytes.Trim(decodedMessage, "\x00")
				if len(decodedMessage) == 0 {
					fmt.Println("Error: Decoded message is empty after trimming")
					reject.Invoke(js.ValueOf("Decoded message is empty after trimming"))
					return
				}
				
				plaintext, err := decrypt(decodedMessage, sharedSecret)
				fmt.Println("PLAINTEXT:", plaintext)
				if err != nil {
					fmt.Println("Error decrypting message:", err)
					reject.Invoke(js.ValueOf(err.Error()))
					return
				}

				resolve.Invoke(string(plaintext))
			}()
			return nil
		}))

		return promise
	}))
	<-c
}

func decrypt(ciphertext []byte, key []byte) (string, error) {
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

// GenerateKeyPair generates a public and private key pair.
func GenerateKeyPair() ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %v", err)
	}

	return privateBytes, publicBytes, nil
}

// GenerateSharedSecret generates a shared secret from own private key and other party's public key.
func GenerateSharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	privKey, err := x509.ParseECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	pubKey, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not of type *ecdsa.PublicKey")
	}

	z, _ := privKey.PublicKey.Curve.ScalarMult(ecdsaPubKey.X, ecdsaPubKey.Y, privKey.D.Bytes())
	return z.Bytes(), nil
}
