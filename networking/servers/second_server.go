package main

import (
	// "bytes"
	// "context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	// "log"
	mathRand "math/rand"
	"net/http"
	// "proto"
	"strings"
	"time"

	// "time"

	"github.com/rs/cors"
	// "google.golang.org/grpc"
)
var data = []interface{}{"item1", 1234567, true, 45777.6, "item5", "item6", "item7", 789777, false, 37772.1}
func main() {
	// connection, err := grpc.Dial("localhost:9090", grpc.WithInsecure())

	// if err != nil {
	// 	log.Println(err)
	// }

	// client := proto.NewChatServiceClient(connection)

	// message := proto.Message{
	// 	Body: "Thank you for long Lorem!",
	// }

	// resp, err := client.SendLorem(context.Background(), &message)
	// if err != nil {
	// 	log.Println(err)
	// }
	// text := []byte(resp.Body)

	// Backend server generates its keys
	backendPrivate, backendPublic, err := GenerateKeyPair()
	if err != nil {
		fmt.Println("Error generating backend keys:", err)
		return
	}
	fmt.Println(len(backendPublic))

	// The backend server starts an HTTP server to exchange public keys and messages
	http.HandleFunc("/publicKey", func(w http.ResponseWriter, r *http.Request) {
		// Send the backend server's public key to the frontend server
		fmt.Fprint(w, hex.EncodeToString(backendPublic))
	})

	
	http.HandleFunc("/message", func(w http.ResponseWriter, r *http.Request) {
		randomData := getRandomData()
		stringData := toString(randomData)

		text := []byte(stringData)
    	// randomData.(string)

		// Receive the frontend server's public key
		publicKey := r.URL.Query().Get("publicKey")
		// Remove any double quotes from the string
		publicKey = strings.ReplaceAll(publicKey, "\"", "")
		frontendPublic, err := hex.DecodeString(publicKey)
		if err != nil {
			fmt.Println("Error decoding frontend public key:", err)
			return
		}

		// Generate the shared secret
		sharedSecret, err := GenerateSharedSecret(backendPrivate, frontendPublic)
		if err != nil {
			fmt.Println("Error generating shared secret:", err)
			return
		}
		// Encrypt a message
		message := text
		// fmt.Println(message)

		// newMsg := []byte("Ravi Test message")

		ciphertext, err := encrypt(message, sharedSecret)
		encodedMessage := base64.StdEncoding.EncodeToString(ciphertext)
		if err != nil {
			fmt.Println("Error encrypting message:", err)
			return
		}

		// Start the server and send the encrypted message to the frontend server
		// startServer(ciphertext)

		fmt.Fprintf(w, "%v", encodedMessage)
	})

	// Create a new CORS handler
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:8080"},  // Allow the frontend server to access the backend server
		AllowedMethods:   []string{"GET", "POST", "PUT", "OPTIONS"}, // Allow these HTTP methods
		AllowedHeaders:   []string{"Accept", "content-type"}, // Allow these HTTP headers
		AllowCredentials: true,                               // Allow cookies
	})

	// Wrap the original handler with the CORS handler
	handler := c.Handler(http.DefaultServeMux)

	// Start the server with the CORS handler
	http.ListenAndServe(":9091", handler)
}

func getRandomData() interface{} {
	mathRand.Seed(time.Now().UnixNano())
	return data[mathRand.Intn(len(data))]
}

func toString(i interface{}) (string) {
	str := fmt.Sprintf("%v", i)
	return str
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
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
