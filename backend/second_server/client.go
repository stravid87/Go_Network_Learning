package main

import (
	// "bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"proto"
	"strings"
	// "time"

	"github.com/rs/cors"
	"google.golang.org/grpc"
)

func main() {
	connection, err := grpc.Dial("localhost:9090", grpc.WithInsecure())
	// grpc.Dial is a function that creates a client connection to the given target
	// "localhost:9090" is the target which the function is creating a connection to.
	// grpc.WithInsecure() is an option to create the connection without encryption, which
	// is not recommended for production code, but it's fine in development or testing stage when security is not the critical consideration
	if err != nil {
		log.Println(err)
	}

	client := proto.NewChatServiceClient(connection)

	message := proto.Message{
		Body: "Thank you for long Lorem!",
	}

	resp, err := client.SendLorem(context.Background(), &message)
	if err != nil {
		log.Println(err)
	}
	text := []byte(resp.Body)

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
		fmt.Println(sharedSecret)
		// Encrypt a message
		message := text
		fmt.Println(message)

		newMsg := []byte("Ravi Test message")

		ciphertext, err := encrypt(newMsg, sharedSecret)
		fmt.Println(ciphertext)
		if err != nil {
			fmt.Println("Error encrypting message:", err)
			return
		}

		// Start the server and send the encrypted message to the frontend server
		// startServer(ciphertext)

		fmt.Fprintf(w, "%v", ciphertext)
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

// func startServer(cipherText []byte) {
// 	mux := http.NewServeMux()
// 	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
// 		fmt.Fprintf(w, "%x", cipherText)
// 	})

// 	c := cors.New(cors.Options{
// 		AllowedOrigins: []string{"http://localhost:8080"},
// 		AllowedMethods: []string{"GET", "OPTIONS"},
// 		AllowedHeaders: []string{"Accept", "Accept-Language", "Content-Language", "Content-Type"},
// 	})

// 	server := &http.Server{
// 		Addr:         ":9091",
// 		ReadTimeout:  5 * time.Minute,
// 		WriteTimeout: 10 * time.Second,
// 		Handler:      c.Handler(mux),
// 	}

// 	log.Fatal(server.ListenAndServe())
// }

// GenerateKeyPair generates a public and private key pair.
func GenerateKeyPair() ([]byte, []byte, error) {
	private, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	public := elliptic.Marshal(elliptic.P256(), x, y)

	return private, public, nil
}

// GenerateSharedSecret generates a shared secret from own private key and other party's public key.
func GenerateSharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey)
	z, _ := elliptic.P256().ScalarMult(x, y, privateKey)

	return z.Bytes(), nil
}
