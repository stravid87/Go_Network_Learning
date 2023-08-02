package main

import (
	// "bytes"
	// "context"
	// "bytes"
	// "crypto/aes"
	// "crypto/cipher"
	// "crypto/ecdsa"
	// "crypto/elliptic"
	// "crypto/rand"
	// "crypto/x509"
	// "encoding/base64"
	// "encoding/hex"
	// "encoding/json"
	// "errors"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"crypto/sha256"

	// "log"
	// mathRand "math/rand"
	"net/http"

	// "proto"
	// "strings"
	// "time"

	// "time"

	"github.com/rs/cors"
	// "google.golang.org/grpc"
)

var data = []interface{}{"item1", 1234567, true, 45777.6, "item5", "item6", "item7", 789777, false, 37772.1}

type IncomingData struct {
	Message string `json:"message"`
}
type SimplePost struct {
	Id     int    `json:"id"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	UserId int    `json:"userId"`
}

func main() {
	// backendPrivate, backendPublic, err := GenerateKeyPair()
	// if err != nil {
	// 	fmt.Println("Error generating backend keys:", err)
	// 	return
	// }

	// // The backend server starts an HTTP server to exchange public keys and messages
	// http.HandleFunc("/publicKey", func(w http.ResponseWriter, r *http.Request) {
	// 	// Send the backend server's public key to the frontend server
	// 	fmt.Fprint(w, hex.EncodeToString(backendPublic))
	// })

	// http.HandleFunc("/message", func(w http.ResponseWriter, r *http.Request) {
	// 	randomData := getRandomData()
	// 	stringData := toString(randomData)

	// 	text := []byte(stringData)
	// 	// randomData.(string)

	// 	// Receive the frontend server's public key
	// 	publicKey := r.URL.Query().Get("publicKey")
	// 	// Remove any double quotes from the string
	// 	publicKey = strings.ReplaceAll(publicKey, "\"", "")
	// 	frontendPublic, err := hex.DecodeString(publicKey)
	// 	if err != nil {
	// 		fmt.Println("Error decoding frontend public key:", err)
	// 		return
	// 	}

	// 	// Generate the shared secret
	// 	sharedSecret, err := GenerateSharedSecret(backendPrivate, frontendPublic)
	// 	if err != nil {
	// 		fmt.Println("Error generating shared secret:", err)
	// 		return
	// 	}
	// 	// Encrypt a message
	// 	message := text
	// 	// fmt.Println(message)

	// 	// newMsg := []byte("Ravi Test message")

	// 	ciphertext, err := encrypt(message, sharedSecret)
	// 	encodedMessage := base64.StdEncoding.EncodeToString(ciphertext)
	// 	if err != nil {
	// 		fmt.Println("Error encrypting message:", err)
	// 		return
	// 	}

	// 	// Start the server and send the encrypted message to the frontend server
	// 	// startServer(ciphertext)

	// 	fmt.Fprintf(w, "%v", encodedMessage)
	// })

	// Create a new CORS handler
	http.HandleFunc("/post-ur-hash", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		r_bs, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Println(err.Error())
		}

		var mySimplePost SimplePost
		if json.Unmarshal(r_bs, &mySimplePost); err != nil {
			fmt.Println(err.Error())
		}

		originalHash := sha256.Sum256([]byte(mySimplePost.Title))
		originalText := string(originalHash[:])

		fmt.Println("Coming data: ", string(originalText))

		// Simple echo
		io.Copy(w, r.Body)
	})

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:8080"},         // Allow the frontend server to access the backend server
		AllowedMethods:   []string{"GET", "POST", "PUT", "OPTIONS"}, // Allow these HTTP methods
		AllowedHeaders:   []string{"Accept", "content-type"},        // Allow these HTTP headers
		AllowCredentials: true,                                      // Allow cookies
	})
	handler := c.Handler(http.DefaultServeMux)

	// resp, err := http.Get("http://localhost:8080/post-ur-hash")
	// if err != nil {
	// 	return
	// }
	// defer resp.Body.Close()

	// r_bs, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }

	// var mySimplePost SimplePost
	// if json.Unmarshal(r_bs, &mySimplePost); err != nil {
	// 	fmt.Println(err.Error())
	// }

	// response_BS, err := ioutil.ReadAll(resp.Body)
	// fmt.Println("I should be a successful ping...", string(response_BS))

	// The frontend server sends its public key to the backend server and receives the backend server's public key
	// resp, err := http.Get("/publicKey")
	// if err != nil {
	// 	fmt.Println("Error getting backend public key:", err)
	// 	return
	// }
	// Here, we first check if resp is not nil.
// 	if resp != nil {
// 		// We also check if resp.Body is not nil before closing it.
// 		if resp.Body != nil {
// 			defer resp.Body.Close()
// 		}
// 		// Checking the HTTP status code
// 		if resp.StatusCode != http.StatusOK {
// 			fmt.Println("Server returned non-OK status: ", resp.Status)
// 		}
// 	} else {
// 		fmt.Println("Response is nil")
// 		return
// 	}

// 	backendPublic, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		fmt.Println("Error reading backend public key:", err)
// 		return
// 	}

// 	bytesPublicKey, err := hex.DecodeString(string(backendPublic))
// 	if err != nil {
// 		panic(err)
// 	}

// 	// The frontend server generates the shared secret
// 	sharedSecret, err := GenerateSharedSecret(frontendPrivate, bytesPublicKey)
// 	if err != nil {
// 		fmt.Println("Error generating shared secret:", err)
// 		return
// 	}

// 	// The frontend server sends its public key to the backend server and receives an encrypted message
// 	resp, err = http.Get("/message?publicKey=" + hex.EncodeToString(frontendPublic))
// 	if err != nil {
// 		fmt.Println("Error getting message:", err)
// 		return
// 	}
// 	// Duplicate the resp and resp.Body null checks for the second http.Get
// 	if resp != nil {
// 		if resp.Body != nil {
// 			defer resp.Body.Close()
// 		}
// 		// Checking the HTTP status code
// 		if resp.StatusCode != http.StatusOK {
// 			fmt.Println("Server returned non-OK status: ", resp.Status)
// 		}
// 	} else {
// 		fmt.Println("Response is nil1")
// 		return
// 	}
// 	defer resp.Body.Close()

// 	ciphertext, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		fmt.Println("Error reading message:", err)
// 		return
// 	}

// 	decodedMessage := make([]byte, base64.StdEncoding.DecodedLen(len(ciphertext)))
// 	_, err = base64.StdEncoding.Decode(decodedMessage, ciphertext)

// 	decodedMessage = bytes.Trim(decodedMessage, "\x00")
// 	if len(decodedMessage) == 0 {
// 		fmt.Println("Error: Decoded message is empty after trimming")
// 		return
// 	}

// 	plaintext, err := decrypt(decodedMessage, sharedSecret)
// 	fmt.Println("PLAINTEXT:", plaintext)
// 	if err != nil {
// 		fmt.Println("Error decrypting message:", err)
// 		return
// 	}
	
	http.ListenAndServe(":9091", handler)
}

func getDatafromFront() {
	resp, err := http.Get("http://localhost:8080/post-ur-hash")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	r_bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err.Error())
	}

	var mySimplePost SimplePost
	if json.Unmarshal(r_bs, &mySimplePost); err != nil {
		fmt.Println(err.Error())
	}

	response_BS, err := ioutil.ReadAll(resp.Body)
	fmt.Println("I should be a successful ping...", string(response_BS))
}

// func handleIncomingData(w http.ResponseWriter, r *http.Request) {
// 	// Read the incoming data from the request body
// 	body, err := ioutil.ReadAll(r.Body)
// 	if err != nil {
// 		http.Error(w, "Failed to read request body", http.StatusBadRequest)
// 		return
// 	}

// 	// Parse the JSON data into a struct
// 	var data IncomingData
// 	err = json.Unmarshal(body, &data)
// 	if err != nil {
// 		http.Error(w, "Failed to parse JSON data", http.StatusBadRequest)
// 		return
// 	}

// 	// Print the incoming data
// 	fmt.Println("Incoming data:", data)

// 	// Optionally, you can send a response back to the frontserver
// 	// For example, you can use w.Write() to send a simple response
// 	// Or you can use w.WriteHeader() and w.Write() to send a custom response with a status code
// }

// func getRandomData() interface{} {
// 	mathRand.Seed(time.Now().UnixNano())
// 	return data[mathRand.Intn(len(data))]
// }

// func toString(i interface{}) string {
// 	str := fmt.Sprintf("%v", i)
// 	// str, ok := i.(string)
// 	// str, ok := i.(string); if ok != true {
// 	// 	fmt.Println("OK:", ok)
// 	// }
// 	return str
// }

// func encrypt(plaintext []byte, key []byte) ([]byte, error) {
// 	// Validate key length
// 	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
// 		return nil, fmt.Errorf("crypto/aes: invalid key size %d, want: 16, 24 or 32", len(key))
// 	}

// 	cipherBlock, err := aes.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}

// 	gcm, err := cipher.NewGCM(cipherBlock)
// 	if err != nil {
// 		return nil, err
// 	}

// 	nonce := make([]byte, gcm.NonceSize())
// 	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
// 		return nil, err
// 	}

// 	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

// 	return ciphertext, nil
// }

// func decrypt(ciphertext []byte, key []byte) (string, error) {
// 	c, err := aes.NewCipher(key)
// 	if err != nil {
// 		return "error: ", err
// 	}

// 	gcm, err := cipher.NewGCM(c)
// 	if err != nil {
// 		return "error: ", err
// 	}

// 	nonceSize := gcm.NonceSize()
// 	if len(ciphertext) < nonceSize { //length of ciphertext
// 		return "error: ", errors.New("ciphertext too short")
// 	}

// 	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
// 	byteText, err := gcm.Open(nil, nonce, ciphertext, nil)

// 	return string(byteText), err
// }

// GenerateKeyPair generates a public and private key pair.
// func GenerateKeyPair() ([]byte, []byte, error) {
// 	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("failed to marshal private key: %v", err)
// 	}

// 	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("failed to marshal public key: %v", err)
// 	}

// 	return privateBytes, publicBytes, nil
// }

// GenerateSharedSecret generates a shared secret from own private key and other party's public key.
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
