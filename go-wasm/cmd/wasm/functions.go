package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"syscall/js"
)

func SayHello(this js.Value, args []js.Value) interface{} {
	resolve_reject_internals := func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		//reject := args[1]
		go func() {
			//reject.Invoke(js.ValueOf(""))
			resolve.Invoke(js.ValueOf("Hello!"))
		}()
		return nil
	}
	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(resolve_reject_internals))
	return promise
}

func PingBackend(this js.Value, args []js.Value) interface{} {
	resolve_reject_internals := func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]
		go func() {
			resp, err := http.Get("http://localhost:8080/ping")
			if err != nil {
				reject.Invoke("Failure to ping backend. Error: ", js.ValueOf(err.Error()))
				return
			}
			if resp == nil || resp.Body == nil || resp.StatusCode != http.StatusOK {
				reject.Invoke(js.ValueOf(fmt.Errorf("500 error from server? ", err.Error())))
				return
			}

			response_BS, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				reject.Invoke(js.ValueOf(fmt.Errorf("Error reading response body: ", err.Error())))
			}
			fmt.Println("I should be a successful ping...")
			resolve.Invoke(js.ValueOf(string(response_BS)))
		}()
		return nil
	}
	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(resolve_reject_internals))
	return promise
}

func HashString(this js.Value, args []js.Value) interface{} {
	jsString := args[0].String()
	resolve_reject_internals := func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]
		go func(jsString string) {
			hash := sha256.New()
			if _, err := hash.Write([]byte(jsString)); err != nil {
				reject.Invoke(js.ValueOf(fmt.Errorf("HashMessage of WASM module failed with error %s", err.Error())))
			}
			str_hex := hex.EncodeToString(hash.Sum(nil))
			resolve.Invoke(js.ValueOf(str_hex))
		}(jsString)
		return nil
	}
	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(resolve_reject_internals))
	return promise
}

func SignString(this js.Value, args []js.Value) interface{} {
	arg0BS := []byte(args[0].String())
	resolve_reject_internals := func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]
		go func(input []byte) {
			hash, err := HashByteSlice(input)
			if err != nil {
				reject.Invoke(js.ValueOf(fmt.Errorf("Error hashing: \"%s\"", err.Error())))
			}
			signatureASN1, err := SignByteSliceASN1(KeyPairS_c.privSK_ptr, hash)
			resolve.Invoke(js.ValueOf(StringToBase64(signatureASN1)))
		}(arg0BS)
		return nil
	}
	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(resolve_reject_internals))
	return promise
}

func SendPost(this js.Value, args []js.Value) interface{} {
	resolve_reject_internals := func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]
		go func() {
			var url = "http://localhost:8080/post-ur-hash"
			simplePost := SimplePost{
				Id:     0,
				Title:  "A Title",
				Body:   "Definitely 'Yay' :)",
				UserId: 99,
			}
			simplePost_bs, err := json.Marshal(simplePost)
			if err != nil {
				fmt.Errorf("Error on POST to %s: %s", url, err.Error())
				reject.Invoke(js.ValueOf("Failure on Post"))
			}

			resp, err := http.Post(url, "Content-Type:application/json", bytes.NewReader(simplePost_bs))
			if err != nil {
				fmt.Errorf("Error on POST to %s: %s", url, err.Error())
				reject.Invoke(js.ValueOf("Failure on Post"))
			}

			defer resp.Body.Close()

			response_BS, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				reject.Invoke(js.ValueOf(fmt.Errorf("Error reading response body: ", err.Error())))
			}

			resolve.Invoke(js.ValueOf(fmt.Sprintf("I got << %s >> in response to sendPost.", string(response_BS))))
		}()
		return nil
	}
	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(resolve_reject_internals))
	return promise
}

// js.Global().Set("getEncryptedData", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
// 	promiseConstructor := js.Global().Get("Promise")
// 	promise := promiseConstructor.New(js.FuncOf(func(this js.Value, args []js.Value) interface{} {
// 		resolve := args[0]
// 		reject := args[1]
// 		go func() {

// 			// Frontend client generates its keys
// 			if err := GenerateKeyPair(); err != nil {
// 				fmt.Println("Error generating frontend keys:", err)
// 				reject.Invoke(js.ValueOf(err.Error()))
// 				return
// 			}

// 			// The frontend server sends its public key to the backend server and receives the backend server's public key
// 			resp, err := http.Get("http://localhost:9091/publicKey")
// 			if err != nil {
// 				fmt.Println("Error getting backend public key:", err)
// 				reject.Invoke(js.ValueOf(err.Error()))
// 				return
// 			}
// 			// Here, we first check if resp is not nil.
// 			if resp != nil {
// 				// We also check if resp.Body is not nil before closing it.
// 				if resp.Body != nil {
// 					defer resp.Body.Close()
// 				}
// 				// Checking the HTTP status code
// 				if resp.StatusCode != http.StatusOK {
// 					fmt.Println("Server returned non-OK status: ", resp.Status)
// 				}
// 			} else {
// 				fmt.Println("Response is nil")
// 				reject.Invoke(js.ValueOf("Response is nil"))
// 				return
// 			}

// 			backendPublic, err := ioutil.ReadAll(resp.Body)
// 			if err != nil {
// 				fmt.Println("Error reading backend public key:", err)
// 				reject.Invoke(js.ValueOf(err.Error()))
// 				return
// 			}

// 			bytesPublicKey, err := hex.DecodeString(string(backendPublic))
// 			if err != nil {
// 				panic(err)
// 			}

// 			// The frontend server generates the shared secret
// 			sharedSecret, err := GenerateSharedSecret(frontendPrivate, bytesPublicKey)
// 			if err != nil {
// 				fmt.Println("Error generating shared secret:", err)
// 				reject.Invoke(js.ValueOf(err.Error()))
// 				return
// 			}

// 			// The frontend server sends its public key to the backend server and receives an encrypted message
// 			resp, err = http.Get("http://localhost:9091/message?publicKey=" + hex.EncodeToString(frontendPublic))
// 			if err != nil {
// 				fmt.Println("Error getting message:", err)
// 				reject.Invoke(js.ValueOf(err.Error()))
// 				return
// 			}
// 			// Duplicate the resp and resp.Body null checks for the second http.Get
// 			if resp != nil {
// 				if resp.Body != nil {
// 					defer resp.Body.Close()
// 				}
// 				// Checking the HTTP status code
// 				if resp.StatusCode != http.StatusOK {
// 					fmt.Println("Server returned non-OK status: ", resp.Status)
// 				}
// 			} else {
// 				fmt.Println("Response is nil1")
// 				reject.Invoke(js.ValueOf("Response is nil1"))
// 				return
// 			}
// 			defer resp.Body.Close()

// 			ciphertext, err := ioutil.ReadAll(resp.Body)
// 			if err != nil {
// 				fmt.Println("Error reading message:", err)
// 				reject.Invoke(js.ValueOf(err.Error()))
// 				return
// 			}

// 			decodedMessage := make([]byte, base64.StdEncoding.DecodedLen(len(ciphertext)))
// 			_, err = base64.StdEncoding.Decode(decodedMessage, ciphertext)

// 			decodedMessage = bytes.Trim(decodedMessage, "\x00")
// 			if len(decodedMessage) == 0 {
// 				fmt.Println("Error: Decoded message is empty after trimming")
// 				reject.Invoke(js.ValueOf("Decoded message is empty after trimming"))
// 				return
// 			}

// 			plaintext, err := decrypt(decodedMessage, sharedSecret)
// 			fmt.Println("PLAINTEXT:", plaintext)
// 			if err != nil {
// 				fmt.Println("Error decrypting message:", err)
// 				reject.Invoke(js.ValueOf(err.Error()))
// 				return
// 			}

// 			resolve.Invoke(string(plaintext))
// 		}()
// 		return nil
// 	}))

// 	return promise
// }))

// js.Global().Set("publicKey", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
// 	backendPrivate, backendPublic, err := GenerateKeyPair()
// 	fmt.Println(backendPrivate)
// 	if err != nil {
// 		fmt.Println("Error generating backend keys:", err)
// 		return nil
// 	}

// 	type keyPair [][]byte
// 	var keysToReturn keyPair
// 	keysToReturn = append(keysToReturn, backendPrivate)
// 	keysToReturn = append(keysToReturn, backendPublic)

// 	return keysToReturn
// }))

// js.Global().Set("privateKey", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
// 	backendPrivate, backendPublic, err := GenerateKeyPair()
// 	fmt.Println(backendPublic)
// 	if err != nil {
// 		fmt.Println("Error generating backend keys:", err)
// 		return nil
// 	}
// 	return backendPrivate
// }))

// js.Global().Set("encrypted", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
// 	message := args[0].String()
// 	publicKey := args[1].String()
// 	backendPrivates := args[2].String()

// 	backendPrivate := []byte(backendPrivates)
// 	text := []byte(message)
// 	frontendPublic, err := hex.DecodeString(publicKey)
// 	if err != nil {
// 		fmt.Println("Error decoding frontend public key:", err)
// 		return nil
//
// 	// Generate the shared secret
// 	sharedSecret, err := GenerateSharedSecret(backendPrivate, frontendPublic)
// 	if err != nil {
// 		fmt.Println("Error generating shared secret:", err)
// 		return nil
// 	}

// 	ciphertext, err := encrypt(text, sharedSecret)
// 	encodedMessage := base64.StdEncoding.EncodeToString(ciphertext)
// 	if err != nil {
// 		fmt.Println("Error encrypting message:", err)
// 		return nil
// 	}

// 	return encodedMessage
// }))
