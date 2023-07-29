package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

type SimplePost struct {
	Id     int    `json:"id"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	UserId int    `json:"userId"`
}

func main() {
	fs := http.FileServer(http.Dir("go-wasm/assets"))
	http.Handle("/", corsMiddleware(fs))

	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("/ping API endpoint hit.")
		io.Copy(w, bytes.NewReader([]byte("Successfully pinged. Keep moving.")))
	})

	http.HandleFunc("/post-ur-hash", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("/post-ur-hash API endpoint hit.")

		defer r.Body.Close()

		r_bs, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Println(err.Error())
		}

		var mySimplePost SimplePost
		if json.Unmarshal(r_bs, &mySimplePost); err != nil {
			fmt.Println(err.Error())
		}
		fmt.Println("yay? :", mySimplePost.Body)

		// Simple echo
		io.Copy(w, r.Body)
	})

	log.Println("Listening on http://localhost:8080/index.html")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}

// First server is running on :9090
// Second server is running on :9091
// Front sever is running on :8080

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		next.ServeHTTP(w, r)
	})
}
