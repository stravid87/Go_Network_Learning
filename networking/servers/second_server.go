package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"crypto/sha256"
	"net/http"
	"github.com/rs/cors"
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
	http.ListenAndServe(":9091", handler)
}