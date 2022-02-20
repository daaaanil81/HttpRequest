package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {

	fmt.Println("Start simple http server :8080")

	helloHandler := func(w http.ResponseWriter, req *http.Request) {
		fmt.Println("Connected " + req.RemoteAddr)
		io.WriteString(w, "Connected "+req.RemoteAddr+"\n")
	}

	http.HandleFunc("/", helloHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
