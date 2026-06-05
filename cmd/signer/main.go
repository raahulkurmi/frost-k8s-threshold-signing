package main

import (
	"fmt"
	"net/http"
)

func healthHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	fmt.Fprintf(
		w,
		"signer alive",
	)
}

func main() {

	http.HandleFunc(
		"/health",
		healthHandler,
	)

	fmt.Println(
		"Signer listening on :8081",
	)

	if err := http.ListenAndServe(
		":8081",
		nil,
	); err != nil {
		panic(err)
	}
}