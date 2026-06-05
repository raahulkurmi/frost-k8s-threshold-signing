package main

import (
	"fmt"
	"io"
	"net/http"
)

func healthHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	fmt.Fprintf(
		w,
		"coordinator alive",
	)
}

func signerHealthHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	resp, err := http.Get(
		"http://localhost:8081/health",
	)

	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	defer resp.Body.Close()

	body, _ := io.ReadAll(
		resp.Body,
	)

	fmt.Fprintf(
		w,
		"Signer Response: %s",
		string(body),
	)
}

func main() {

	http.HandleFunc(
		"/health",
		healthHandler,
	)

	http.HandleFunc(
		"/signer-health",
		signerHealthHandler,
	)

	fmt.Println(
		"Coordinator listening on :8080",
	)

	if err := http.ListenAndServe(
		":8080",
		nil,
	); err != nil {
		panic(err)
	}
}