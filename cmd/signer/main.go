package main

import (
	"fmt"
	"net/http"
	 "encoding/json"

    "frost-k8s-threshold-signing/internal/api"
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


func commitHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	resp := api.CommitmentResponse{
	CommitmentID: 12345,
	SignerID:     1,
	Commitment:   "frost-commitment-placeholder",
}
	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	json.NewEncoder(w).Encode(resp)
}

func main() {

	http.HandleFunc(
		"/health",
		healthHandler,
	)
	http.HandleFunc(
	"/commit",
	commitHandler,
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