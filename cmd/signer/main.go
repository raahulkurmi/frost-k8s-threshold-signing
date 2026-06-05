package main

import (
	"fmt"
	"net/http"
	 "encoding/json"

    "frost-k8s-threshold-signing/internal/api"
	"frost-k8s-threshold-signing/internal/froststate"
	"frost-k8s-threshold-signing/internal/config"
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

commitment := froststate.Signer.Commit()

resp := api.CommitmentResponse{
	CommitmentID: commitment.CommitmentID,
	SignerID:     commitment.SignerID,
	Commitment:   commitment.Hex(),
}
	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	json.NewEncoder(w).Encode(resp)
}

func main() {



	if err := froststate.Init(); err != nil {
		panic(err)
	}
	http.HandleFunc(
		"/health",
		healthHandler,
	)
	http.HandleFunc(
	"/commit",
	commitHandler,
)

	port := config.Port()

fmt.Printf(
	"Signer listening on :%s\n",
	port,
)

if err := http.ListenAndServe(
	":"+port,
	nil,
); err != nil {
	panic(err)
}
}