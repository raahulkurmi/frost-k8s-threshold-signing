package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bytemare/frost"

	"frost-k8s-threshold-signing/internal/api"
	"frost-k8s-threshold-signing/internal/config"
	"frost-k8s-threshold-signing/internal/froststate"
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

	froststate.Commitments[
		commitment.CommitmentID,
	] = commitment

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

func signHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	var req api.SignRequest

	if err := json.NewDecoder(
		r.Body,
	).Decode(&req); err != nil {

		http.Error(
			w,
			err.Error(),
			http.StatusBadRequest,
		)
		return
	}

	var commitments frost.CommitmentList

	for _, item := range req.Commitments {

		commitment := &frost.Commitment{}

		if err := commitment.DecodeHex(
			item.Commitment,
		); err != nil {

			http.Error(
				w,
				err.Error(),
				http.StatusBadRequest,
			)
			return
		}

		commitments = append(
			commitments,
			commitment,
		)
	}

	commitments.Sort()

	sigShare, err := froststate.Signer.Sign(
		[]byte(req.Message),
		commitments,
	)

	if err != nil {

		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	resp := api.SignatureShareResponse{
		SignerID: sigShare.SignerIdentifier,
		Share:    sigShare.Hex(),
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

	http.HandleFunc(
		"/sign",
		signHandler,
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