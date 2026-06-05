package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"frost-k8s-threshold-signing/internal/api"
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

func collectCommitmentHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	ports := []string{
		"8081",
		"8082",
		"8083",
	}

	var result api.CommitmentCollection

	for _, port := range ports {

		resp, err := http.Post(
			"http://localhost:"+port+"/commit",
			"application/json",
			nil,
		)

		if err != nil {
			http.Error(
				w,
				err.Error(),
				http.StatusInternalServerError,
			)
			return
		}

		var commitment api.CommitmentResponse

		if err := json.NewDecoder(
			resp.Body,
		).Decode(&commitment); err != nil {

			resp.Body.Close()

			http.Error(
				w,
				err.Error(),
				http.StatusInternalServerError,
			)
			return
		}

		resp.Body.Close()

		result.Commitments = append(
			result.Commitments,
			commitment,
		)
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	json.NewEncoder(w).Encode(
		result,
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

	http.HandleFunc(
		"/collect-commitment",
		collectCommitmentHandler,
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