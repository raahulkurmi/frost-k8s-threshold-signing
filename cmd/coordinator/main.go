package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/bytemare/frost"

	"frost-k8s-threshold-signing/internal/api"
	"frost-k8s-threshold-signing/internal/coordinatorstate"
	"encoding/base64"
)

var signerPorts = []string{
	"8081",
	"8082",
	"8083",
}

type ThresholdSignResponse struct {
	Message       string                         `json:"message"`
	Commitments  []api.CommitmentResponse       `json:"commitments"`
	Signatures   []api.SignatureShareResponse   `json:"signatures"`
	FinalSigHex  string                         `json:"final_signature"`
}

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

func collectCommitments() (
	api.CommitmentCollection,
	error,
) {

	var result api.CommitmentCollection

	for _, port := range signerPorts {

		resp, err := http.Post(
			"http://localhost:"+port+"/commit",
			"application/json",
			nil,
		)

		if err != nil {
			return result, err
		}

		var commitment api.CommitmentResponse

		if err := json.NewDecoder(
			resp.Body,
		).Decode(&commitment); err != nil {

			resp.Body.Close()
			return result, err
		}

		resp.Body.Close()

		result.Commitments = append(
			result.Commitments,
			commitment,
		)
	}

	return result, nil
}

func collectCommitmentHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	result, err := collectCommitments()

	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	json.NewEncoder(w).Encode(
		result,
	)
}

func collectSignaturesWithCommitments(
	message string,
	commitments []api.CommitmentResponse,
) (
	api.SignatureCollection,
	error,
) {

	var result api.SignatureCollection

	req := api.SignRequest{
		Message:     message,
		Commitments: commitments,
	}

	body, err := json.Marshal(req)

	if err != nil {
		return result, err
	}

	for _, port := range signerPorts {

		resp, err := http.Post(
			"http://localhost:"+port+"/sign",
			"application/json",
			bytes.NewReader(body),
		)

		if err != nil {
			return result, err
		}

		var share api.SignatureShareResponse

		if err := json.NewDecoder(
			resp.Body,
		).Decode(&share); err != nil {

			resp.Body.Close()
			return result, err
		}

		resp.Body.Close()

		result.Signatures = append(
			result.Signatures,
			share,
		)
	}

	return result, nil
}

func collectSignaturesHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	message := "hello-frost-threshold-signing"

	commitments, err := collectCommitments()

	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	signatures, err := collectSignaturesWithCommitments(
		message,
		commitments.Commitments,
	)

	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	json.NewEncoder(w).Encode(
		signatures,
	)
}

func encodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func thresholdSignHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	message := "hello-frost-threshold-signing"

	commitmentCollection, err := collectCommitments()

	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	signatureCollection, err := collectSignaturesWithCommitments(
		message,
		commitmentCollection.Commitments,
	)

	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	var commitmentList frost.CommitmentList

	for _, item := range commitmentCollection.Commitments {

		commitment := &frost.Commitment{}

		if err := commitment.DecodeHex(
			item.Commitment,
		); err != nil {

			http.Error(
				w,
				err.Error(),
				http.StatusInternalServerError,
			)
			return
		}

		commitmentList = append(
			commitmentList,
			commitment,
		)
	}

	commitmentList.Sort()

	var signatureShares []*frost.SignatureShare

	for _, item := range signatureCollection.Signatures {

		share := &frost.SignatureShare{}

		if err := share.DecodeHex(
			item.Share,
		); err != nil {

			http.Error(
				w,
				err.Error(),
				http.StatusInternalServerError,
			)
			return
		}

		signatureShares = append(
			signatureShares,
			share,
		)
	}

	finalSignature, err := coordinatorstate.Config.AggregateSignatures(
		[]byte(message),
		signatureShares,
		commitmentList,
		true,
	)

	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	resp := ThresholdSignResponse{
		Message:      message,
		Commitments: commitmentCollection.Commitments,
		Signatures:  signatureCollection.Signatures,
		FinalSigHex: finalSignature.Hex(),
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	json.NewEncoder(w).Encode(resp)
}


func thresholdJWTHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	headerJSON := []byte(`{"alg":"FROST-RISTRETTO255-SHA512","typ":"JWT"}`)

	payloadJSON := []byte(`{
		"iss":"kubernetes/serviceaccount",
		"sub":"system:serviceaccount:default:demo-sa",
		"aud":["https://kubernetes.default.svc"],
		"namespace":"default",
		"serviceaccount":"demo-sa"
	}`)

	header := encodeBase64URL(headerJSON)
	payload := encodeBase64URL(payloadJSON)

	signingInput := header + "." + payload

	commitmentCollection, err := collectCommitments()

	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	signatureCollection, err := collectSignaturesWithCommitments(
		signingInput,
		commitmentCollection.Commitments,
	)

	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	var commitmentList frost.CommitmentList

	for _, item := range commitmentCollection.Commitments {

		commitment := &frost.Commitment{}

		if err := commitment.DecodeHex(
			item.Commitment,
		); err != nil {
			http.Error(
				w,
				err.Error(),
				http.StatusInternalServerError,
			)
			return
		}

		commitmentList = append(
			commitmentList,
			commitment,
		)
	}

	commitmentList.Sort()

	var signatureShares []*frost.SignatureShare

	for _, item := range signatureCollection.Signatures {

		share := &frost.SignatureShare{}

		if err := share.DecodeHex(
			item.Share,
		); err != nil {
			http.Error(
				w,
				err.Error(),
				http.StatusInternalServerError,
			)
			return
		}

		signatureShares = append(
			signatureShares,
			share,
		)
	}

	finalSignature, err := coordinatorstate.Config.AggregateSignatures(
		[]byte(signingInput),
		signatureShares,
		commitmentList,
		true,
	)

	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	signature := encodeBase64URL(
		[]byte(finalSignature.Hex()),
	)

	token := signingInput + "." + signature

	resp := api.ThresholdJWTResponse{
		Header:       header,
		Payload:      payload,
		SigningInput: signingInput,
		Signature:    signature,
		Token:        token,
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	json.NewEncoder(w).Encode(resp)
}


func main() {

	if err := coordinatorstate.Init(); err != nil {
		panic(err)
	}

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

	http.HandleFunc(
		"/collect-signatures",
		collectSignaturesHandler,
	)

	http.HandleFunc(
		"/threshold-sign",
		thresholdSignHandler,
	)
http.HandleFunc(
	"/threshold-jwt",
	thresholdJWTHandler,
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