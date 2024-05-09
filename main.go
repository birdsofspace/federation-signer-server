package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type SignRequest struct {
	Message    string `json:"message"`
	PrivateKey string `json:"private_key"`
}

type SignResponse struct {
	Signature string `json:"signature"`
	Error     string `json:"error,omitempty"`
}

func main() {
	var port int
	var host string
	flag.IntVar(&port, "port", 8080, "Port number to listen on")
	flag.StringVar(&host, "host", "0.0.0.0", "Host address to listen on")
	flag.Parse()

	http.HandleFunc("/sign", handleSign)
	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("Server started on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SignRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid JSON request", http.StatusBadRequest)
		return
	}

	if req.Message == "" || req.PrivateKey == "" {
		http.Error(w, "Message and private key are required", http.StatusBadRequest)
		return
	}
	log.Print(req)

	privateKey, err := hex.DecodeString(strings.TrimPrefix(req.PrivateKey, "0x"))
	if err != nil {
		http.Error(w, "Invalid private key format", http.StatusBadRequest)
		return
	}

	key, err := crypto.ToECDSA(privateKey)
	if err != nil {
		http.Error(w, "Invalid private key", http.StatusBadRequest)
		return
	}

	signature, err := FeederationSign(req.Message, key)
	if err != nil {
		http.Error(w, "Error signing message", http.StatusInternalServerError)
		return
	}

	resp := SignResponse{
		Signature: signature,
	}
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResp)
}

func FeederationSign(message string, privateKey *ecdsa.PrivateKey) (string, error) {
	fullMessage := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := crypto.Keccak256Hash([]byte(fullMessage))
	signatureBytes, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return "", err
	}
	signatureBytes[64] += 27
	return hexutil.Encode(signatureBytes), nil
}
