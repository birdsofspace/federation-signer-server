package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/storyicon/sigverify"
	"golang.org/x/crypto/sha3"
)

type SignRequest struct {
	Message    string `json:"message"`
	PrivateKey string `json:"private_key"`
}

type SignResponse struct {
	Signature string `json:"signature"`
	Error     string `json:"error,omitempty"`
}

type ErrorResponse struct {
	Success bool   `json:"success"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type PendingResponse struct {
	Success       bool      `json:"success"`
	Code          int       `json:"code"`
	Status        string    `json:"status"`
	RequestAt     time.Time `json:"request_at"`
	User          string    `json:"user"`
	SourceChainID int       `json:"source_chain_id"`
	TargetChainID int       `json:"target_chain_id"`
	Amount        int       `json:"amount"`
}

func main() {
	var port int
	var host string
	flag.IntVar(&port, "port", 8080, "Port number to listen on")
	flag.StringVar(&host, "host", "0.0.0.0", "Host address to listen on")
	flag.Parse()

	http.HandleFunc("/sign", handleSign)
	http.HandleFunc("/ws", handleWebSocket)
	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("Server started on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	_ = godotenv.Load()
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	for {
		userSign := r.Header.Get("user-sign")
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			log.Println(err)
			return
		}

		var data map[string]interface{}
		_ = json.Unmarshal([]byte(message), &data)

		userBridge, ok := data["user_bridge"].(string)
		if !ok {
			_ = conn.WriteMessage(messageType, sendErrorResponse(http.StatusBadRequest, "Bad Request: Must use the JSON key user_bridge."))
		}
		userBridge = strings.Trim(userBridge, " ")
		userBridge = strings.ToLower(userBridge)
		msgHash := crypto.Keccak256Hash([]byte("Request to connect to bridge by user: " + userBridge))

		log.Printf("Received message from: %s", userBridge)

		if validateSignatureByAddress(msgHash, userSign, userBridge) {
			sourceChainIDStr, ok := data["source_chainID"].(string)
			if !ok {
				_ = conn.WriteMessage(messageType, sendErrorResponse(http.StatusBadRequest, "Bad Request: Must use the JSON key source_chainID."))
			}
			sourceChainID, _ := strconv.Atoi(sourceChainIDStr)
			targetChainIDStr, ok := data["target_chainID"].(string)
			if !ok {
				_ = conn.WriteMessage(messageType, sendErrorResponse(http.StatusBadRequest, "Bad Request: Must use the JSON key target_chainID."))
			}
			targetChainID, _ := strconv.Atoi(targetChainIDStr)
			requestAtStr, ok := data["request_at"].(string)
			if !ok {
				_ = conn.WriteMessage(messageType, sendErrorResponse(http.StatusBadRequest, "Bad Request: Must use the JSON key request_at."))
			}
			requestAt, _ := strconv.Atoi(requestAtStr)
			amountStr, ok := data["amount"].(string)
			if !ok {
				_ = conn.WriteMessage(messageType, sendErrorResponse(http.StatusBadRequest, "Bad Request: Must use the JSON key amount."))
			}
			amount, _ := strconv.Atoi(amountStr)

			selectedContract := ""
			if sourceChainID == 8453 {
				selectedContract = os.Getenv("BASE_BRIDGE_CONTRACT_ADDRESS")
			} else if sourceChainID == 137 {
				selectedContract = os.Getenv("POLYGON_BRIDGE_CONTRACT_ADDRESS")
			} else if sourceChainID == 158 {
				selectedContract = os.Getenv("ROBURNA_BRIDGE_CONTRACT_ADDRESS")
			} else {
				return
			}

			bridgeAddress := common.HexToAddress(selectedContract)
			requestFnSignature := []byte("checkInputRequest(address,uint256)")
			hash := sha3.NewLegacyKeccak256()
			hash.Write(requestFnSignature)
			methodID := hash.Sum(nil)[:4]

			outputBalance := 0
			if outputBalance < amount {
				_ = conn.WriteMessage(messageType, sendPendingResponse(time.Unix(int64(requestAt), 0), userBridge, sourceChainID, targetChainID, amount))
			} else {

			}

			err = conn.WriteMessage(messageType, message)
			if err != nil {
				log.Println(err)
				return
			}
			log.Printf("Sent message: %s", message)
		}

	}
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

func validateSignatureByAddress(msgHash common.Hash, userSign string, publicKey string) bool {
	signature, _ := hexutil.Decode(userSign)
	address, _ := sigverify.EcRecoverEx(msgHash.Bytes(), signature)
	log.Print(address)
	matches := strings.ToLower(address.String()) == publicKey
	return matches
}

func sendErrorResponse(code int, message string) []byte {
	errorResponse := ErrorResponse{
		Success: false,
		Code:    code,
		Message: message,
	}
	errorResponseJsonString, _ := json.Marshal(errorResponse)
	return errorResponseJsonString
}

func sendPendingResponse(requestAt time.Time, user string, sourceChainID int, targetChainID int, amount int) []byte {
	errorResponse := PendingResponse{
		Success:       false,
		Code:          http.StatusNotAcceptable,
		Status:        "pending",
		RequestAt:     requestAt,
		User:          user,
		SourceChainID: sourceChainID,
		TargetChainID: targetChainID,
		Amount:        amount,
	}
	errorResponseJsonString, _ := json.Marshal(errorResponse)
	return errorResponseJsonString
}
