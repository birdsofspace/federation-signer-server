package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/storyicon/sigverify"
	"golang.org/x/crypto/sha3"
)

type Chain struct {
	ChainID  int    `json:"chain_id"`
	RPC      string `json:"rpc"`
	Explorer string `json:"explorer"`
}

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
	Success       bool   `json:"success"`
	Code          int    `json:"code"`
	Status        string `json:"status"`
	RequestAt     string `json:"request_at"`
	User          string `json:"user"`
	SourceChainID int    `json:"source_chain_id"`
	TargetChainID int    `json:"target_chain_id"`
	Amount        int    `json:"amount"`
}

type SuccessResponse struct {
	Success        bool   `json:"success"`
	Code           int    `json:"code"`
	Status         string `json:"status"`
	UserBridge     string `json:"user_bridge"`
	SourceContract string `json:"source_contract"`
	TargetContract string `json:"target_contract"`
	SourceChainID  int    `json:"source_chainID"`
	TargetChainID  int    `json:"target_chainID"`
	Symbol         string `json:"symbol"`
	Decimal        int    `json:"decimal"`
	Amount         int    `json:"amount"`
	SignAt         string `json:"sign_at"`
	Signature      string `json:"signature"`
}

type SignaturePack struct {
	UserBridge     string `json:"user_bridge"`
	SourceContract string `json:"source_contract"`
	TargetContract string `json:"target_contract"`
	SourceChainID  int    `json:"source_chainID"`
	TargetChainID  int    `json:"target_chainID"`
	Symbol         string `json:"symbol"`
	Decimal        int    `json:"decimal"`
	Amount         int    `json:"amount"`
	SignAt         string `json:"sign_at"`
}

var chains []Chain
var claimedFile *os.File

func main() {
	var port int
	var host string
	flag.IntVar(&port, "port", 8080, "Port number to listen on")
	flag.StringVar(&host, "host", "0.0.0.0", "Host address to listen on")
	flag.Parse()

	chainData, _ := os.ReadFile("chainlist.json")
	_ = json.Unmarshal(chainData, &chains)

	claimedFile, _ = os.OpenFile("claimed.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer claimedFile.Close()

	http.HandleFunc("/sign", handleSign)
	http.HandleFunc("/ws", handleWebSocket)
	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("Server started on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))

}

func getDataByChainID(chainsx []Chain, chainID int) *Chain {
	for _, chain := range chainsx {
		if chain.ChainID == chainID {
			return &chain
		}
	}
	return nil
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
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
		queryParams := r.URL.Query()
		userSign := queryParams.Get("usign")
		// userSign := r.Header.Get("user-sign")
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

			sourceContract, ok := data["source_contract"].(string)
			if !ok {
				_ = conn.WriteMessage(messageType, sendErrorResponse(http.StatusBadRequest, "Bad Request: Must use the JSON key source_contract."))
			}

			targetContract, ok := data["target_contract"].(string)
			if !ok {
				_ = conn.WriteMessage(messageType, sendErrorResponse(http.StatusBadRequest, "Bad Request: Must use the JSON key target_contract."))
			}

			requestAtStr, ok := data["request_at"].(string)
			if !ok {
				_ = conn.WriteMessage(messageType, sendErrorResponse(http.StatusBadRequest, "Bad Request: Must use the JSON key request_at."))
			}

			// requestAt, _ := strconv.Atoi(requestAtStr)
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
			} else if sourceChainID == 4002 {
				selectedContract = os.Getenv("FANTOM_TESTNET_BRIDGE_CONTRACT_ADDRESS")
			} else {
				return
			}

			rpc_url := getDataByChainID(chains, sourceChainID)
			ether_client, _ := ethclient.Dial(rpc_url.RPC)
			bridgeAddress := common.HexToAddress(selectedContract)
			requestFnSignature := []byte("checkRequest(address,uint256)")
			hash := sha3.NewLegacyKeccak256()
			hash.Write(requestFnSignature)
			methodID := hash.Sum(nil)[:4]
			paddedUserBridge := common.LeftPadBytes(common.HexToAddress(userBridge).Bytes(), 32)
			newRequestAt := new(big.Int)
			newRequestAt.SetString(requestAtStr, 10)
			paddedNewRequestAt := common.LeftPadBytes(newRequestAt.Bytes(), 32)
			var dataCall []byte
			dataCall = append(dataCall, methodID...)
			dataCall = append(dataCall, paddedUserBridge...)
			dataCall = append(dataCall, paddedNewRequestAt...)

			outputCheck, _ := ether_client.CallContract(context.Background(), ethereum.CallMsg{
				To:   &bridgeAddress,
				Data: dataCall,
			}, nil)
			outputBalance := int(big.NewInt(0).SetBytes(outputCheck).Uint64())

			if outputBalance < amount {
				_ = conn.WriteMessage(messageType, sendPendingResponse(requestAtStr, userBridge, sourceChainID, targetChainID, amount))
			} else {
				fKeyBytes, _ := hex.DecodeString(strings.TrimPrefix(os.Getenv("FEDERATION_KEY"), "0x"))
				fKey, _ := crypto.ToECDSA(fKeyBytes)

				signaturePack := SignaturePack{
					UserBridge:     userBridge,
					SourceContract: sourceContract,
					TargetContract: targetContract,
					SourceChainID:  sourceChainID,
					TargetChainID:  targetChainID,
					Symbol:         "BOSS",
					Decimal:        18,
					Amount:         amount,
					SignAt:         requestAtStr,
				}
				jsignaturePack, _ := json.Marshal(signaturePack)

				signMaker, _ := FeederationSign(string(jsignaturePack), fKey)
				_ = conn.WriteMessage(messageType, sendSuccessResponse(requestAtStr, userBridge, "BOSS", 18, sourceContract, targetContract, sourceChainID, targetChainID, amount, signMaker))
				_, _ = claimedFile.Write(append(jsignaturePack, '\n'))
			}
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

func sendPendingResponse(requestAt string, user string, sourceChainID int, targetChainID int, amount int) []byte {
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

func sendSuccessResponse(SignAt string, user string, symbol string, decimal int, sourceContract string, targetContract string, sourceChainID int, targetChainID int, amount int, signature string) []byte {
	successResponse := SuccessResponse{
		Success:        true,
		Code:           200,
		Status:         "success",
		UserBridge:     user,
		SourceChainID:  sourceChainID,
		TargetChainID:  targetChainID,
		SourceContract: sourceContract,
		TargetContract: targetContract,
		Symbol:         symbol,
		Decimal:        decimal,
		Amount:         amount,
		SignAt:         SignAt,
		Signature:      signature,
	}
	successResponseJsonString, _ := json.Marshal(successResponse)
	return successResponseJsonString
}
