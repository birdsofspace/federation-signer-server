# Federation Signer Server

This server is used for signing federation messages using Ethereum private keys.

## Installation

1. Make sure you have Golang installed on your computer.
2. Clone this repository to your local directory.
3. Open a terminal, navigate to the repository directory, and run the command:
   ```
   go run main.go -port 8081 -host 0.0.0.0
   ```
4. The server will start running at http://localhost:8081 by default.

## Usage

### Endpoint

- `POST /sign`: Endpoint for signing messages using Ethereum private keys.

### Request

Requests to the `/sign` endpoint should be in JSON format with the following structure:

```json
{
  "message": "Message to be signed",
  "private_key": "0x123456789abcdef" 
}
```

- `message`: The message to be signed.
- `private_key`: The Ethereum private key in hexadecimal format (without the "0x" prefix).

### Example Usage with cURL

```bash
curl -X POST -H "Content-Type: application/json" -d '{"message": "Hello, world!", "private_key": "0x123456789abcdef"}' http://localhost:8080/sign
```
```bash
{"signature":"0x75be0c821115f946f02d35e8059988d76c407eaad5acf8e3e312f7f311f2032f5c8803168a338176412ec8ca3fde4cc10cb6c180c24ec125e0746e144fa482151c"}
```

## License

This project is licensed under the [MIT License](LICENSE).
