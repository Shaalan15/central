module github.com/Shaalan15/central/server

go 1.27.1

require (
	connectrpc.com/connect v1.21.0
	github.com/BurntSushi/toml v1.6.0
	github.com/Shaalan15/central/gen/go v0.0.0
	github.com/appwrite/sdk-for-go/v7 v7.4.0
	github.com/coder/websocket v1.8.15
	github.com/go-webauthn/webauthn v0.18.2
	github.com/google/uuid v1.6.0
	github.com/pquerna/otp v1.5.0
	golang.org/x/crypto v0.57.0
	golang.org/x/time v0.16.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

replace github.com/Shaalan15/central/gen/go => ../gen/go
