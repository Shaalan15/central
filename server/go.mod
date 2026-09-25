module github.com/Shaalan15/central/server

go 1.27.1

require (
	connectrpc.com/connect v1.21.0
	github.com/BurntSushi/toml v1.6.0
	github.com/Shaalan15/central/gen/go v0.0.0
	github.com/google/uuid v1.6.0
	golang.org/x/crypto v0.57.0
	golang.org/x/time v0.16.0
)

require (
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/Shaalan15/central/gen/go => ../gen/go
