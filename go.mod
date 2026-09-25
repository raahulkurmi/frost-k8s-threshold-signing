module frost-k8s-threshold-signing

go 1.27.1

require (
	github.com/go-jose/go-jose/v4 v4.1.5
	github.com/niclabs/tcrsa v0.0.5 // pinned exactly: later versions change the license (NOTES.md N6); never upgrade
	golang.org/x/time v0.16.0
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af
	gopkg.in/go-jose/go-jose.v2 v2.6.3
	k8s.io/externaljwt v0.36.5
)

require (
	github.com/stretchr/testify v1.12.1 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
)
