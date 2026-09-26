package grpcserver

import (
	"context"
	"regexp"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"frost-k8s-threshold-signing/internal/coordinator"
)

// Headers nginx adds to every proxied request (deploy/nginx-grpc.conf, NOTES N64).
const (
	HeaderNginxRequestID = "x-frost-nginx-request-id" // nginx $request_id
	HeaderNginxMsec      = "x-frost-nginx-msec"       // nginx $msec when proxying
)

var (
	reNginxID   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reNginxMsec = regexp.MustCompile(`^[0-9]{10}\.[0-9]{3}$`)
)

// TimingInterceptor records when a unary request reached this process, the
// caller's remaining gRPC deadline and the nginx timing headers, and attaches
// them for the coordinator's log lines (NOTES N64). The values are only
// logged: they never influence signing, and malformed headers are ignored.
func TimingInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	a := coordinator.Arrival{At: time.Now()}
	if d, ok := ctx.Deadline(); ok {
		a.IncomingDeadline = time.Until(d)
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(HeaderNginxRequestID); len(v) == 1 && reNginxID.MatchString(v[0]) {
			a.NginxRequestID = v[0]
		}
		if v := md.Get(HeaderNginxMsec); len(v) == 1 && reNginxMsec.MatchString(v[0]) {
			if sec, err := strconv.ParseInt(v[0][:10], 10, 64); err == nil {
				msec, _ := strconv.Atoi(v[0][11:])
				a.NginxProxyAt = time.Unix(sec, int64(msec)*int64(time.Millisecond))
			}
		}
	}
	return h(coordinator.WithArrival(ctx, a), req)
}
