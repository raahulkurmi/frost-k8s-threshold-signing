package grpcserver

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"frost-k8s-threshold-signing/internal/coordinator"
)

// TimingInterceptor (N64) attaches arrival time, the caller's deadline and the
// nginx headers; malformed headers are ignored (timing only, never trusted).
func TestTimingInterceptor(t *testing.T) {
	run := func(md metadata.MD, deadline time.Duration) coordinator.Arrival {
		ctx := metadata.NewIncomingContext(context.Background(), md)
		if deadline > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, deadline)
			defer cancel()
		}
		var got coordinator.Arrival
		_, err := TimingInterceptor(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, _ any) (any, error) {
			a, ok := coordinator.ArrivalFrom(ctx)
			if !ok {
				t.Fatal("no Arrival in the handler context")
			}
			got = a
			return nil, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	before := time.Now()
	a := run(metadata.Pairs(HeaderNginxRequestID, "0123456789abcdef0123456789abcdef", HeaderNginxMsec, "1790000000.250"), 3*time.Second)
	if a.At.Before(before) || a.NginxRequestID != "0123456789abcdef0123456789abcdef" ||
		!a.NginxProxyAt.Equal(time.Unix(1790000000, 250*int64(time.Millisecond))) ||
		a.IncomingDeadline <= 2*time.Second || a.IncomingDeadline > 3*time.Second {
		t.Fatalf("well-formed headers: %+v", a)
	}
	for _, bad := range []metadata.MD{
		metadata.Pairs(HeaderNginxRequestID, "not-hex", HeaderNginxMsec, "12.5"),
		metadata.Pairs(HeaderNginxRequestID, "0123456789ABCDEF0123456789ABCDEF", HeaderNginxMsec, "1790000000.25x"),
		metadata.Pairs(HeaderNginxRequestID, "0123456789abcdef0123456789abcdef", HeaderNginxRequestID, "0123456789abcdef0123456789abcdef"),
	} {
		if a := run(bad, 0); a.NginxRequestID != "" || !a.NginxProxyAt.IsZero() || a.IncomingDeadline != 0 {
			t.Fatalf("malformed/duplicate headers %v were not ignored: %+v", bad, a)
		}
	}
}
