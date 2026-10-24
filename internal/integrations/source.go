package integrations

import (
	"context"

	"github.com/SantanaCharles/sentinels/internal/event"
)

// Source streams detections from an external engine until ctx ends.
type Source interface {
	Name() string
	Run(ctx context.Context, out chan<- event.Event) error
}

// send delivers e unless ctx is done.
func send(ctx context.Context, out chan<- event.Event, e event.Event) bool {
	select {
	case out <- e:
		return true
	case <-ctx.Done():
		return false
	}
}
