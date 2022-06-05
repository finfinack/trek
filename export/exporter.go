package export

import (
	"context"

	"github.com/finfinack/trek/payload"
)

type Exporter interface {
	Write(context.Context, <-chan payload.Message) error
}
