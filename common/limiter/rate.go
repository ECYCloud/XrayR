package limiter

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type Writer struct {
	writer  buf.Writer
	limiter *rate.Limiter
	w       io.Writer
}

type Reader struct {
	reader  buf.Reader
	limiter *rate.Limiter
}

func (l *Limiter) RateWriter(writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	return &Writer{
		writer:  writer,
		limiter: limiter,
	}
}

func (l *Limiter) RateReader(reader buf.Reader, limiter *rate.Limiter) buf.Reader {
	return &Reader{
		reader:  reader,
		limiter: limiter,
	}
}

func (w *Writer) Close() error {
	return common.Close(w.writer)
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	ctx := context.Background()
	w.limiter.WaitN(ctx, int(mb.Len()))
	return w.writer.WriteMultiBuffer(mb)
}

func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	if err != nil || mb.IsEmpty() {
		return mb, err
	}
	ctx := context.Background()
	_ = r.limiter.WaitN(ctx, int(mb.Len()))
	return mb, nil
}
