package limiter

import (
	"context"
	"errors"
	"io"
	"time"

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
	r.limiter.WaitN(ctx, int(mb.Len()))
	return mb, nil
}

// GuardReader / GuardWriter 周期性复查连接的在线名额：
// IP 仍持有名额则刷新活跃时间；被挤出且名额已满时返回错误，促使 xray 关闭连接，
// 从而让超限设备的既有长连接也被强制断开。

type guardState struct {
	l       *Limiter
	tag     string
	userKey string
	ip      string
	next    int64
}

func (g *guardState) check() error {
	if now := time.Now().Unix(); now >= g.next {
		g.next = now + onlineTouchSec
		if !g.l.EnsureOnline(g.tag, g.userKey, g.ip) {
			return errDeviceLimited
		}
	}
	return nil
}

var errDeviceLimited = errors.New("device limit exceeded, connection closed by limiter")

type GuardReader struct {
	reader buf.Reader
	guardState
}

type GuardWriter struct {
	writer buf.Writer
	guardState
}

func (l *Limiter) GuardReader(reader buf.Reader, tag, userKey, ip string) buf.Reader {
	return &GuardReader{reader: reader, guardState: guardState{l: l, tag: tag, userKey: userKey, ip: ip}}
}

func (l *Limiter) GuardWriter(writer buf.Writer, tag, userKey, ip string) buf.Writer {
	return &GuardWriter{writer: writer, guardState: guardState{l: l, tag: tag, userKey: userKey, ip: ip}}
}

func (r *GuardReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	return r.reader.ReadMultiBuffer()
}

func (w *GuardWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if err := w.check(); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	return w.writer.WriteMultiBuffer(mb)
}

func (w *GuardWriter) Close() error {
	return common.Close(w.writer)
}

func (r *Reader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	// If underlying reader supports timeout, use it; otherwise fallback to non-timeout read.
	type timeoutReader interface {
		ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error)
	}
	if tr, ok := r.reader.(timeoutReader); ok {
		mb, err := tr.ReadMultiBufferTimeout(timeout)
		if err != nil || mb.IsEmpty() {
			return mb, err
		}
		ctx := context.Background()
		r.limiter.WaitN(ctx, int(mb.Len()))
		return mb, nil
	}
	mb, err := r.reader.ReadMultiBuffer()
	if err != nil || mb.IsEmpty() {
		return mb, err
	}
	ctx := context.Background()
	r.limiter.WaitN(ctx, int(mb.Len()))
	return mb, nil
}
