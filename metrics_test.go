package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

type DummyWriter struct {
}

func (w *DummyWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

type DummyReader struct {
	reader io.Reader
}

func (r *DummyReader) Read(p []byte) (n int, err error) {
	return r.reader.Read(p)
}

var data []byte

func init() {
	data := make([]byte, 1024*1024) // 100MB
	rand.Read(data)
}

func BenchmarkIoCopy(b *testing.B) {
	reader := &DummyReader{bytes.NewReader(data)}

	var writer DummyWriter

	for b.Loop() {
		io.Copy(&writer, reader)
	}
}

func BenchmarkMetricsCopy(b *testing.B) {
	reader := &DummyReader{bytes.NewReader(data)}

	var writer DummyWriter

	reader2 := handleMetric(reader, mDataSend, "benchmark")

	for b.Loop() {
		io.Copy(&writer, reader2)
	}
}
