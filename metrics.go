package main

import (
	"io"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	mActiveConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "jumpgopher_active_connections",
		Help: "Amount of active connections per user.",
	}, []string{"user"})

	mDataSend = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "jumpgopher_data_send_bytes_total",
		Help: "Total amount of data sent from client to target per user.",
	}, []string{"user"})

	mDataReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "jumpgopher_data_received_bytes_total",
		Help: "Total amount of data received from target to client per user.",
	}, []string{"user"})
)

// handleMetric wraps an io.Reader to count the number of bytes read and update
// the provided Prometheus counter with the specified user label.
func handleMetric(reader io.Reader, counter *prometheus.CounterVec, user string) io.Reader {
	return &MetricReader{
		reader:  reader,
		counter: counter.WithLabelValues(user),
	}
}

// MetricReader is a wrapper around io.Reader that counts the number of bytes read
// and updates a Prometheus counter accordingly.
type MetricReader struct {
	counter prometheus.Counter
	reader  io.Reader
}

func (r MetricReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if n > 0 {
		r.counter.Add(float64(n))
	}
	return n, err
}
