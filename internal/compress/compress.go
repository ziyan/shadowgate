// Package compress wraps a stream connection with Snappy compression.
package compress

import (
	"io"

	"github.com/golang/snappy"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("compress") //nolint:unused

// CompressedConnection wraps an io.ReadWriteCloser and transparently compresses
// data written and decompresses data read using Snappy.
type CompressedConnection struct {
	// underlying connection
	conn io.ReadWriteCloser

	// reader and writer
	reader *snappy.Reader
	writer *snappy.Writer
}

func (self *CompressedConnection) Read(buffer []byte) (int, error) {
	return self.reader.Read(buffer)
}

func (self *CompressedConnection) Write(buffer []byte) (int, error) {
	size, err := self.writer.Write(buffer)
	if err != nil {
		return size, err
	}
	if err := self.writer.Flush(); err != nil {
		return size, err
	}
	return size, nil
}

func (self *CompressedConnection) Close() error {
	return self.conn.Close()
}

func NewCompressedConnection(conn io.ReadWriteCloser) *CompressedConnection {
	return &CompressedConnection{
		conn:   conn,
		reader: snappy.NewReader(conn),
		writer: snappy.NewBufferedWriter(conn),
	}
}
