package tun

import (
	"io"
	"os"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("ipv6")

type TUN interface {
	io.ReadWriteCloser

	Name() string
}

type tun struct {
	file    *os.File
	name    string
	persist bool
}

func (t *tun) Name() string {
	return t.name
}

func (t *tun) Read(p []byte) (int, error) {
	return t.file.Read(p)
}

func (t *tun) Write(p []byte) (int, error) {
	return t.file.Write(p)
}

func (t *tun) Close() error {
	return t.file.Close()
}
func Open(name string, persist bool) (TUN, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	name, err = createInterface(file.Fd(), name)
	if err != nil {
		file.Close()
		return nil, err
	}

	if err := setInterfacePersist(file.Fd(), persist); err != nil {
		file.Close()
		return nil, err
	}

	return &tun{
		file: file,
		name: name,
	}, nil
}
