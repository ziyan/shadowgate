package tun

import (
	"io"
	"os"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("ipv6")

type TUN interface {
	io.ReadWriteCloser

	Interface() string
}

type tun struct {
	file    *os.File
	ifname  string
	persist bool
}

func (t *tun) Interface() string {
	return t.ifname
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
func Open(ifname string, persist bool) (TUN, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	ifname, err = createInterface(file.Fd(), ifname)
	if err != nil {
		file.Close()
		return nil, err
	}

	if err := setInterfacePersist(file.Fd(), persist); err != nil {
		file.Close()
		return nil, err
	}

	return &tun{
		file:   file,
		ifname: ifname,
	}, nil
}
