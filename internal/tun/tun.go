// Package tun opens and manages a Linux TUN network interface.
package tun

import (
	"io"
	"os"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("tun")

// TUN is a TUN network interface that can be read from and written to as a
// stream of raw IP frames.
type TUN interface {
	io.ReadWriteCloser

	Interface() string
}

type tun struct {
	file          *os.File
	interfaceName string
}

func (self *tun) Interface() string {
	return self.interfaceName
}

func (self *tun) Read(buffer []byte) (int, error) {
	return self.file.Read(buffer)
}

func (self *tun) Write(buffer []byte) (int, error) {
	return self.file.Write(buffer)
}

func (self *tun) Close() error {
	return self.file.Close()
}

func Open(interfaceName string, persist bool) (TUN, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	interfaceName, err = createInterface(file.Fd(), interfaceName)
	if err != nil {
		_ = file.Close()
		return nil, err
	}

	if err := setInterfacePersist(file.Fd(), persist); err != nil {
		_ = file.Close()
		return nil, err
	}

	log.Noticef("opened tun interface: %s (persist=%t)", interfaceName, persist)

	return &tun{
		file:          file,
		interfaceName: interfaceName,
	}, nil
}
