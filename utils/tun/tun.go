package tun

import (
	"io"
	"os"
)

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
	defer func() {
		if file != nil {
			file.Close()
			file = nil
		}
	}()

	name, err = createInterface(file.Fd(), name, 0x0001|0x1000)
	if err != nil {
		return nil, err
	}

	if err := setInterfacePersist(file.Fd(), persist); err != nil {
		return nil, err
	}

	t := &tun{
		file: file,
		name: name,
	}
	file = nil
	return t, nil
}
