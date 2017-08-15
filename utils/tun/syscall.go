package tun

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

func ioctl(fd uintptr, request int, argp uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(request), argp)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}

func createInterface(fd uintptr, name string, flags uint16) (string, error) {
	data := &struct {
		Name  [0x10]byte
		Flags uint16
		pad   [0x28 - 0x10 - 2]byte
	}{}

	data.Flags = flags
	copy(data.Name[:], name)

	if err := ioctl(fd, syscall.TUNSETIFF, uintptr(unsafe.Pointer(data))); err != nil {
		return "", nil
	}

	return strings.Trim(string(data.Name[:]), "\x00"), nil
}

func setInterfacePersist(fd uintptr, persist bool) error {
	value := 0
	if persist {
		value = 1
	}
	return ioctl(fd, syscall.TUNSETPERSIST, uintptr(value))
}
