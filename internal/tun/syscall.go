package tun

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// TUN interface flags, see <linux/if_tun.h> and <linux/if.h>.
const (
	iffTun     = 0x0001
	iffNoPi    = 0x1000
	ifNameSize = 0x10
)

func ioctl(fd uintptr, request uintptr, argp uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, argp)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}

func createInterface(fd uintptr, name string) (string, error) {
	data := &struct {
		Name  [ifNameSize]byte
		Flags uint16
		pad   [0x28 - ifNameSize - 2]byte
	}{}

	data.Flags = iffTun | iffNoPi
	copy(data.Name[:], name)

	if err := ioctl(fd, syscall.TUNSETIFF, uintptr(unsafe.Pointer(data))); err != nil {
		return "", err
	}

	return strings.Trim(string(data.Name[:]), "\x00"), nil
}

func setInterfacePersist(fd uintptr, persist bool) error {
	value := uintptr(0)
	if persist {
		value = 1
	}
	return ioctl(fd, syscall.TUNSETPERSIST, value)
}
