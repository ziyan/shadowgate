package e2e

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ziyan/shadowgate/internal/client"
	"github.com/ziyan/shadowgate/internal/ipv4"
	"github.com/ziyan/shadowgate/internal/server"
	"github.com/ziyan/shadowgate/internal/tuntest"
)

var (
	serverIP = net.ParseIP("172.18.0.1")
	clientIP = net.ParseIP("172.18.0.2")
)

func mustCIDR(t *testing.T, cidr string) (net.IP, *net.IPNet) {
	t.Helper()
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %s", cidr, err)
	}
	return ip, network
}

// freePort returns a likely-free port. TCP and UDP port spaces are independent,
// but on a test host a free TCP port is almost always free for UDP too, which
// lets the server bind both on one port (as it does in production).
func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %s", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

// setup starts a server (with the requested transports) and a client sharing one
// address, returning their in-memory tun devices.
func setup(t *testing.T, tcpEnabled, udpEnabled bool) (*tuntest.FakeTUN, *tuntest.FakeTUN) {
	t.Helper()

	address := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	password := []byte("shared-secret")

	serverAddress, serverNetwork := mustCIDR(t, "172.18.0.1/24")
	clientAddress, clientNetwork := mustCIDR(t, "172.18.0.2/24")

	serverTun := tuntest.New()
	config := server.Config{Password: password, Padding: 128, Timeout: time.Second}
	if tcpEnabled {
		config.TCPListen = address
	}
	if udpEnabled {
		config.UDPListen = address
	}
	serverRunner, err := server.NewServer(serverTun, serverAddress, serverNetwork, config)
	if err != nil {
		t.Fatalf("NewServer: %s", err)
	}

	serverSignal := make(chan os.Signal, 1)
	clientSignal := make(chan os.Signal, 1)
	var group sync.WaitGroup

	group.Add(1)
	go func() { defer group.Done(); _ = serverRunner.Run(serverSignal) }()

	clientTun := tuntest.New()
	clientRunner, err := client.NewClient(clientTun, clientAddress, clientNetwork, address, password, false, 128, time.Second)
	if err != nil {
		close(serverSignal)
		group.Wait()
		t.Fatalf("NewClient: %s", err)
	}

	group.Add(1)
	go func() { defer group.Done(); _ = clientRunner.Run(clientSignal) }()

	t.Cleanup(func() {
		close(clientSignal)
		close(serverSignal)
		group.Wait()
	})

	return serverTun, clientTun
}

// deliver injects frame on the "from" tun and waits for it to appear on the "to"
// tun, retrying because route learning and health probing take a moment.
func deliver(t *testing.T, from, to *tuntest.FakeTUN, frame ipv4.Frame) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		from.Inject(frame)
		if got, ok := to.Observe(200 * time.Millisecond); ok && bytes.Equal(got, frame) {
			return
		}
	}
	t.Fatal("frame was not delivered within the deadline")
}

func TestBothTransports(t *testing.T) {
	serverTun, clientTun := setup(t, true, true)
	deliver(t, clientTun, serverTun, ipv4.MakeFrame(clientIP, serverIP))
	deliver(t, serverTun, clientTun, ipv4.MakeFrame(serverIP, clientIP))
}

func TestUDPOnlyServerClientFallsBack(t *testing.T) {
	// The server offers only UDP; the client's TCP dial fails, so it uses UDP.
	serverTun, clientTun := setup(t, false, true)
	deliver(t, clientTun, serverTun, ipv4.MakeFrame(clientIP, serverIP))
	deliver(t, serverTun, clientTun, ipv4.MakeFrame(serverIP, clientIP))
}

func TestTCPOnlyServerClientFallsBack(t *testing.T) {
	// The server offers only TCP; the client's UDP link never gets a reply and is
	// unhealthy, so the client sends over TCP.
	serverTun, clientTun := setup(t, true, false)
	deliver(t, clientTun, serverTun, ipv4.MakeFrame(clientIP, serverIP))
	deliver(t, serverTun, clientTun, ipv4.MakeFrame(serverIP, clientIP))
}

func TestClientReconnectsAfterServerRestart(t *testing.T) {
	password := []byte("shared-secret")
	address := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	serverAddress, serverNetwork := mustCIDR(t, "172.18.0.1/24")
	clientAddress, clientNetwork := mustCIDR(t, "172.18.0.2/24")
	config := server.Config{TCPListen: address, UDPListen: address, Password: password, Padding: 128, Timeout: time.Second}

	startServer := func(device *tuntest.FakeTUN) (chan<- os.Signal, *sync.WaitGroup) {
		runner, err := server.NewServer(device, serverAddress, serverNetwork, config)
		if err != nil {
			t.Fatalf("NewServer: %s", err)
		}
		signal := make(chan os.Signal, 1)
		var group sync.WaitGroup
		group.Add(1)
		go func() { defer group.Done(); _ = runner.Run(signal) }()
		return signal, &group
	}

	// First server generation.
	firstTun := tuntest.New()
	firstSignal, firstGroup := startServer(firstTun)

	clientTun := tuntest.New()
	clientRunner, err := client.NewClient(clientTun, clientAddress, clientNetwork, address, password, false, 128, time.Second)
	if err != nil {
		t.Fatalf("NewClient: %s", err)
	}
	clientSignal := make(chan os.Signal, 1)
	var clientGroup sync.WaitGroup
	clientGroup.Add(1)
	go func() { defer clientGroup.Done(); _ = clientRunner.Run(clientSignal) }()
	t.Cleanup(func() { close(clientSignal); clientGroup.Wait() })

	deliver(t, clientTun, firstTun, ipv4.MakeFrame(clientIP, serverIP))

	// Kill the server, then start a fresh one on the same address.
	close(firstSignal)
	firstGroup.Wait()

	secondTun := tuntest.New()
	secondSignal, secondGroup := startServer(secondTun)
	t.Cleanup(func() { close(secondSignal); secondGroup.Wait() })

	// The client must re-dial and deliver to the new server without a restart.
	deliver(t, clientTun, secondTun, ipv4.MakeFrame(clientIP, serverIP))
}

func TestRouteThroughClient(t *testing.T) {
	// A network (10.9.9.9) sits behind the client, which relays for it.
	behindClient := net.ParseIP("10.9.9.9")
	serverTun, clientTun := setup(t, true, true)

	// The client forwards a frame sourced from behind it to the server. The
	// server must accept and deliver it (not drop the foreign source) and learn a
	// route back to 10.9.9.9 via this client.
	deliver(t, clientTun, serverTun, ipv4.MakeFrame(behindClient, serverIP))

	// The server now routes a frame destined for the behind-client network; it
	// must be forwarded to the client (not looped back to the server's own tun),
	// and the client must accept it (not drop the foreign destination).
	deliver(t, serverTun, clientTun, ipv4.MakeFrame(serverIP, behindClient))
}
