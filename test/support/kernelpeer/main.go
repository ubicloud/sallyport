// This is a fixture for the tests: a WireGuard peer that has the Linux
// kernel for its TCP.
//
// It makes a network namespace of its own with a TUN device in it, which
// wireguard-go serves, and it runs a TCP forwarder there on kernel
// sockets. What arrives on port 7000 goes to port 7001 at the other end
// of the tunnel. So the kernel is a TCP server and a TCP client at once,
// and a test that holds both ends has a ring through it.
//
// The UDP socket stays in the namespace that the fixture was started in,
// where the tunnel under test reaches it on the loopback interface. The
// fixture has a keepalive, and so begins the handshake.
//
// It needs CAP_NET_ADMIN, CAP_SYS_ADMIN and /dev/net/tun. When it is up
// it prints "ready 6", or "ready 4" where the kernel has no IPv6, which
// is the family that the test is to use.
//
//	kernelpeer PRIVATE-KEY PEER-PUBLIC-KEY PEER-ENDPOINT
package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// These are the tunnel's addresses in each family: ours, and those of
// the other end.
var (
	ours   = map[int]string{4: "10.7.0.2/32", 6: "fd07::2/128"}
	theirs = map[int]string{4: "10.7.0.1", 6: "fd07::1"}
)

// key returns a base64 key in hex, as wireguard-go takes it.
func key(text string) string {
	bytes, err := base64.StdEncoding.DecodeString(text)
	if err != nil || len(bytes) != 32 {
		log.Fatalf("bad key %q", text)
	}
	return hex.EncodeToString(bytes)
}

// A dial asks the thread inside the namespace for a connection.
type dial struct {
	address string
	done    chan net.Conn
}

// inside is what the thread inside the namespace made there.
type inside struct {
	tun      tun.Device
	listener net.Listener
	dials    chan dial
	family   int
}

// enter moves the calling thread into a new network namespace for good,
// and makes there everything that must belong to it. A socket belongs to
// the namespace of the thread that made it, wherever it is used.
func enter(made chan<- inside) {
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		log.Fatalf("unshare: %v", err)
	}
	// Go decides whether a listener can take both families by binding
	// to the loopback addresses, which a new namespace has down.
	loopback, err := netlink.LinkByName("lo")
	if err == nil {
		err = netlink.LinkSetUp(loopback)
	}
	if err != nil {
		log.Fatalf("loopback: %v", err)
	}
	device, err := tun.CreateTUN("sallyport%d", 1420)
	if err != nil {
		log.Fatalf("tun: %v", err)
	}
	name, _ := device.Name()
	link, err := netlink.LinkByName(name)
	if err != nil {
		log.Fatal(err)
	}
	family := 4
	for _, f := range []int{4, 6} {
		address, _ := netlink.ParseAddr(ours[f])
		if f == 6 {
			// The address is usable at once, with no wait to see
			// whether another host has it.
			address.Flags = unix.IFA_F_NODAD
		}
		if err := netlink.AddrAdd(link, address); err != nil {
			if f == 4 {
				log.Fatalf("address: %v", err)
			}
			log.Printf("no IPv6 here: %v", err)
			continue
		}
		family = f
	}
	if err := netlink.LinkSetUp(link); err != nil {
		log.Fatal(err)
	}
	for f := 4; f <= family; f += 2 {
		_, to, _ := net.ParseCIDR(theirs[f] + map[int]string{4: "/32", 6: "/128"}[f])
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: to}); err != nil {
			log.Fatalf("route: %v", err)
		}
	}
	listener, err := net.Listen(map[int]string{4: "tcp4", 6: "tcp6"}[family], ":7000")
	if err != nil {
		log.Fatal(err)
	}
	dials := make(chan dial)
	made <- inside{device, listener, dials, family}
	for d := range dials {
		conn, err := net.DialTimeout("tcp", d.address, 10*time.Second)
		if err != nil {
			conn = nil
		}
		d.done <- conn
	}
}

// forward carries a connection that arrived to port 7001 at the other
// end of the tunnel, and back.
func forward(in inside, from net.Conn) {
	d := dial{net.JoinHostPort(theirs[in.family], "7001"), make(chan net.Conn)}
	in.dials <- d
	to := <-d.done
	if to == nil {
		from.Close()
		return
	}
	// Each direction ends with a shutdown and not a close, so that the
	// end of one direction goes round the ring as that and no more.
	pipe := func(to, from *net.TCPConn, done chan<- struct{}) {
		io.Copy(to, from)
		to.CloseWrite()
		done <- struct{}{}
	}
	done := make(chan struct{}, 2)
	go pipe(to.(*net.TCPConn), from.(*net.TCPConn), done)
	go pipe(from.(*net.TCPConn), to.(*net.TCPConn), done)
	<-done
	<-done
	from.Close()
	to.Close()
}

func main() {
	if len(os.Args) != 4 {
		log.Fatal("usage: kernelpeer PRIVATE-KEY PEER-PUBLIC-KEY PEER-ENDPOINT")
	}
	made := make(chan inside)
	go enter(made)
	in := <-made

	// The device's UDP socket is made here, on a thread that never left
	// the first namespace. Standard output carries "ready" and nothing
	// else, so the device reports on standard error.
	logger := &device.Logger{Verbosef: func(string, ...any) {}, Errorf: log.Printf}
	dev := device.NewDevice(in.tun, conn.NewDefaultBind(), logger)
	err := dev.IpcSet(fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=%s/128\nallowed_ip=%s/32\npersistent_keepalive_interval=25\n",
		key(os.Args[1]), key(os.Args[2]), os.Args[3], theirs[6], theirs[4]))
	if err != nil {
		log.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("ready", in.family)
	for {
		conn, err := in.listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go forward(in, conn)
	}
}
