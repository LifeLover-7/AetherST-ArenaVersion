// Android service integration peers. Nothing routes onto the Internet. The only host
// listeners for the emulator are on loopback; all DNS, origins and nested edges are
// inside userspace IP stacks. Generate a fresh identity and scoped test CA per run.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const gateway = "10.70.0.1"
const origin = "192.0.2.42:80"
const edge = "edge.fixture.test"
const records = "firefox.settings.services.mozilla.com"

var cert tls.Certificate
var metadata = map[string]string{}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func b64(v []byte) string { return base64.StdEncoding.EncodeToString(v) }
func stack() (tun.Device, *netstack.Net) {
	var ips []netip.Addr
	for _, s := range []string{gateway, "8.8.8.8", "1.1.1.1", "192.0.2.42"} {
		ips = append(ips, netip.MustParseAddr(s))
	}
	dev, n, err := netstack.CreateNetTUN(ips, nil, 1280)
	must(err)
	for _, address := range []string{"8.8.8.8:53", "1.1.1.1:53"} {
		udp, err := n.ListenUDPAddrPort(netip.MustParseAddrPort(address))
		must(err)
		go dns(udp)
	}
	return dev, n
}
func dns(c net.PacketConn) {
	defer c.Close()
	b := make([]byte, 4096)
	for {
		l, a, err := c.ReadFrom(b)
		if err != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(b[:l]) != nil || len(q.Questions) != 1 {
			continue
		}
		q.Response = true
		name := q.Questions[0].Name.String()
		if name == records+"." || name == edge+"." {
			q.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 10}, Body: &dnsmessage.AResource{A: [4]byte{10, 70, 0, 1}}}}
		} else {
			q.RCode = dnsmessage.RCodeNameError
		}
		reply, err := q.Pack()
		if err == nil {
			c.WriteTo(reply, a)
		}
	}
}
func listen(n *netstack.Net, addr string) net.Listener {
	l, err := n.ListenTCPAddrPort(netip.MustParseAddrPort(addr))
	must(err)
	return l
}
func https(l net.Listener, f http.HandlerFunc) {
	srv := &http.Server{Handler: f, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}}
	go srv.ServeTLS(l, "", "")
}
func originHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "via-%s:%s\n", name, r.URL.Path) }
}
func trace(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ip=192.0.2.10") }

func wg(n tun.Device, label string) string {
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	must(err)
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	must(err)
	dev := device.NewDevice(n, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	must(dev.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=0\npublic_key=%x\nallowed_ip=10.70.0.2/32\n", server.Bytes(), client.PublicKey().Bytes())))
	must(dev.Up())
	st, err := dev.IpcGet()
	must(err)
	metadata[label+"Key"] = b64(client.Bytes())
	metadata[label+"Pub"] = b64(server.PublicKey().Bytes())
	return strings.SplitN(strings.SplitN(st, "listen_port=", 2)[1], "\n", 2)[0]
}

// One virtual destination -> one fixture peer. Separate controls/UDP sources for tests and retries.
func forwardWG(n *netstack.Net, port string) {
	udp, err := n.ListenUDPAddrPort(netip.MustParseAddrPort(gateway + ":2408"))
	must(err)
	go func() {
		defer udp.Close()
		sessions := map[string]net.Conn{}
		defer func() {
			for _, c := range sessions {
				c.Close()
			}
		}()
		b := make([]byte, 2048)
		for {
			l, a, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			c := sessions[a.String()]
			if c == nil {
				c, err = net.Dial("udp4", "127.0.0.1:"+port)
				if err != nil {
					return
				}
				sessions[a.String()] = c
				go func(c net.Conn, a net.Addr) {
					r := make([]byte, 2048)
					for {
						l, err := c.Read(r)
						if err != nil {
							return
						}
						if _, err = udp.WriteTo(r[:l], a); err != nil {
							return
						}
					}
				}(c, a)
			}
			c.Write(b[:l])
		}
	}()
}
func main() {
	root := os.Args[1]
	var err error
	cert, err = tls.LoadX509KeyPair(filepath.Join(root, "leaf.pem"), filepath.Join(root, "leaf.key"))
	must(err)
	// No trust in this JWT is implied by the client; the fixture edge compares the complete value.
	metadata["pass"] = "eyJ0ZXN0Ijp0cnVlfQ." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(24*time.Hour).Unix()))) + ".fixture"
	inner, inn := stack()
	innerPort := wg(inner, "inner")
	go http.Serve(listen(inn, origin), originHandler("wireguard"))
	https(listen(inn, "1.1.1.1:443"), trace)
	outer, on := stack()
	metadata["wgPort"] = wg(outer, "outer")
	forwardWG(on, innerPort)
	https(listen(on, gateway+":443"), func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"data":[{"code":"US","cities":[{"servers":[{"protocols":[{"name":"connect","host":%q,"port":8443}]}]}]}]}`, edge)
	})
	fakeOrigin, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	go http.Serve(fakeOrigin, originHandler("firefox"))
	fakeTrace, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	https(fakeTrace, trace)
	https(listen(on, gateway+":8443"), func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Header.Get("Proxy-Authorization") != "Bearer "+metadata["pass"] {
			w.WriteHeader(407)
			return
		}
		var dest string
		switch r.Host {
		case origin:
			dest = fakeOrigin.Addr().String()
		case "1.1.1.1:443":
			dest = fakeTrace.Addr().String()
		default:
			w.WriteHeader(403)
			return
		}
		c, err := net.Dial("tcp4", dest)
		if err != nil {
			return
		}
		defer c.Close()
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		go func() { io.Copy(c, r.Body); c.(*net.TCPConn).CloseWrite() }()
		buf := make([]byte, 8192)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				if _, err = w.Write(buf[:n]); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
	})
	outerTLS, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	metadata["masquePort"] = fmt.Sprint(outerTLS.Addr().(*net.TCPAddr).Port)
	https(outerTLS, masque(func(n *netstack.Net) {
		forwardWG(n, innerPort)
		https(listen(n, gateway+":4443"), masque(func(n *netstack.Net) { go http.Serve(listen(n, origin), originHandler("masque")) }))
	}))
	data, err := json.Marshal(metadata)
	must(err)
	must(os.WriteFile(filepath.Join(root, "peers.json.tmp"), data, 0600))
	must(os.Rename(filepath.Join(root, "peers.json.tmp"), filepath.Join(root, "peers.json")))
	fmt.Println("Local device peers ready")
	select {}
}
