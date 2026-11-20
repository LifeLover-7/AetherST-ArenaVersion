package main

import (
    "crypto/ecdh"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "net"
    "net/http"
    "net/netip"
    "strings"

    "golang.zx2c4.com/wireguard/conn"
    "golang.zx2c4.com/wireguard/device"
    "golang.zx2c4.com/wireguard/tun/netstack"
)

func must(err error) { if err != nil { panic(err) } }

func main() {
    client, err := ecdh.X25519().GenerateKey(rand.Reader); must(err)
    server, err := ecdh.X25519().GenerateKey(rand.Reader); must(err)
    tun, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.2.0.1")}, nil, 1120); must(err)
    dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "")); defer dev.Close()
    must(dev.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=0\npublic_key=%x\nallowed_ip=10.2.0.2/32\n", server.Bytes(), client.PublicKey().Bytes())))
    must(dev.Up())
    state, err := dev.IpcGet(); must(err)
    port := strings.SplitN(strings.SplitN(state, "listen_port=", 2)[1], "\n", 2)[0]
    listener, err := stack.ListenTCP(&net.TCPAddr{Port: 80}); must(err)
    fmt.Println(port, base64.StdEncoding.EncodeToString(client.Bytes()), base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()))
    must(http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "inside-the-test-peer") })))
}
