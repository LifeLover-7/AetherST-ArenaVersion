package main

import (
	"bufio"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"io"
	"net/http"
)

// The bundled Aether H2 transport sends a classic CONNECT with cf-connect-proto
// and type-zero capsules containing IP packets. The virtual stack serves only fixtures.
func varint(r *bufio.Reader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	size := 1 << (b >> 6)
	v := int(b & 63)
	for i := 1; i < size; i++ {
		next, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		if v > 65535 {
			return 0, io.ErrShortBuffer
		}
		v = v*256 + int(next)
	}
	return v, nil
}
func masque(serve func(*netstack.Net)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Method != "CONNECT" || r.Header.Get("cf-connect-proto") == "" {
			w.WriteHeader(400)
			return
		}
		dev, n := stack()
		serve(n)
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		go func() {
			defer dev.Close()
			input := bufio.NewReader(r.Body)
			for {
				kind, err := varint(input)
				if err != nil {
					return
				}
				l, err := varint(input)
				if err != nil || l < 0 || l > 65535 {
					return
				}
				p := make([]byte, l)
				if _, err = io.ReadFull(input, p); err != nil {
					return
				}
				if kind == 0 && l >= 20 {
					if _, err = dev.Write([][]byte{p}, 0); err != nil {
						return
					}
				}
			}
		}()
		sizes := make([]int, 1)
		buf := make([]byte, 65535)
		for {
			_, err := dev.Read([][]byte{buf}, sizes, 0)
			if err != nil {
				return
			}
			l := sizes[0]
			if l < 1 || l >= 16384 {
				return
			}
			hdr := []byte{0, byte(l>>8) | 0x40, byte(l)}
			if _, err = w.Write(hdr); err != nil {
				return
			}
			if _, err = w.Write(buf[:l]); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}
}
