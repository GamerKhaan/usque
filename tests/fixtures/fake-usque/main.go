// fake-usque is a CI fixture for exercising the real supervisor and systemd
// unit. It serves a local TLS trace through a minimal TCP SOCKS5 endpoint.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		log.Fatal("fake-usque is restricted to ephemeral GitHub Actions test runners")
	}
	if len(os.Args) == 3 && os.Args[1] == "--init-ca" {
		if err := createCertificate(os.Args[2]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := serve(); err != nil {
		log.Fatal(err)
	}
}

func createCertificate(dir string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "usque CI trace"}, DNSNames: []string{"trace.invalid"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "test-ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "test-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600)
}

func serve() error {
	key, err := tls.LoadX509KeyPair("/var/lib/usque/test-ca.crt", "/var/lib/usque/test-key.pem")
	if err != nil {
		return err
	}
	trace, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{key}, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	defer func() { _ = trace.Close() }()
	server := &http.Server{
		ReadHeaderTimeout: 3 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "warp=on\nfixture=local-ci\n")
		}),
	}
	defer func() { _ = server.Close() }()
	go func() { _ = server.Serve(trace) }()
	listener, err := net.Listen("tcp", net.JoinHostPort(os.Getenv("USQUE_BIND"), os.Getenv("USQUE_PORT")))
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	log.Printf("local CI SOCKS fixture listening on %s", listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handleSOCKS(conn, trace.Addr().String())
	}
}

func handleSOCKS(conn net.Conn, target string) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != 5 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	request := make([]byte, 5)
	if _, err := io.ReadFull(conn, request); err != nil || request[0] != 5 || request[1] != 1 || request[3] != 3 {
		return
	}
	name := make([]byte, int(request[4])+2)
	if _, err := io.ReadFull(conn, name); err != nil {
		return
	}
	if string(name[:len(name)-2]) != "trace.invalid" || name[len(name)-2] != 1 || name[len(name)-1] != 187 {
		_, _ = conn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	remote, err := net.DialTimeout("tcp", target, time.Second)
	if err != nil {
		log.Print(fmt.Errorf("local trace dial: %w", err))
		return
	}
	defer func() { _ = remote.Close() }()
	if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() { _, _ = io.Copy(remote, conn); _ = remote.Close(); close(done) }()
	_, _ = io.Copy(conn, remote)
	_ = conn.Close()
	<-done
}
