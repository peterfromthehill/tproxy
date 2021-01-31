package webserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/peterfromthehill/tproxy/services"
	"go.elastic.co/apm"
)

type Webserver struct {
	HttpPort, HttpsPort int
	SSLCert, SSLKey     string
}

type contextKey struct {
	key string
}

var connContextKey = &contextKey{"http-conn"}

func saveConnInContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connContextKey, c)
}
func getConn(r *http.Request) net.Conn {
	return r.Context().Value(connContextKey).(net.Conn)
}

// getConnFromTLSConn returns the internal wrapped connection from the tls.Conn.
func getConnFromTLSConn(tlsConn *tls.Conn) net.Conn {
	// XXX: This is really BAD!!! Only way currently to get the underlying
	// connection of the tls.Conn. At least until
	// https://github.com/golang/go/issues/29257 is solved.
	conn := reflect.ValueOf(tlsConn).Elem().FieldByName("conn")
	conn = reflect.NewAt(conn.Type(), unsafe.Pointer(conn.UnsafeAddr())).Elem()
	return conn.Interface().(net.Conn)
}

func getTCPConnFromConn(netConn net.Conn) (*net.TCPConn, bool) {
	if tcpConn, ok := netConn.(*net.TCPConn); ok {
		return tcpConn, true
	}
	return nil, false
}

func getFileFromTCPConn(tcpConn *net.TCPConn) (*os.File, error) {
	file, err := tcpConn.File()
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (this Webserver) StartWebserver() {
	const NETWORK = "tcp"

	config := &tls.Config{
		GetCertificate: services.ReturnCert,
	}

	finish := make(chan bool)
	this.serveScheme("http", this.HttpPort, config)
	this.serveScheme("https", this.HttpsPort, config)
	log.Printf("Webserver startd in Ports %d & %d", this.HttpPort, this.HttpsPort)
	<-finish
}
func getFileFromConn(netConn net.Conn) (*os.File, error) {
	if tlsConn, ok := netConn.(*tls.Conn); ok {
		netConn := getConnFromTLSConn(tlsConn)
		if tcpConn, ok := getTCPConnFromConn(netConn); ok {
			file, err := getFileFromTCPConn(tcpConn)
			if err != nil {
				return nil, err
			}
			return file, nil
		}
	}

	if tcpConn, ok := netConn.(*net.TCPConn); ok {
		file, err := getFileFromTCPConn(tcpConn)
		if err != nil {
			return nil, err
		}
		return file, nil
	}
	return nil, errors.New("not a tcp or tls connection")
}

func isConnTLS(netConn net.Conn) bool {
	if _, ok := netConn.(*tls.Conn); ok {
		return true
	}
	return false
}

func handler(w http.ResponseWriter, r *http.Request) {
	span, ctx := apm.StartSpan(r.Context(), "HandlerFunc", "request")
	defer span.End()

	conn := getConn(r)
	log.Printf(conn.RemoteAddr().String())

	file, err := getFileFromConn(conn)
	if err != nil {
		log.Printf(err.Error())
	} else {
		log.Printf(file.Name())
		origAddr, err := getOrigAddr(file)
		if err != nil {
			log.Printf(err.Error())
		} else {
			log.Printf("Origin Addr: %s", origAddr)
		}
	}
	scheme := "http"
	if isConnTLS(conn) {
		scheme = "https"
	}
	requestHandler := services.RequestHandler{w, r, scheme}
	requestHandler.HandleHTTP(ctx)
}

func (this Webserver) serveScheme(scheme string, port int, TLSconfig *tls.Config) {
	go func() {
		server := http.Server{
			ConnContext: saveConnInContext,
			Handler:     http.HandlerFunc(handler),
			Addr:        ":" + fmt.Sprintf("%d", port),
		}
		switch scheme {
		case "http":
			log.Fatal(server.ListenAndServe())
		case "https":
			server.TLSConfig = TLSconfig
			log.Fatal(server.ListenAndServeTLS(this.SSLCert, this.SSLKey))
		}
	}()
}

func getOrigAddr(file *os.File) (string, error) {
	const SO_ORIGINAL_DST = 80
	addr, err := syscall.GetsockoptIPv6Mreq(int(file.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		log.Println("syscall.GetsockoptIPv6Mreq error: %w", err)
		return "", err
	}

	remote := fmt.Sprintf("%d.%d.%d.%d:%d",
		addr.Multiaddr[4], addr.Multiaddr[5], addr.Multiaddr[6], addr.Multiaddr[7],
		uint16(addr.Multiaddr[2])<<8+uint16(addr.Multiaddr[3]))
	log.Println("remote: ", remote)

	return remote, nil
}
