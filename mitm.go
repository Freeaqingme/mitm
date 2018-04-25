package mitm

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

// Proxy is a forward proxy that substitutes its own certificate
// for incoming TLS connections in place of the upstream server's
// certificate.
type Proxy struct {
	// Wrap specifies a function for optionally wrapping upstream for
	// inspecting the decrypted HTTP request and response.
	Wrap func(upstream http.Handler) http.Handler

	// CA specifies the root CA for generating leaf certs for each incoming
	// TLS request.
	CA *tls.Certificate

	// FlushInterval specifies the flush interval
	// to flush to the client while copying the
	// response body.
	// If zero, no periodic flushing is done.
	FlushInterval time.Duration

	ModifyResponse func(*http.Response) error
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}

	p.Wrap(p.getReverseProxy(httpDirector)).ServeHTTP(w, r)
}

func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	cconn, err := p.handshake(w)
	if err != nil {
		log.Println("handshake", r.Host, err)
		return
	}
	defer cconn.Close()

	ch := make(chan struct{}, 0)
	wc := &onCloseConn{cconn, func() { ch <- struct{}{} }}
	http.Serve(&oneShotListener{wc}, p.Wrap(p.getReverseProxy(httpsDirector)))
	<-ch
}

func (p *Proxy) getReverseProxy(director func(r *http.Request)) *httputil.ReverseProxy {
	ret := &httputil.ReverseProxy{
		Director:      director,
		FlushInterval: p.FlushInterval,
		//Transport:     p,
	}

	if p.ModifyResponse != nil {
		ret.ModifyResponse = p.ModifyResponse
	}

	return ret
}

func (p *Proxy) cert(names ...string) (*tls.Certificate, error) {
	return p.CA, nil
}

var okHeader = []byte("HTTP/1.1 200 OK\r\n\r\n")

// handshake hijacks w's underlying net.Conn, responds to the CONNECT request
// and manually performs the TLS handshake. It returns the net.Conn or and
// error if any.
func (p *Proxy) handshake(w http.ResponseWriter) (net.Conn, error) {
	raw, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "no upstream", 503)
		return nil, err
	}
	if _, err = raw.Write(okHeader); err != nil {
		raw.Close()
		return nil, err
	}

	conn := tls.Server(raw, &tls.Config{
		Certificates: []tls.Certificate{*p.CA},
	})
	err = conn.Handshake()
	if err != nil {
		conn.Close()
		raw.Close()
		return nil, err
	}
	return conn, nil
}

func httpDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "http"
}

func httpsDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "https"
}

// A oneShotListener implements net.Listener whose Accept only returns a
// net.Conn as specified by c followed by an error for each subsequent Accept.
type oneShotListener struct {
	c net.Conn
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.c == nil {
		return nil, errors.New("closed")
	}
	c := l.c
	l.c = nil
	return c, nil
}

func (l *oneShotListener) Close() error {
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.c.LocalAddr()
}

// A onCloseConn implements net.Conn and calls its f on Close.
type onCloseConn struct {
	net.Conn
	f func()
}

func (c *onCloseConn) Close() error {
	if c.f != nil {
		c.f()
		c.f = nil
	}
	return c.Conn.Close()
}
