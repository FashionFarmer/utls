package tls

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// A REALITY server has to resemble Dest all the way through the handshake, not
// just up to the client's Finished. A real TLS server keeps talking after that
// point: OpenSSL sends its two NewSessionTickets there (two, because
// SSL_CTX_set_num_tickets defaults to 2), and a server that negotiated h2 adds
// its HTTP/2 SETTINGS frame straight away. Upstream REALITY stopped at Finished
// and went silent, which anyone who has ever opened a real TLS connection to
// Dest can notice for free — no traffic analysis required, one probe is enough.
//
// So we measure Dest once per (Dest, SNI, ALPN class) when the listener comes
// up, and replay records of exactly those lengths after the client's Finished.
// Only the lengths are observable, since the bodies are AEAD ciphertext, so the
// records we emit carry an empty application_data fragment: every TLS stack
// decrypts it, finds no content, and moves on.
//
// The measurement is keyed on ALPN because the h2 SETTINGS frame only shows up
// when ALPN negotiated h2, and on SNI because Dest may serve several names.

const (
	// How long to let Dest volunteer records once we have gone quiet.
	realityShapeReadWindow = 5 * time.Second
	// How long a handshake waits for a measurement that is still in flight.
	// Probing starts with the listener, so this only covers a client arriving
	// in the first few seconds after start-up.
	realityShapeWait = 6 * time.Second
	// Bound on how much of Dest's chatter we are willing to imitate.
	realityShapeMaxRecords = 16
	// A Dest that is briefly unreachable should not cost us the imitation for
	// the lifetime of the process.
	realityShapeAttempts   = 4
	realityShapeRetryDelay = 30 * time.Second
)

// realityShapes maps a shape key to []int once measured. A false placeholder
// means a probe is in flight; the absence of a key means nobody is probing it.
var realityShapes sync.Map

func realityShapeKey(dest, sni string, alpn int) string {
	return dest + " " + sni + " " + strconv.Itoa(alpn)
}

// realityALPNClass collapses the client's ALPN list into the three cases that
// change what Dest says after the handshake.
func realityALPNClass(protos []string) int {
	switch {
	case len(protos) == 0:
		return 0
	case protos[0] == "h2":
		return 2
	default:
		return 1
	}
}

// detectRealityRecordShape measures Dest in the background, once per key. It is
// safe to call repeatedly; keys already measured or in flight are skipped.
func detectRealityRecordShape(config *RealityConfig) {
	for sni := range config.ServerNames {
		for alpn := 0; alpn < 3; alpn++ {
			key := realityShapeKey(config.Dest, sni, alpn)
			if _, inFlight := realityShapes.LoadOrStore(key, false); inFlight {
				continue
			}
			go func(sni string, alpn int, key string) {
				// Publish the first attempt whatever it produced, so no
				// handshake waits longer than realityShapeWait, then keep
				// retrying in the background: a Dest that was unreachable at
				// start-up would otherwise leave us silent until a restart.
				for attempt := 0; attempt < realityShapeAttempts; attempt++ {
					if attempt > 0 {
						time.Sleep(realityShapeRetryDelay)
					}
					lens := probeRealityRecordShape(config, sni, alpn)
					realityShapes.Store(key, lens)
					if config.Log != nil {
						config.Log("REALITY dest shape %v: %v", key, lens)
					}
					if len(lens) > 0 {
						return
					}
				}
			}(sni, alpn, key)
		}
	}
}

// probeRealityRecordShape opens one ordinary TLS connection to Dest, completes
// the handshake, then says nothing and writes down the length of every record
// Dest sends on its own.
func probeRealityRecordShape(config *RealityConfig, sni string, alpn int) []int {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var (
		target net.Conn
		err    error
	)
	if config.DialContext != nil {
		target, err = config.DialContext(ctx, config.Type, config.Dest)
	} else {
		var d net.Dialer
		target, err = d.DialContext(ctx, config.Type, config.Dest)
	}
	if err != nil {
		if config.Log != nil {
			config.Log("REALITY dest shape: dial %v: %v", config.Dest, err)
		}
		return nil
	}
	defer target.Close()

	// Match the fingerprint to the ALPN the way a real client would: a browser
	// asks for h2, a plain library client does not.
	hello := HelloGolang
	var protos []string
	switch alpn {
	case 1:
		protos = []string{"http/1.1"}
	case 2:
		protos = []string{"h2", "http/1.1"}
		hello = HelloChrome_Auto
	}

	probe := &realityShapeConn{Conn: target}
	u := UClient(probe, &Config{ServerName: sni, NextProtos: protos}, hello)
	target.SetDeadline(time.Now().Add(20 * time.Second))
	if err := u.Handshake(); err != nil {
		if config.Log != nil {
			config.Log("REALITY dest shape: handshake %v (sni %v alpn %v): %v", config.Dest, sni, alpn, err)
		}
		return nil
	}
	// Dest has nothing of ours left to answer, so everything from here is
	// unprompted. Read the raw socket rather than the TLS connection: we only
	// want lengths, and going through the record layer would make empty or
	// unexpected records an error.
	target.SetReadDeadline(time.Now().Add(realityShapeReadWindow))
	io.Copy(io.Discard, probe)
	return probe.shape()
}

// realityShapeConn tees the bytes Dest sends after our own Finished goes out.
// The client's Finished is the last thing it writes during the handshake and it
// travels as application_data, so the first such write is the boundary. Taking
// the boundary from our Finished rather than from the ChangeCipherSpec matters:
// the CCS goes out before Dest's own flight has been read, and cutting there
// would swallow the rest of the handshake.
type realityShapeConn struct {
	net.Conn

	mu       sync.Mutex
	finished bool
	tail     []byte
}

func (c *realityShapeConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if !c.finished {
		// The Finished is an application_data record, but it is flushed in the
		// same write as the compatibility ChangeCipherSpec that precedes it, so
		// look at every record in the buffer instead of only the first one.
		for p := b; len(p) >= recordHeaderLen; {
			if binary.BigEndian.Uint16(p[1:3]) != VersionTLS12 {
				break
			}
			if recordType(p[0]) == recordTypeApplicationData {
				c.finished = true
				break
			}
			n := recordHeaderLen + int(binary.BigEndian.Uint16(p[3:5]))
			if n > len(p) {
				break
			}
			p = p[n:]
		}
	}
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *realityShapeConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.mu.Lock()
		if c.finished && len(c.tail) < int(realitySize) {
			c.tail = append(c.tail, b[:n]...)
		}
		c.mu.Unlock()
	}
	return n, err
}

// shape walks the tail along record boundaries and returns each record's total
// length, header included. A partial trailing record is dropped: we can only
// imitate what we measured whole.
func (c *realityShapeConn) shape() []int {
	c.mu.Lock()
	defer c.mu.Unlock()

	var out []int
	data := c.tail
	for len(data) >= recordHeaderLen && len(out) < realityShapeMaxRecords {
		if recordType(data[0]) != recordTypeApplicationData ||
			binary.BigEndian.Uint16(data[1:3]) != VersionTLS12 {
			break
		}
		n := recordHeaderLen + int(binary.BigEndian.Uint16(data[3:5]))
		if n > len(data) || n > int(realitySize) {
			break
		}
		out = append(out, n)
		data = data[n:]
	}
	return out
}

// realityRecordShape returns the measured shape for this client's SNI and ALPN,
// waiting briefly if the measurement is still running.
func realityRecordShape(config *RealityConfig, sni string, protos []string) []int {
	key := realityShapeKey(config.Dest, sni, realityALPNClass(protos))
	deadline := time.Now().Add(realityShapeWait)
	for {
		v, ok := realityShapes.Load(key)
		if !ok {
			// Nothing is measuring this key, so there is nothing to wait for.
			return nil
		}
		if lens, done := v.([]int); done {
			return lens
		}
		if !time.Now().Before(deadline) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// writeRealityShapeRecords emits one record per measured length. The sealed
// plaintext is a single content-type byte followed by zeros, which unwraps to a
// zero-length application_data fragment — the peer's record layer skips it.
func (hs *realityServerHandshakeStateTLS13) writeRealityShapeRecords(lens []int) {
	c := hs.c
	sealer, ok := c.out.cipher.(aead)
	if !ok {
		return
	}
	// Header, at least the inner content type, and the authentication tag.
	min := recordHeaderLen + 1 + sealer.Overhead()
	for _, n := range lens {
		if n < min || n > int(realitySize) {
			continue
		}
		buf := make([]byte, n-sealer.Overhead())
		buf[0] = byte(recordTypeApplicationData)
		binary.BigEndian.PutUint16(buf[1:3], VersionTLS12)
		binary.BigEndian.PutUint16(buf[3:5], uint16(n-recordHeaderLen))
		buf[recordHeaderLen] = byte(recordTypeApplicationData)
		record := sealer.Seal(buf[:recordHeaderLen], c.out.seq[:], buf[recordHeaderLen:], buf[:recordHeaderLen])
		c.out.incSeq()
		if _, err := c.write(record); err != nil {
			return
		}
	}
}
