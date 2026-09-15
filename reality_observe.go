package tls

import "time"

// RealityOutcome is how RealityServer finished with one inbound connection.
type RealityOutcome uint8

const (
	// RealityAuthenticated means the client proved it holds the server's
	// REALITY identity and the handshake completed; the connection is handed to
	// the listener's Accept.
	RealityAuthenticated RealityOutcome = iota + 1
	// RealityFallback means the connection was not accepted as a REALITY client
	// and its traffic was relayed to Dest, so the peer saw Dest itself.
	RealityFallback
	// RealityFailed means the connection was neither accepted nor fully relayed:
	// Dest could not be reached, or an authenticated handshake broke part-way.
	RealityFailed
)

func (o RealityOutcome) String() string {
	switch o {
	case RealityAuthenticated:
		return "authenticated"
	case RealityFallback:
		return "fallback"
	case RealityFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// RealityObservation describes one inbound connection once RealityServer has
// decided what it was. It carries no key material or payload, so it is safe to
// record in production logs; RealityConfig.Log, by contrast, is a debug stream
// that includes part of the derived auth key and must not be enabled there.
//
// Reason is a short stable token explaining a non-authenticated outcome:
//
//	dest_dial_failed         Dest could not be dialed
//	client_hello_invalid     no parseable ClientHello
//	dest_spoke_first         Dest sent bytes before a decision was reached
//	not_tls13                ClientHello did not negotiate TLS 1.3
//	server_name_not_allowed  SNI is not one of ServerNames
//	no_x25519_key_share      no usable X25519 key share to authenticate with
//	key_exchange_error       deriving the auth key failed
//	not_reality_client       session_id did not decrypt: an ordinary TLS client
//	client_version_rejected  REALITY client version outside Min/MaxClientVer
//	client_time_rejected     client clock outside MaxTimeDiff
//	short_id_unknown         REALITY client with a short id not in ShortIds
//	dest_server_hello_invalid Dest's ServerHello could not be mirrored
//	server_handshake_error   authenticated, but our side of the handshake failed
//	client_finished_error    authenticated, but the client Finished was bad
//	incomplete               any other path that did not complete
//
// Reason is empty for RealityAuthenticated.
type RealityObservation struct {
	RemoteAddr string
	ServerName string
	Outcome    RealityOutcome
	Reason     string
	Duration   time.Duration
}
