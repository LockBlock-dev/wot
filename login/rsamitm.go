package login

// RSA MITM for the LoginApp login path (wotproxy explicit mode).
//
// The game encrypts LogOnParams with the RSA key named by its host
// entry's public_key_path (res/loginapp_wot.pubkey for every EU host,
// CUSTOM included). Pointing just the CUSTOM entry at our own key
// (mods/custom-server-mod) makes the game encrypt to us: the proxy
// RSA-decrypts the login params, learns the per-login Blowfish key,
// re-encrypts the IDENTICAL cleartext to the real server key, and
// forwards. Lengths never change (both keys 2048-bit → same chunk
// geometry), the server sees byte-equivalent plaintext, and the 232B
// rewrite path finally gets its key live instead of from heap scans.
//
// Anything unexpected forwards the ORIGINAL datagram untouched
// (fail-open): wrong shape, unknown message, decrypt failure, chunk
// mismatch. Key bytes never reach logs (hashes only, at the call
// site — this package returns values, it does not print them).
//
// Wire refs: login#1 534 B / login#2 728 B framing (login.go,
// NETWORK_PROTOCOL.md §§3-5); RSA-OAEP-SHA1 chunking partSize =
// keySize-42 (logonparams.go); LogOnParams layout IDA sub_140E6E210.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // game-mandated OAEP-SHA1
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
)

// LogOnParams is a parsed LogOnParams cleartext: flags u8, four packed
// strings (username/password/encryptionKey/clientContext), the MD5
// digest (present iff flags&1 — the game always sets HAS_ALL=1, IDA
// sub_140E6C6E4 mov r8b,1) and the trailing PoW nonce u32.
type LogOnParams struct {
	Flags     byte
	Username  string
	Password  string
	EncKey    string
	ClientCtx string
	Digest    [16]byte
	Nonce     uint32
}

// parseLogOnParamsClear is the inverse of buildLogOnParamsClear.
func parseLogOnParamsClear(clear []byte) (LogOnParams, error) {
	var p LogOnParams
	if len(clear) < 1 {
		return p, fmt.Errorf("wotlogin: logonparams too short (%d B)", len(clear))
	}
	p.Flags = clear[0]
	rest := clear[1:]
	dsts := []*string{&p.Username, &p.Password, &p.EncKey, &p.ClientCtx}
	for _, dst := range dsts {
		s, n, err := consumePackedString(rest)
		if err != nil {
			return p, fmt.Errorf("wotlogin: logonparams field: %w", err)
		}
		*dst = s
		rest = rest[n:]
	}
	if p.Flags&1 != 0 {
		if len(rest) < 16 {
			return p, fmt.Errorf("wotlogin: logonparams missing digest (%d B left)", len(rest))
		}
		copy(p.Digest[:], rest[:16])
		rest = rest[16:]
	}
	if len(rest) < 4 {
		return p, fmt.Errorf("wotlogin: logonparams missing nonce (%d B left)", len(rest))
	}
	p.Nonce = binary.LittleEndian.Uint32(rest[:4])
	rest = rest[4:]
	if len(rest) != 0 {
		return p, fmt.Errorf("wotlogin: logonparams %d trailing bytes", len(rest))
	}
	return p, nil
}

// LoadRSAPrivateKey parses a PEM PKCS#8 or PKCS#1 RSA private key file.
// The path comes from a flag; the key itself never leaves this package
// except as *rsa.PrivateKey (no logging here by design).
func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("wotlogin: privkey read: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("wotlogin: no PEM block in %s", path)
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := k.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("wotlogin: PKCS#8 key in %s is not RSA", path)
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("wotlogin: privkey parse %s: %w", path, err)
	}
	return rsaKey, nil
}

// decryptChunks runs RSA-OAEP-SHA1 over whole keySize blocks.
func decryptChunks(cipher []byte, priv *rsa.PrivateKey) ([]byte, error) {
	keySize := priv.Size()
	if len(cipher) == 0 || len(cipher)%keySize != 0 {
		return nil, fmt.Errorf("wotlogin: RSA chunks misaligned (%d B, key %d)", len(cipher), keySize)
	}
	out := make([]byte, 0, len(cipher)/keySize*(keySize-42))
	for off := 0; off < len(cipher); off += keySize {
		blk, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, cipher[off:off+keySize], nil) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("wotlogin: RSA decrypt block @%d: %w", off, err)
		}
		out = append(out, blk...)
	}
	return out, nil
}

// encryptChunks runs RSA-OAEP-SHA1 with partSize = keySize-42 chunking
// (the layout encryptLogOnParams uses against the live key).
func encryptChunks(clear []byte, pub *rsa.PublicKey) ([]byte, error) {
	keySize := pub.Size()
	partSize := keySize - 41 - 1
	if partSize <= 0 {
		return nil, fmt.Errorf("wotlogin: RSA key too small (%d bytes)", keySize)
	}
	out := make([]byte, 0, ((len(clear)+partSize-1)/partSize)*keySize)
	for off := 0; off < len(clear); off += partSize {
		end := off + partSize
		if end > len(clear) {
			end = len(clear)
		}
		blk, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, clear[off:end], nil) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("wotlogin: RSA encrypt: %w", err)
		}
		out = append(out, blk...)
	}
	return out, nil
}

// MitmLoginParams runs one params body through the MITM: decrypt with
// the key the game used (ours, via the CUSTOM public_key_path), parse
// the cleartext, re-encrypt the IDENTICAL bytes to the server key.
// Returns the replacement body (same length — equal key sizes) and the
// parsed params (EncKey feeds the 232B rewrite). Any failure errors
// and the caller forwards the original datagram.
func MitmLoginParams(cipherParams []byte, mitmPriv *rsa.PrivateKey, srvPub *rsa.PublicKey) (reenc []byte, params LogOnParams, err error) {
	clear, err := decryptChunks(cipherParams, mitmPriv)
	if err != nil {
		return nil, LogOnParams{}, err
	}
	params, err = parseLogOnParamsClear(clear)
	if err != nil {
		return nil, LogOnParams{}, err
	}
	reenc, err = encryptChunks(clear, srvPub)
	if err != nil {
		return nil, LogOnParams{}, err
	}
	if len(reenc) != len(cipherParams) {
		return nil, LogOnParams{}, fmt.Errorf("wotlogin: MITM length drift %d -> %d", len(cipherParams), len(reenc))
	}
	return reenc, params, nil
}

// extractLoginParams locates the login message (ID=0) in a C>S LoginApp
// datagram via the reqOff footer (covers login#1 single-msg and login#2
// challengeResponse+login shapes) and returns the params body with its
// bounds plus the isEncrypted flag. Rebuild splices a same-length
// replacement back into a datagram copy.
func extractLoginParams(pkt []byte) (params []byte, start, end int, encrypted bool, err error) {
	if len(pkt) < 4+2+3+6+4+1+2 {
		return nil, 0, 0, false, fmt.Errorf("wotlogin: datagram too short (%d B)", len(pkt))
	}
	if pkt[4] != 0x01 || pkt[5] != 0x00 {
		return nil, 0, 0, false, fmt.Errorf("wotlogin: not a C>S request (flags %02x %02x)", pkt[4], pkt[5])
	}
	reqOff := int(binary.LittleEndian.Uint16(pkt[len(pkt)-2:]))
	msg := 4 + reqOff
	if msg+3+6+4+1 > len(pkt) {
		return nil, 0, 0, false, fmt.Errorf("wotlogin: login msg out of bounds (off %d, len %d)", reqOff, len(pkt))
	}
	if pkt[msg] != msgLogin {
		return nil, 0, 0, false, fmt.Errorf("wotlogin: first request ID %02x (want login 00)", pkt[msg])
	}
	dataLen := int(binary.LittleEndian.Uint16(pkt[msg+1 : msg+3]))
	body := msg + 3 + 6 // replyID(4) + nextOff(2)
	if body+dataLen > len(pkt) {
		return nil, 0, 0, false, fmt.Errorf("wotlogin: login data out of bounds (%d+%d > %d)", body, dataLen, len(pkt))
	}
	if dataLen < 4+1 {
		return nil, 0, 0, false, fmt.Errorf("wotlogin: login data too short (%d B)", dataLen)
	}
	// version[4] + isEncrypted[1] + params
	ps, pe := body+4+1, body+dataLen
	return pkt[ps:pe], ps, pe, pkt[body+4] == 0x01, nil
}

// MitmLoginParamsFromPacket decrypts the RSA-encrypted LogOnParams out
// of one captured C>S LoginApp datagram with our MITM private key.
// Offline census helper (version-drift checks on username/clientContext
// keys across client builds): values stay in the returned struct, and
// callers must log keys/lengths only, never secrets.
func MitmLoginParamsFromPacket(pkt []byte, mitmPriv *rsa.PrivateKey) (LogOnParams, error) {
	cipher, _, _, encrypted, err := extractLoginParams(pkt)
	if err != nil {
		return LogOnParams{}, err
	}
	if !encrypted {
		return LogOnParams{}, fmt.Errorf("wotlogin: login params not encrypted")
	}
	clear, err := decryptChunks(cipher, mitmPriv)
	if err != nil {
		return LogOnParams{}, err
	}
	return parseLogOnParamsClear(clear)
}

// MitmPacket inspects one C>S LoginApp datagram. If it carries a login
// message RSA-encrypted to mitmPriv, it returns a rebuilt datagram
// (same bytes except re-encrypted params) plus the login Blowfish key.
// If the login message is plaintext (isEncrypted=0), it returns
// (nil, key, nil): forward the original, but the key is learned. Else
// (nil, "", nil): not a login — forward untouched.
func MitmPacket(pkt []byte, mitmPriv *rsa.PrivateKey, srvPub *rsa.PublicKey) (out []byte, encKey string, err error) {
	params, ps, pe, encrypted, err := extractLoginParams(pkt)
	if err != nil {
		return nil, "", err
	}
	if !encrypted {
		clear := append([]byte(nil), params...)
		p, err := parseLogOnParamsClear(clear)
		if err != nil {
			return nil, "", err
		}
		return nil, p.EncKey, nil
	}
	if len(params)%mitmPriv.Size() != 0 {
		return nil, "", fmt.Errorf("wotlogin: RSA body %d B misaligned to MITM key %d", len(params), mitmPriv.Size())
	}
	reenc, p, err := MitmLoginParams(params, mitmPriv, srvPub)
	if err != nil {
		return nil, "", err
	}
	out = append([]byte(nil), pkt...)
	copy(out[ps:pe], reenc)
	return out, p.EncKey, nil
}
