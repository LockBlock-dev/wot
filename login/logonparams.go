package login

import (
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// appendPackedString writes a BigWorld packed string: 1-byte length for
// len < 255, else 0xFF + 3-byte length, then raw bytes.
func appendPackedString(out []byte, s string) []byte {
	if len(s) >= 255 {
		out = append(out, 0xFF, byte(len(s)), byte(len(s)>>8), byte(len(s)>>16))
	} else {
		out = append(out, byte(len(s)))
	}
	return append(out, s...)
}

// consumePackedString is the inverse of appendPackedString.
func consumePackedString(b []byte) (string, int, error) {
	if len(b) < 1 {
		return "", 0, errors.New("wotlogin: truncated string length")
	}
	ln := int(b[0])
	off := 1
	if ln == 0xFF {
		if len(b) < 4 {
			return "", 0, errors.New("wotlogin: truncated long string length")
		}
		ln = int(b[1]) | int(b[2])<<8 | int(b[3])<<16
		off = 4
	}
	if len(b) < off+ln {
		return "", 0, errors.New("wotlogin: truncated string body")
	}
	return string(b[off : off+ln]), off + ln, nil
}

// token2Middle extracts the stable middle segment of a token2
// `{accountID}:{stable}:{rotating}` (lengths unchecked — split only).
// The middle is machine-bound stable across logins while the tail
// rotates, so equality of middles (never values) tests whether two
// sessions share the same machine binding.
func token2Middle(token2 string) (string, bool) {
	parts := splitColon(token2)
	if len(parts) < 3 {
		return "", false
	}
	return parts[1], true
}

func splitColon(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ':' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	return append(out, cur)
}

// Token2FamilyMatch reports whether token2's stable middle equals the
// genuine reference middle from captures/CE.txt — a machine-binding
// check that logs a boolean only, never values. Fail-silent (false on
// any error); only meaningful on local runs from the repo layout.
func Token2FamilyMatch(token2 string) bool {
	mid, ok := token2Middle(token2)
	if !ok {
		return false
	}
	ref, ok := ceReferenceMiddle()
	if !ok {
		return false
	}
	return mid == ref
}

// ceReferenceMiddle scrapes the token2 from the genuine-client log line
// in captures/CE.txt (`'token2': u'...'`).
func ceReferenceMiddle() (string, bool) {
	raw, err := os.ReadFile("../../captures/CE.txt")
	if err != nil {
		return "", false
	}
	s := string(raw)
	i := strings.Index(s, "token2")
	if i < 0 {
		return "", false
	}
	rest := s[i:]
	for _, q := range []string{"u'", `u"`} {
		if j := strings.Index(rest, q); j >= 0 {
			rest = rest[j+len(q):]
			k := strings.Index(rest, q[1:])
			if k > 0 {
				if m, ok := token2Middle(rest[:k]); ok {
					return m, true
				}
			}
			break
		}
	}
	return "", false
}

// pwdToken mirrors client_common/pwd_token.py: identity, except the CN/VN
// locales which send md5 hex of the password.
func pwdToken(lang, password string) string {
	if lang == "cn" || lang == "vn" {
		sum := md5.Sum([]byte(password)) //nolint:gosec // game-mandated md5
		return hex.EncodeToString(sum[:])
	}
	return password
}

// RSAPublicKey wraps the LoginApp RSA-2048 key (res/loginapp_wot.pubkey).
type RSAPublicKey struct {
	key *rsa.PublicKey
}

// LoadRSAPublicKey parses a PEM PKIX public key file.
func LoadRSAPublicKey(path string) (*RSAPublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("wotlogin: pubkey read: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("wotlogin: no PEM block in %s", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("wotlogin: pubkey parse: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("wotlogin: not an RSA key in %s", path)
	}
	return &RSAPublicKey{key: rsaPub}, nil
}

// Public exposes the inner key for MITM re-encryption (wotproxy).
func (k *RSAPublicKey) Public() *rsa.PublicKey {
	return k.key
}

// Size reports the RSA modulus in bytes (chunk geometry follows it).
func (k *RSAPublicKey) Size() int {
	return k.key.Size()
}

// buildLogOnParamsClear assembles the LogOnParams cleartext: flags u8,
// username/password/encryptionKey/clientContext packed strings (IDA
// sub_140E6E210 streams flags + four strings at +24/+56/+88/+120, the
// MD5 digest at +156 when flags&1, and the nonce u32 at +152).
// Content per EU 1.27.1 connection_mgr.__setConnectionData (username =
// JSON {login, session(md5), temporary, auth_method, publication,
// auth_realm, ...}, password emptied for token2) and
// gui/login/manager.initiateLogin (clientContext = JSON
// {lang_id, publication}).
func buildLogOnParamsClear(cfg Config) []byte {
	return buildLogOnParamsClearWithProvider(cfg, ProviderForConfig(cfg))
}

// buildLogOnParamsClearWithProvider renders the same cleartext with
// the identity half supplied by auth (Client path). Byte-identical to
// buildLogOnParamsClear for consistent configs (auth_method matching
// the token keys present — the only shape the genuine client sends).
func buildLogOnParamsClearWithProvider(cfg Config, auth AuthProvider) []byte {
	clear := []byte{0x01} // HAS_ALL; digest follows
	clear = appendPackedString(clear, auth.Username())
	clear = appendPackedString(clear, auth.Password(cfg.Lang))
	clear = appendPackedString(clear, cfg.BlockKey)
	clear = appendPackedString(clear, cfg.ClientContext)
	// Defs digest: MD5 over the entity definitions (OSE
	// ServerConnection::logOnBegin: pParams->digest(this->digest())).
	// The server rejects mismatches (status 70); zeros only prove framing.
	clear = append(clear, cfg.Digest[:]...)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], cfg.Nonce())
	clear = append(clear, tmp[:]...)
	return clear
}

// encryptLogOnParams builds the LogOnParams cleartext and RSA-OAEP-SHA1
// encrypts it in chunks of partSize = keySize - RSA_PADDING - 1 bytes in,
// keySize bytes out (PublicKeyCipher::encrypt, OSE: RSA_PADDING=41, the
// "magic 41" of RSA_public_encrypt OAEP overhead). partSize MUST follow
// the loaded key: the wire forces non-2048 login keys (506-B params =
// 2x253 or 1x506, never k x 256), so a hardcoded 214 would over-chunk
// (or fail to encrypt at all) against the live key.
func encryptLogOnParams(cfg Config, pubkey *RSAPublicKey) ([]byte, error) {
	return encryptLogOnParamsWithProvider(cfg, ProviderForConfig(cfg), pubkey)
}

// encryptLogOnParamsWithProvider builds the LogOnParams cleartext via
// auth and RSA-OAEP-SHA1 encrypts it in chunks of partSize = keySize -
// RSA_PADDING - 1 bytes in, keySize bytes out (PublicKeyCipher::encrypt,
// OSE: RSA_PADDING=41, the "magic 41" of RSA_public_encrypt OAEP
// overhead). partSize MUST follow the loaded key: the wire forces
// non-2048 login keys (506-B params = 2x253 or 1x506, never k x 256),
// so a hardcoded 214 would over-chunk (or fail to encrypt at all)
// against the live key.
func encryptLogOnParamsWithProvider(cfg Config, auth AuthProvider, pubkey *RSAPublicKey) ([]byte, error) {
	clear := buildLogOnParamsClearWithProvider(cfg, auth)
	// Lengths only, never values: proves which fields went on the wire
	// (e.g. a stale CLIENT_CONTEXT override in the .env shows up as a
	// short ctx here) without leaking secrets.
	cfg.debugf("logonparams clear=%d (user=%d pwd=%d key=%d ctx=%d) chunks=%d",
		len(clear), len(auth.Username()), len(auth.Password(cfg.Lang)),
		len(cfg.BlockKey), len(cfg.ClientContext),
		(len(clear)+pubkey.key.Size()-42-1)/(pubkey.key.Size()-42))

	keySize := pubkey.key.Size() // RSA modulus in bytes (256 for 2048-bit)
	partSize := keySize - 41 - 1
	if partSize <= 0 {
		return nil, fmt.Errorf("wotlogin: RSA key too small (%d bytes)", keySize)
	}
	out, err := encryptChunks(clear, pubkey.key)
	if err != nil {
		return nil, err
	}
	return out, nil
}
