package login

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/blowfish"
)

// Encryption spans Blowfish-ECB from golang.org/x/crypto/blowfish plus
// BigWorld's own framing, ported from EncryptionFilter in
// src/lib/network/encryption_filter.cpp (2.0.1): a chaining XOR over
// plaintext blocks (anti-replay, v49), a trailing ENCRYPTION_MAGIC
// (0xdeadbeef) and a wastage pad byte so the ciphertext is a multiple
// of the 8-byte block size.

const (
	bfBlockSize = 8
	bfMagic     = 0xdeadbeef
)

// decryptBlowfish reverses one EncryptionFilter::decrypt pass: Blowfish-ECB
// decrypt every 8-byte block, then XOR all but the first with the previous
// PLAINTEXT block (mirrors encrypt, which XORs each plaintext block with
// its plaintext predecessor before encrypting — 2.0.1
// encryption_filter.cpp, and the 2.4.0 fork's own encrypt loop, IDA
// sub_142AD67F0, was verified to use the same plaintext chaining), then
// validates the trailing ENCRYPTION_MAGIC (0xdeadbeef) and wastage pad.
// The magic/wastage trailer belongs to the CHANNEL path: the fork checks
// it in EncryptionFilter::recv (IDA sub_142AD6570), so this function is
// for BaseApp channel packets. The LOGIN reply path (decryptStream +
// readReplyRecordFromStream, fork onReply via sub_142AD6320) performs NO
// magic check — it just needs ≥12 B — so login must use decryptLogin
// below, never this.
func decryptBlowfish(key string, src []byte) ([]byte, error) {
	if len(src)%bfBlockSize != 0 {
		return nil, fmt.Errorf("wotlogin: blowfish input %d not a multiple of 8", len(src))
	}
	c, err := blowfish.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("wotlogin: blowfish key: %w", err)
	}
	dst := make([]byte, len(src))
	for i := 0; i < len(src); i += bfBlockSize {
		c.Decrypt(dst[i:i+bfBlockSize], src[i:i+bfBlockSize])
	}
	var prev []byte
	for i := 0; i < len(dst); i += bfBlockSize {
		if prev != nil {
			for j := 0; j < bfBlockSize; j++ {
				dst[i+j] ^= prev[j]
			}
		}
		prev = dst[i : i+bfBlockSize : i+bfBlockSize]
	}
	// Validate magic + wastage trailer: [magic u32][wastage u8], where
	// wastage (1..8) counts itself plus magic as strip length.
	if len(dst) < 5 {
		return nil, fmt.Errorf("wotlogin: blowfish output too short")
	}
	wastage := int(dst[len(dst)-1])
	magic := binary.LittleEndian.Uint32(dst[len(dst)-1-4 : len(dst)-1])
	if magic != bfMagic {
		return nil, fmt.Errorf("wotlogin: bad magic %08x", magic)
	}
	if wastage < 1 || wastage > bfBlockSize || wastage+4 > len(dst) {
		return nil, fmt.Errorf("wotlogin: bad wastage %d", wastage)
	}
	return dst[:len(dst)-(wastage+4)], nil
}

// encryptBlowfish is the mirror of decryptBlowfish (EncryptionFilter::encrypt,
// IDA sub_142AD67F0): XOR-chain plaintext blocks, Blowfish-ECB encrypt,
// then zero-pad + ENCRYPTION_MAGIC u32 LE + wastage byte so the total is a
// multiple of 8 (wastage 1..8 = pad length + 1; the magic sits directly
// before the final wastage byte — verified against live 36B replies,
// whose 32B bodies strip with wastage=5).
func encryptBlowfish(key string, src []byte) ([]byte, error) {
	c, err := blowfish.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("wotlogin: blowfish key: %w", err)
	}
	padlen := (8 - ((len(src) + 5) % 8)) % 8
	wastage := padlen + 1
	plain := make([]byte, 0, len(src)+padlen+5)
	plain = append(plain, src...)
	plain = append(plain, bytes.Repeat([]byte{0}, padlen)...)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], bfMagic)
	plain = append(plain, tmp[:]...)
	plain = append(plain, byte(wastage))
	dst := make([]byte, len(plain))
	var prev []byte
	for i := 0; i < len(plain); i += bfBlockSize {
		blk := append([]byte{}, plain[i:i+bfBlockSize]...)
		if prev != nil {
			for j := 0; j < bfBlockSize; j++ {
				blk[j] ^= prev[j]
			}
		}
		c.Encrypt(dst[i:i+bfBlockSize], blk)
		prev = plain[i : i+bfBlockSize : i+bfBlockSize]
	}
	return dst, nil
}

// tryZlib reports whether blob zlib-decodes (TEMPORARY probe for a
// compression layer in the login reply; returns decoded bytes, never
// logged). Capped at 1 MiB against zip bombs.
func tryZlib(blob []byte) ([]byte, bool) {
	r, err := zlib.NewReader(bytes.NewReader(blob))
	if err != nil {
		return nil, false
	}
	defer r.Close()
	plain, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil || len(plain) == 0 {
		return nil, false
	}
	return plain, true
}

// decryptSession decrypts a LOGGED_ON reply body with the session block
// cipher (LogOnParams.encryptionKey) and parses LoginReplyRecord:
// serverAddr (ip 4 raw + port 2 raw + salt u16) + sessionKey u32,
// then the optional server message string. With an empty key
// (BLOCK_KEY_EMPTY) the server may skip encryption: parse plaintext.
func decryptSession(blob []byte, blockKey string) (Session, error) {
	if blockKey == "" {
		return parseSessionRecord(blob)
	}
	clear, err := decryptLogin(string(blockKey), blob)
	if err != nil {
		return Session{}, err
	}
	return parseSessionRecord(clear)
}

// decryptLogin runs the login-reply decrypt: ECB + plaintext chain with NO
// magic/wastage validation, mirroring decryptStream as used by the login
// onReply path (the magic trailer is a channel-path concern, checked in
// recv, not here).
func decryptLogin(key string, src []byte) ([]byte, error) {
	if len(src)%bfBlockSize != 0 {
		return nil, fmt.Errorf("wotlogin: blowfish input %d not a multiple of 8", len(src))
	}
	c, err := blowfish.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("wotlogin: blowfish key: %w", err)
	}
	dst := make([]byte, len(src))
	for i := 0; i < len(src); i += bfBlockSize {
		c.Decrypt(dst[i:i+bfBlockSize], src[i:i+bfBlockSize])
	}
	var prev []byte
	for i := 0; i < len(dst); i += bfBlockSize {
		if prev != nil {
			for j := 0; j < bfBlockSize; j++ {
				dst[i+j] ^= prev[j]
			}
		}
		prev = dst[i : i+bfBlockSize : i+bfBlockSize]
	}
	return dst, nil
}

// encryptLogin is the mirror of decryptLogin for the login-reply path:
// XOR-chain plaintext blocks (first block raw), Blowfish-ECB encrypt,
// NO magic/wastage trailer (channel-path framing does not apply here).
// Needed to re-emit a modified LOGGED_ON body (see rewrite.go); the
// server accepts it because it decrypts with the same stream.
func encryptLogin(key string, src []byte) ([]byte, error) {
	if len(src)%bfBlockSize != 0 {
		return nil, fmt.Errorf("wotlogin: blowfish input %d not a multiple of 8", len(src))
	}
	c, err := blowfish.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("wotlogin: blowfish key: %w", err)
	}
	dst := make([]byte, len(src))
	var prev []byte
	for i := 0; i < len(src); i += bfBlockSize {
		blk := append([]byte{}, src[i:i+bfBlockSize]...)
		if prev != nil {
			for j := 0; j < bfBlockSize; j++ {
				blk[j] ^= prev[j]
			}
		}
		c.Encrypt(dst[i:i+bfBlockSize], blk)
		prev = src[i : i+bfBlockSize : i+bfBlockSize]
	}
	return dst, nil
}

func parseSessionRecord(clear []byte) (Session, error) {
	if len(clear) < 8+4 {
		return Session{}, fmt.Errorf("wotlogin: reply record too short (%d B)", len(clear))
	}
	var s Session
	s.ServerAddr = net.IP(append([]byte{}, clear[0:4]...))
	s.ServerPort = binary.BigEndian.Uint16(clear[4:6]) // raw = network order
	s.SessionKey = binary.LittleEndian.Uint32(clear[8:12])
	if len(clear) > 12 {
		msg, _, err := consumePackedString(clear[12:])
		if err == nil {
			s.ServerMsg = msg
		}
	}
	return s, nil
}
