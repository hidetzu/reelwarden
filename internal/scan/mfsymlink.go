package scan

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
)

// Minshall–French symlinks are how the Linux CIFS client (mount option
// mfsymlinks), macOS and some NAS clients store a symlink on an SMB server
// that cannot hold real ones: a regular file of exactly 1067 bytes,
//
//	"XSym\n" + 4-digit length + "\n" + 32 hex MD5 of the target + "\n" +
//	target + "\n", padded with spaces.
//
// Without mfsymlinks on the reading side they appear as ordinary files.
const (
	mfSymlinkSize   = 1067
	mfSymlinkMaxLen = 1024
)

// parseMFSymlink returns the link target if data is a Minshall–French
// symlink that the Linux CIFS client would follow (parse_mf_symlink in
// fs/smb/client/link.c): exact size, "XSym\n" and a length of up to 1024,
// and an MD5 of the target whose first 17 hex digits match. The kernel does
// not check the separators, so neither does this; accepting what the
// kernel accepts means no link it would follow is missed. A file whose
// checksum does not match is not a link.
func parseMFSymlink(data []byte) (string, bool) {
	if len(data) != mfSymlinkSize || string(data[:5]) != "XSym\n" {
		return "", false
	}
	n, ok := scanLength(data[5:])
	if !ok || n <= 0 || n > mfSymlinkMaxLen || 43+n > len(data) {
		return "", false
	}
	raw := data[43 : 43+n]
	sum := md5.Sum(raw) // over the stated length, as the kernel hashes it
	if hex.EncodeToString(sum[:])[:17] != string(data[10:27]) {
		return "", false
	}
	// The kernel keeps the target only up to the first NUL (kstrndup).
	if i := bytes.IndexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	if len(raw) == 0 {
		return "", false
	}
	return string(raw), true
}

// scanLength reads the length field like the kernel's sscanf("%04u"):
// leading white space is skipped, then up to four decimal digits; no sign.
func scanLength(b []byte) (int, bool) {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r' || b[i] == '\v' || b[i] == '\f') {
		i++
	}
	n, digits := 0, 0
	for i < len(b) && digits < 4 && b[i] >= '0' && b[i] <= '9' {
		n = n*10 + int(b[i]-'0')
		i++
		digits++
	}
	return n, digits > 0
}

// readMFSymlink reads path and parses it if it has the exact size.
func readMFSymlink(path string, size int64) (string, bool) {
	if size != mfSymlinkSize {
		return "", false
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	buf := make([]byte, mfSymlinkSize+1)
	n, err := io.ReadFull(f, buf)
	if err != io.ErrUnexpectedEOF || n != mfSymlinkSize {
		return "", false
	}
	return parseMFSymlink(buf[:n])
}
