package essh

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/google/gopacket"
)

// maxVersionStringBytes is the maximum number of bytes that we'll
// accept as a version string. RFC 4253 section 4.2 limits this at 255
// chars
const maxVersionStringBytes = 255

type ESSHBannerRecord struct {
	ProtoVersion    string `json:"proto_version"`
	SoftwareVersion string `json:"software_version"`
}

// decodeFromBytes decodes the version string as specified by RFC 4253, section 4.2, som a slice of bytes.
// SSH Protocol version exchange, as given by 4.2:
//
//   SSH-<protoversion>-<softwareversion> <space> <comments...> CR LF
//
func (s *ESSHBannerRecord) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) > maxVersionStringBytes {
		return fmt.Errorf("Invalid version string, it should be less than %d characters including <CR><LF>",
			maxVersionStringBytes,
		)
	}

	versionString := make([]byte, 0, 64)
	var ok bool
	var buf [1]byte

	r := bytes.NewReader(data)

	for length := 0; length < maxVersionStringBytes; length++ {
		_, err := io.ReadFull(r, buf[:])
		if err != nil {
			return err
		}
		// The RFC says that the version should be terminated with \r\n
		// but several SSH servers actually only send a \n.
		if buf[0] == '\n' {
			if !bytes.HasPrefix(versionString, []byte("SSH-")) {
				// RFC 4253 says we need to ignore all version string lines
				// except the one containing the SSH version (provided that
				// all the lines do not exceed 255 bytes in total).
				versionString = versionString[:0]
				continue
			}
			ok = true
			break
		}

		// non ASCII chars are disallowed, but we are lenient,
		// since Go doesn't use null-terminated strings.

		// The RFC allows a comment after a space, however,
		// all of it (version and comments) goes into the
		// session hash.
		versionString = append(versionString, buf[0])
	}

	if !ok {
		return errors.New("invalid version string")
	}

	// There might be a '\r' on the end which we should remove.
	if len(versionString) > 0 && versionString[len(versionString)-1] == '\r' {
		versionString = versionString[:len(versionString)-1]
	}

	lvs := len(versionString)

	// First 4 bytes are "SSH-", we skip these.
	bptr := 4

	// Next is the protocol version before the next `-`
	p := bytes.Index(data[bptr:], []byte("-"))
	if p < 1 {
		return errors.New("invalid version string: length of protocol version is too short")
	}
	s.ProtoVersion = string(data[bptr:(bptr + p)])
	bptr += p
	bptr += 1 // skip -

	// Next is the software version before either a space or end of versionstring.
	sp := bytes.Index(data[bptr:], []byte{0x20})
	if sp < 0 {
		// No comment given
		s.SoftwareVersion = string(data[bptr:lvs])
	} else {
		// Software version is everything before the space.
		s.SoftwareVersion = string(data[bptr:(bptr + sp)])
	}

	return nil
}

// Sends and receives a version line.  The versionLine string should
// be US ASCII, start with "SSH-2.0-", and should not include a
// newline. exchangeVersions returns the other side's version line.
func exchangeVersions(rw io.ReadWriter, versionLine []byte) (them []byte, err error) {
	// Contrary to the RFC, we do not ignore lines that don't
	// start with "SSH-2.0-" to make the library usable with
	// nonconforming servers.
	for _, c := range versionLine {
		// The spec disallows non US-ASCII chars, and
		// specifically forbids null chars.
		if c < 32 {
			return nil, errors.New("ssh: junk character in version line")
		}
	}
	if _, err = rw.Write(append(versionLine, '\r', '\n')); err != nil {
		return
	}

	them, err = readVersion(rw)
	return them, err
}

// Read version string as specified by RFC 4253, section 4.2.
func readVersion(r io.Reader) ([]byte, error) {
	versionString := make([]byte, 0, 64)
	var ok bool
	var buf [1]byte

	for length := 0; length < maxVersionStringBytes; length++ {
		_, err := io.ReadFull(r, buf[:])
		if err != nil {
			return nil, err
		}
		// The RFC says that the version should be terminated with \r\n
		// but several SSH servers actually only send a \n.
		if buf[0] == '\n' {
			if !bytes.HasPrefix(versionString, []byte("SSH-")) {
				// RFC 4253 says we need to ignore all version string lines
				// except the one containing the SSH version (provided that
				// all the lines do not exceed 255 bytes in total).
				versionString = versionString[:0]
				continue
			}
			ok = true
			break
		}

		// non ASCII chars are disallowed, but we are lenient,
		// since Go doesn't use null-terminated strings.

		// The RFC allows a comment after a space, however,
		// all of it (version and comments) goes into the
		// session hash.
		versionString = append(versionString, buf[0])
	}

	if !ok {
		return nil, errors.New("ssh: overflow reading version string")
	}

	// There might be a '\r' on the end which we should remove.
	if len(versionString) > 0 && versionString[len(versionString)-1] == '\r' {
		versionString = versionString[:len(versionString)-1]
	}
	return versionString, nil
}
