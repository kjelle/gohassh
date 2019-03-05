package essh

import (
	"bytes"
	"errors"
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
// It returns how much of the data that was processed.
func (s *ESSHBannerRecord) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) (int, error) {
	/*	if len(data) > maxVersionStringBytes {
		return 0, fmt.Errorf("Invalid version string, it should be less than %d characters including <CR><LF>",
			maxVersionStringBytes,
		)
	}*/

	versionString := make([]byte, 0, 64)
	var ok bool
	var buf [1]byte
	crlf := 0

	r := bytes.NewReader(data)

	for length := 0; length < maxVersionStringBytes; length++ {
		_, err := io.ReadFull(r, buf[:])
		if err != nil {
			return 0, err
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
			crlf += 1
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
		return 0, errors.New("invalid version string")
	}

	// There might be a '\r' on the end which we should remove.
	if len(versionString) > 0 && versionString[len(versionString)-1] == '\r' {
		versionString = versionString[:len(versionString)-1]
		crlf += 1
	}

	lvs := len(versionString)

	// First 4 bytes are "SSH-", we skip these.
	bptr := 4

	// Next is the protocol version before the next `-`
	p := bytes.Index(data[bptr:], []byte("-"))
	if p < 1 {
		return 0, errors.New("invalid version string: length of protocol version is too short")
	}
	s.ProtoVersion = string(data[bptr:(bptr + p)])
	bptr += p
	bptr += 1 // skip -

	// Next is the software version before either a space or end of versionstring.
	sp := bytes.Index(data[bptr:], []byte{0x20})
	if sp < 0 {
		// No comment given
		s.SoftwareVersion = string(data[bptr:lvs])
		bptr = lvs
	} else {
		// Software version is everything before the space.
		s.SoftwareVersion = string(data[bptr:(bptr + sp)])
		bptr += sp
	}

	bptr += crlf // Skip the line feed bytes.
	return bptr, nil
}
