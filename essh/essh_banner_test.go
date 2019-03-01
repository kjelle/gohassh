package essh

import (
	"testing"

	"github.com/google/gopacket"
)

var testBanner = map[string]struct {
	data             []byte
	proto_version    string
	software_version string
}{
	"meh": {
		data:             append([]byte("SSH-2.0-OpenSSH_7.4"), []byte{0x0d, 0x0a}...),
		proto_version:    "2.0",
		software_version: "OpenSSH_7.4",
	},
}

func TestBanner(t *testing.T) {
	for k, test := range testBanner {
		t.Run(k, func(t *testing.T) {
			t.Log(k)
			r := &ESSHBannerRecord{}
			r.decodeFromBytes(test.data, gopacket.NilDecodeFeedback)

			if r.ProtoVersion != test.proto_version {
				t.Errorf("failed testcase '%s', mismatch on ProtoVersion\n\nexpected:\n%s\ngot: \n%s\n", k, test.proto_version, r.ProtoVersion)
			}
			if r.SoftwareVersion != test.software_version {
				t.Errorf("failed testcase '%s', mismatch on SoftwareVersion\n\nexpected:\n%s\ngot: \n%s\n", k, test.software_version, r.SoftwareVersion)
			}

		})
	}
}
