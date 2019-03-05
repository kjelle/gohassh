package gohassh

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var testHASSH = map[string]struct {
	clientrecord    *ClientRecord
	hassh           string
	hasshalgorithms string
}{
	"SSH-2.0-Cyberduck/6.7.1.28683 (Mac OS X/10.13.6) (x86_64)": {
		clientrecord: &ClientRecord{
			Hassh:           `8a8ae540028bf433cd68356c1b9e8d5b`,
			HasshAlgorithms: `curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,diffie-hellman-group15-sha512,diffie-hellman-group16-sha512,diffie-hellman-group17-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256@ssh.com,diffie-hellman-group15-sha256,diffie-hellman-group15-sha256@ssh.com,diffie-hellman-group15-sha384@ssh.com,diffie-hellman-group16-sha256,diffie-hellman-group16-sha384@ssh.com,diffie-hellman-group16-sha512@ssh.com,diffie-hellman-group18-sha512@ssh.com;aes128-cbc,aes128-ctr,aes192-cbc,aes192-ctr,aes256-cbc,aes256-ctr,blowfish-cbc,blowfish-ctr,cast128-cbc,cast128-ctr,idea-cbc,idea-ctr,serpent128-cbc,serpent128-ctr,serpent192-cbc,serpent192-ctr,serpent256-cbc,serpent256-ctr,3des-cbc,3des-ctr,twofish128-cbc,twofish128-ctr,twofish192-cbc,twofish192-ctr,twofish256-cbc,twofish256-ctr,twofish-cbc,arcfour,arcfour128,arcfour256;hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-sha2-256,hmac-sha2-512;zlib@openssh.com,zlib,none`,

			KexAlgos:                `curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,diffie-hellman-group15-sha512,diffie-hellman-group16-sha512,diffie-hellman-group17-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256@ssh.com,diffie-hellman-group15-sha256,diffie-hellman-group15-sha256@ssh.com,diffie-hellman-group15-sha384@ssh.com,diffie-hellman-group16-sha256,diffie-hellman-group16-sha384@ssh.com,diffie-hellman-group16-sha512@ssh.com,diffie-hellman-group18-sha512@ssh.com`,
			CiphersClientServer:     `aes128-cbc,aes128-ctr,aes192-cbc,aes192-ctr,aes256-cbc,aes256-ctr,blowfish-cbc,blowfish-ctr,cast128-cbc,cast128-ctr,idea-cbc,idea-ctr,serpent128-cbc,serpent128-ctr,serpent192-cbc,serpent192-ctr,serpent256-cbc,serpent256-ctr,3des-cbc,3des-ctr,twofish128-cbc,twofish128-ctr,twofish192-cbc,twofish192-ctr,twofish256-cbc,twofish256-ctr,twofish-cbc,arcfour,arcfour128,arcfour256`,
			MACsClientServer:        `hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-sha2-256,hmac-sha2-512`,
			CompressionClientServer: `zlib@openssh.com,zlib,none`,
		},
	},
}

func TestHASSH(t *testing.T) {
	for k, test := range testHASSH {
		t.Run(k, func(t *testing.T) {
			t.Log(k)
			testClientRecord(k, t, test.clientrecord)
		})
	}
}

func testClientRecord(k string, t *testing.T, h *ClientRecord) {
	hassh := string(h.Hassh) // The underlying bytes of hassh is a copy of h.Hassh
	hasshalgorithms := string(h.HasshAlgorithms)
	if len(hassh) != 32 {
		t.Fatalf("Expected hassh to be 32 byte")
	}
	if len(hasshalgorithms) < 1 {
		t.Fatalf("No hasshalgorithms given")
	}
	h.Hassh = ""
	h.HasshAlgorithms = ""

	_ = h.HASSH()
	t.Logf("Hassh: %s", h.Hassh)
	t.Logf("HasshAlgorithms: %s", h.HasshAlgorithms)
	if !reflect.DeepEqual(h.Hassh, hassh) {
		t.Errorf("failed testcase '%s', mismatch on hassh\n\nexpected:\n%v\ngot: \n%v\n", k, hassh, h.Hassh)
	}
	if !reflect.DeepEqual(h.HasshAlgorithms, hasshalgorithms) {
		t.Errorf("failed testcase '%s', mismatch on hassh\n\nexpected:\n%v\ngot: \n%v\n", k, hasshalgorithms, h.HasshAlgorithms)
	}
}

func TestHASSHJson(t *testing.T) {
	files, err := filepath.Glob("testdata/hassh/*.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, fn := range files {
		test, err := NewTestFile(t, fn)
		if err != nil {
			t.Errorf("error creating test for %s: %s", fn, err)
		}

		err = test.Run(clientrecord, testClientRecordFile)
		if err != nil {
			t.Errorf("error running test %s: %s", fn, err)
		}
	}

}

func clientrecord() interface{} {
	var s ClientRecord
	return &s
}

func testClientRecordFile(k string, t *testing.T, s interface{}) {
	r, ok := s.(*ClientRecord)
	if !ok {
		panic(fmt.Sprintf("Expected *ClientRecord, got %T", s))
	}
	// spew.Dump(r)
	testClientRecord(k, t, r)
}

var testHASSHServer = map[string]struct {
	serverrecord          *ServerRecord
	hasshserver           string
	hasshserveralgorithms string
}{
	"SSH-2.0-OpenSSH_6.6.1": {
		serverrecord: &ServerRecord{
			HasshServer:           `ba6d3d2aecbd0d91b01dfa7828110d70`,
			HasshServerAlgorithms: `curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1;aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se;hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-md5,hmac-sha1,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96;none,zlib@openssh.com`,

			KexAlgos:                `curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1`,
			CiphersServerClient:     `aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se`,
			MACsServerClient:        `hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-md5,hmac-sha1,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96`,
			CompressionServerClient: `none,zlib@openssh.com`,
		},
	},
}

func TestHASSHServer(t *testing.T) {
	for k, test := range testHASSHServer {
		t.Run(k, func(t *testing.T) {
			t.Log(k)
			testServerRecord(k, t, test.serverrecord)
		})
	}
}

func testServerRecord(k string, t *testing.T, h *ServerRecord) {
	hasshserver := string(h.HasshServer) // The underlying bytes of hasshserver is a copy of h.HasshServer
	hasshserveralgorithms := string(h.HasshServerAlgorithms)
	if len(hasshserver) != 32 {
		t.Fatalf("Expected hasshserver to be 32 byte")
	}
	if len(hasshserveralgorithms) < 1 {
		t.Fatalf("No hasshserveralgorithms given")
	}
	h.HasshServer = ""
	h.HasshServerAlgorithms = ""

	_ = h.HASSHServer()
	t.Logf("HasshServer: %s", h.HasshServer)
	t.Logf("HasshServerAlgorithms: %s", h.HasshServerAlgorithms)
	if !reflect.DeepEqual(h.HasshServer, hasshserver) {
		t.Errorf("failed testcase '%s', mismatch on hasshserver\n\nexpected:\n%v\ngot: \n%v\n", k, hasshserver, h.HasshServer)
	}
	if !reflect.DeepEqual(h.HasshServerAlgorithms, hasshserveralgorithms) {
		t.Errorf("failed testcase '%s', mismatch on hasshserver\n\nexpected:\n%v\ngot: \n%v\n", k, hasshserveralgorithms, h.HasshServerAlgorithms)
	}
}

type TestFile struct {
	*testing.T
	filename string
	tests    []*Test
}

type Test struct {
	line  int
	event string
}

type StructFunc func() interface{}

func NewTestFile(t *testing.T, filename string) (*TestFile, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	test := &TestFile{
		T:        t,
		filename: filename,
		tests:    []*Test{},
	}
	err = test.parse(string(content))
	return test, err
}

func (t *TestFile) parse(input string) error {
	lines := strings.Split(input, "\n")
	for i, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "#") {
			l = ""
		}
		lines[i] = l
	}

	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if len(l) == 0 {
			continue
		}

		t.tests = append(t.tests, &Test{
			line:  i,
			event: l,
		})
	}
	return nil
}

type TestFunc func(string, *testing.T, interface{})

func (t *TestFile) Run(fn StructFunc, dfn TestFunc) error {
	for _, test := range t.tests {
		k := fmt.Sprintf("%s:%d", t.filename, test.line)
		t.T.Run(k, func(t *testing.T) {
			t.Log(k)
			//			t.Logf("JSON: %s", test.event)

			// Is the input valid?
			var j map[string]interface{}
			if err := json.Unmarshal([]byte(test.event), &j); err != nil {
				t.Errorf("Failed to Unmarshal to JSON: %s", err)
			}

			j2 := fn()
			err := json.Unmarshal([]byte(test.event), j2)
			if err != nil {
				t.Error(err)
			}
			dfn(k, t, j2)

			t.Logf("Object: %+v", j2)
		})
	}
	return nil
}
