package essh

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
)

// SSH Key Exchange Algorithm Negotation
//
//      byte         SSH_MSG_KEXINIT
//      byte[16]     cookie (random bytes)
//      name-list    kex_algorithms
//      name-list    server_host_key_algorithms
//      name-list    encryption_algorithms_client_to_server
//      name-list    encryption_algorithms_server_to_client
//      name-list    mac_algorithms_client_to_server
//      name-list    mac_algorithms_server_to_client
//      name-list    compression_algorithms_client_to_server
//      name-list    compression_algorithms_server_to_client
//      name-list    languages_client_to_server
//      name-list    languages_server_to_client
//      boolean      first_kex_packet_follows
//      uint32       0 (reserved for future extension)
//
type ESSHKexinitRecord struct {
	//	Cookie                  [16]byte `sshtype:"20"`
	KexAlgos                string
	ServerHostKeyAlgos      string
	CiphersClientServer     string
	CiphersServerClient     string
	MACsClientServer        string
	MACsServerClient        string
	CompressionClientServer string
	CompressionServerClient string
	LanguagesClientServer   string
	LanguagesServerClient   string
	FirstKexFollows         bool
	//	Reserved                uint32
}

const (
// Contants used for parsing

)

// decodeFromBytes decodes the Key Exchange (kex) as specified by RFC 4253, section 7.1.
func (s *ESSHKexinitRecord) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	//	copy(s.Cookie[:], data[0:16])
	bptr := uint32(16) // Skip cookie

	fmt.Printf("data len: %d\n", len(data))
	fmt.Printf("data: %02x\n", data)
	fmt.Printf("cookie: %02x\n", data[0:16])
	fmt.Printf("kexalgoslength: %02x\n", data[16:20])

	var l uint32

	// kex_algorithms
	l = binary.BigEndian.Uint32(data[bptr:(bptr + 4)])
	bptr += 4
	if l > 0 {
		s.KexAlgos = string((data[bptr:(bptr + l)])[:])
		bptr += l
	}

	// server_host_key_algorithms
	l = binary.BigEndian.Uint32(data[bptr:(bptr + 4)])
	bptr += 4
	if l > 0 {
		s.ServerHostKeyAlgos = string((data[bptr:(bptr + l)])[:])
		bptr += l
	}

	// encryption_algorithms_client_to_server
	l = binary.BigEndian.Uint32(data[bptr:(bptr + 4)])
	bptr += 4
	if l > 0 {
		s.CiphersClientServer = string((data[bptr:(bptr + l)])[:])
		bptr += l
	}

	// encryption_algorithms_server_to_client
	l = binary.BigEndian.Uint32(data[bptr:(bptr + 4)])
	bptr += 4
	if l > 0 {
		s.CiphersServerClient = string((data[bptr:(bptr + l)])[:])
		bptr += l
	}

	// mac_algorithms_client_to_server
	l = binary.BigEndian.Uint32(data[bptr:(bptr + 4)])
	bptr += 4
	if l > 0 {
		s.MACsClientServer = string((data[bptr:(bptr + l)])[:])
		bptr += l
	}

	// mac_algorithms_server_to_client
	l = binary.BigEndian.Uint32(data[bptr:(bptr + 4)])
	bptr += 4
	if l > 0 {
		s.MACsServerClient = string((data[bptr:(bptr + l)])[:])
		bptr += l
	}

	// compression_algorithms_client_to_server
	l = binary.BigEndian.Uint32(data[bptr:(bptr + 4)])
	bptr += 4
	if l > 0 {
		s.CompressionClientServer = string((data[bptr:(bptr + l)])[:])
		bptr += l
	}

	// compression_algorithms_server_to_client
	l = binary.BigEndian.Uint32(data[bptr:(bptr + 4)])
	bptr += 4
	if l > 0 {
		s.CompressionServerClient = string((data[bptr:(bptr + l)])[:])
		bptr += l
	}

	// languages_client_to_server
	l = binary.BigEndian.Uint32(data[bptr:(bptr + 4)])
	bptr += 4
	if l > 0 {
		s.LanguagesClientServer = string((data[bptr:(bptr + l)])[:])
		bptr += l
	}

	// languages_server_to_client
	l = binary.BigEndian.Uint32(data[bptr:(bptr + 4)])
	bptr += 4
	if l > 0 {
		s.LanguagesServerClient = string((data[bptr:(bptr + l)])[:])
		bptr += l
	}

	// first_kex_packet_follows
	s.FirstKexFollows = data[bptr] != 0
	bptr += 1

	// reserved, skip
	bptr += 4

	// Padding
	fmt.Printf("Padding? %d\n", uint32(len(data))-bptr)

	fmt.Printf("bptr: %d  len(data): %d\n", bptr, len(data))

	fmt.Printf("KexAlgos: %s\n", s.KexAlgos)
	fmt.Printf("server_hostkey_algorithms: %s\n", s.ServerHostKeyAlgos)
	fmt.Printf("s.CiphersClientServer: %s\n", s.CiphersClientServer)
	fmt.Printf("s.CiphersServerClient: %s\n", s.CiphersServerClient)
	fmt.Printf("s.MACsClientServer: %s\n", s.MACsClientServer)
	fmt.Printf("s.MACsServerClient: %s\n", s.MACsServerClient)
	fmt.Printf("s.CompressionClientServer: %s\n", s.CompressionClientServer)
	fmt.Printf("s.CompressionServerClient: %s\n", s.CompressionServerClient)

	return nil
}
