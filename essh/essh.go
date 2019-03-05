package essh

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var LayerTypeESSH gopacket.LayerType

// ESSHType defines the type of data afdter the ESSH Record
type ESSHType uint8

// ESSHType known values, possibly defined in RFC 4253, section 12.
const (
	ESSH_BANNER      ESSHType = 53
	ESSH_MSG_KEXINIT ESSHType = 20 // SSH_MSG_KEXINIT
)

// String shows the register type nicely formatted
func (ss ESSHType) String() string {
	switch ss {
	default:
		return "Unknown"
	case ESSH_BANNER:
		return "Banner"
	case ESSH_MSG_KEXINIT:
		return "Message Key Exchange Init"
	}
}

// ESSHVersion represents the ESSH version in numeric format
type ESSHVersion uint16

// Strings shows the ESSH version nicely formatted
func (sv ESSHVersion) String() string {
	switch sv {
	default:
		return "Unknown"
	}
}

// SSH is specified in RFC 4253

type ESSH struct {
	layers.BaseLayer

	BannersComplete bool

	// ESSH Records
	Banner  *ESSHBannerRecord
	Kexinit *ESSHKexinitRecord
}

// decodeFromBytes decodes the Binary Packet Protocol as specified by RFC 4253, section 6.
//
//   uint32     packet_length
//   byte       padding_length
//   byte       message code
type ESSHRecordHeader struct {
	PacketLength  uint32
	PaddingLength uint8
	MessageCode   ESSHType
}

func (h *ESSHRecordHeader) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 6 {
		return errors.New("ESSH invalid SSH header")
	}
	h.PacketLength = binary.BigEndian.Uint32(data[0:4])
	h.PaddingLength = uint8(data[4:5][0])
	h.MessageCode = ESSHType(uint8(data[5:6][0]))
	return nil
}

func NewESSH(decb bool) *ESSH {
	return &ESSH{
		BannersComplete: decb,
	}
}

func (s *ESSH) LayerType() gopacket.LayerType { return LayerTypeESSH }

// decodeESSH decodes the byte slice into a ESSH type. IT also setups
// the application Layer in PacketBuilder.
func decodeESSH(data []byte, p gopacket.PacketBuilder) error {
	s := &ESSH{}
	err := s.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(s)
	p.SetApplicationLayer(s)
	return nil
}

// DecodeFromBytes decodes a byte slice into the ESSH struct
func (s *ESSH) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	s.BaseLayer.Contents = data
	s.BaseLayer.Payload = nil
	return s.decodeESSHRecords(data, df)
}

func (s *ESSH) decodeESSHRecords(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 4 {
		df.SetTruncated()
		return errors.New("ESSH record too short")
	}

	// since there are no further layers, the baselayer's content is
	// pointing to this layer
	s.BaseLayer = layers.BaseLayer{Contents: data[:len(data)]}

	if !s.BannersComplete {
		var r ESSHBannerRecord
		e := r.decodeFromBytes(data, df)
		if e == nil {
			// Banner successful!
			s.Banner = &r
			return nil
		}

		// We return nil anyways, since we stop processing.
		return nil
	}

	fmt.Printf("Decode kex? BannersComplete:%t %02x\n", s.BannersComplete, data[0:2])

	var h ESSHRecordHeader
	e := h.decodeFromBytes(data, df)
	if e != nil {
		return e
	}

	hl := 6 // header length
	tl := hl + int(h.PacketLength)
	if len(data) < tl {
		df.SetTruncated()
		return errors.New("ESSH packet lengt mismatch")
	}

	switch h.MessageCode {
	default:
		return errors.New("Unknown ESSH message code")
	case ESSH_MSG_KEXINIT:
		var r ESSHKexinitRecord
		e := r.decodeFromBytes(data, h.PaddingLength, df)
		if e == nil {
			// Key Exchange successful!
			s.Kexinit = &r
			return nil
		}
	}

	if len(data) == tl {
		return nil
	}

	return s.decodeESSHRecords(data[tl:len(data)], df)

}

func (s *ESSH) decodeKexRecords(data []byte, df gopacket.DecodeFeedback) error {
	var h ESSHRecordHeader
	err := h.decodeFromBytes(data, df)
	if err != nil {
		return err
	}

	hl := 6                            // header length
	tl := hl + int(h.PacketLength) - 2 // minus padding_length and MessageCode field
	if len(data) < tl {
		df.SetTruncated()
		return errors.New("ESSH packet lengt mismatch")
	}

	if h.MessageCode != ESSH_MSG_KEXINIT {
		return fmt.Errorf("Wrong messagecode, should be ESSH_MSG_KEXINIT (%d)", h.MessageCode)
	}

	var r ESSHKexinitRecord
	err = r.decodeFromBytes(data[hl:tl], h.PaddingLength, gopacket.NilDecodeFeedback)
	if err != nil {
		return err
	}
	// Key Exchange successful!
	s.Kexinit = &r
	return nil
}

// CanDecode implements gopacket.DecodingLayer.
func (s *ESSH) CanDecode() gopacket.LayerClass {
	return LayerTypeESSH
}

// NextLayerType implements gopacket.DecodingLayer.
func (t *ESSH) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// Payload returns nil, since ETLS encrypted payload is inside ETLSAppDataRecord
func (s *ESSH) Payload() []byte {
	return nil
}

func init() {
	LayerTypeESSH = gopacket.RegisterLayerType(6666, gopacket.LayerTypeMetadata{Name: "ESSH", Decoder: gopacket.DecodeFunc(decodeESSH)})
}
