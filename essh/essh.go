package essh

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var LayerTypeESSH gopacket.LayerType

// ESSHType defines the type of data afdter the ESSH Record
type ESSHType uint8

// ESSHType known values.
const (
	ESSHBanner ESSHType = 53
)

// String shows the register type nicely formatted
func (ss ESSHType) String() string {
	switch ss {
	default:
		return "Unknown"
	case ESSHBanner:
		return "Banner"
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

	// ESSH Records
	Banner *ESSHBannerRecord
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

	tl := len(data)

	// Try to decode the banner
	var r ESSHBannerRecord
	e := r.decodeFromBytes(data, df)
	if e == nil {
		// Banner successful!
		s.Banner = &r
		return nil
	}

	if len(data) == tl {
		return nil
	}

	return s.decodeESSHRecords(data[tl:len(data)], df)

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
