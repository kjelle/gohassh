package gohassh

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
)

// HASSH is a method developed by Salesforce (se github.com/salesforce/hassh):
//
//     "hassh" and "hasshServer" are MD5 hashes constructed from a specific set of algorithm,s that are supported
//     by various SSH Client and Server Applications. These algorithms are exchanged after the initial TCP three-way
//     handshake as clear-text packets known as "SSH_MSG_KEXINIT" messages, and are an integral part of the setup
//     of the final encrypted SSH channel. The existence and ordering of these algorithms is unique enough such that
//     it can be used as a fingerprint to help identify the underlying Client and Server application or unique
//     implementation, regardless of higher level ostensible identifiers such as "Client" or "Server" strings.

const hasshFieldDelimiter = byte(59) // ;
const hasshVersion = "1.0"

type ClientRecord struct {
	*HASSH
	KexAlgos                string `json:"ckex"`
	ServerHostKeyAlgos      string `json:"cshka"`
	CiphersClientServer     string `json:"ceacts"`
	CiphersServerClient     string `json:"ceastc"`
	MACsClientServer        string `json:"cmacts"`
	MACsServerClient        string `json:"cmastc"`
	CompressionClientServer string `json:"ccacts"`
	CompressionServerClient string `json:"ccastc"`
	LanguagesClientServer   string `json:"clcts"`
	LanguagesServerClient   string `json:"clstc"`
}

type HASSH struct {
	Hassh           string `json:"hassh"`
	HasshAlgorithms string `json:"hasshAlgorithms"`
	HasshVersion    string `json:"hasshVersion"`
}

func (h *ClientRecord) Compute() *HASSH {
	buf := bytes.Buffer{}
	_, _ = buf.WriteString(h.KexAlgos)
	_ = buf.WriteByte(hasshFieldDelimiter)
	_, _ = buf.WriteString(h.CiphersClientServer)
	_ = buf.WriteByte(hasshFieldDelimiter)
	_, _ = buf.WriteString(h.MACsClientServer)
	_ = buf.WriteByte(hasshFieldDelimiter)
	_, _ = buf.WriteString(h.CompressionClientServer)
	tmp := md5.Sum(buf.Bytes())

	h.HASSH = &HASSH{}
	h.HasshVersion = hasshVersion
	h.HasshAlgorithms = buf.String()
	h.Hassh = hex.EncodeToString(tmp[:])
	return h.HASSH
}

type ServerRecord struct {
	*HASSHServer
	KexAlgos                string `json:"skex"`
	ServerHostKeyAlgos      string `json:"sshka"`
	CiphersClientServer     string `json:"seacts"`
	CiphersServerClient     string `json:"seastc"`
	MACsClientServer        string `json:"smacts"`
	MACsServerClient        string `json:"smastc"`
	CompressionClientServer string `json:"scacts"`
	CompressionServerClient string `json:"scastc"`
	LanguagesClientServer   string `json:"slcts"`
	LanguagesServerClient   string `json:"slstc"`
}

type HASSHServer struct {
	HasshServer           string `json:"hasshServer"`
	HasshServerAlgorithms string `json:"hasshServerAlgorithms"`
	HasshVersion          string `json:"hasshVersion"`
}

func (h *ServerRecord) Compute() *HASSHServer {
	buf := bytes.Buffer{}
	_, _ = buf.WriteString(h.KexAlgos)
	_ = buf.WriteByte(hasshFieldDelimiter)
	_, _ = buf.WriteString(h.CiphersServerClient)
	_ = buf.WriteByte(hasshFieldDelimiter)
	_, _ = buf.WriteString(h.MACsServerClient)
	_ = buf.WriteByte(hasshFieldDelimiter)
	_, _ = buf.WriteString(h.CompressionServerClient)
	tmp := md5.Sum(buf.Bytes())

	h.HASSHServer = &HASSHServer{}
	h.HasshVersion = hasshVersion
	h.HasshServerAlgorithms = buf.String()
	h.HasshServer = hex.EncodeToString(tmp[:])
	return h.HASSHServer
}
