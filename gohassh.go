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
	Hassh                   string `json:"hassh"`
	HasshAlgorithms         string `json:"hasshAlgorithms"`
	HasshVersion            string `json:"hasshVersion"`
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

func (h *ClientRecord) HASSH() string {
	buf := bytes.Buffer{}
	_, _ = buf.WriteString(h.KexAlgos)
	_ = buf.WriteByte(hasshFieldDelimiter)
	_, _ = buf.WriteString(h.CiphersClientServer)
	_ = buf.WriteByte(hasshFieldDelimiter)
	_, _ = buf.WriteString(h.MACsClientServer)
	_ = buf.WriteByte(hasshFieldDelimiter)
	_, _ = buf.WriteString(h.CompressionClientServer)
	tmp := md5.Sum(buf.Bytes())
	h.HasshAlgorithms = buf.String()
	h.Hassh = hex.EncodeToString(tmp[:])
	return h.Hassh
}

type ServerRecord struct {
	HasshServer             string `json:"hasshServer"`
	HasshServerAlgorithms   string `json:"hasshServerAlgorithms"`
	HasshVersion            string `json:"hasshVersion"`
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

func (h *ServerRecord) HASSHServer() string {
	buf := bytes.Buffer{}
	_, _ = buf.WriteString(h.KexAlgos)
	_ = buf.WriteByte(hasshFieldDelimiter)
	_, _ = buf.WriteString(h.CiphersServerClient)
	_ = buf.WriteByte(hasshFieldDelimiter)
	_, _ = buf.WriteString(h.MACsServerClient)
	_ = buf.WriteByte(hasshFieldDelimiter)
	_, _ = buf.WriteString(h.CompressionServerClient)
	tmp := md5.Sum(buf.Bytes())
	h.HasshServerAlgorithms = buf.String()
	h.HasshServer = hex.EncodeToString(tmp[:])
	return h.HasshServer
}
