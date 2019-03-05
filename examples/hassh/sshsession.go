package main

import (
	"encoding/json"
	"time"

	"github.com/kjelle/gohassh"
	"github.com/kjelle/gohassh/essh"
)

type SSHRecord struct {
	*essh.ESSHBannerRecord
	*gohassh.HASSH
	*gohassh.HASSHServer
}

type SSHSession struct {
	Timestamp  time.Time `json:"timestamp"`
	InIface    string    `json:"in_iface"`
	EventType  string    `json:"event_type"`
	ClientIP   string    `json:"src_ip"`
	ClientPort string    `json:"src_port"`
	ServerIP   string    `json:"dest_ip"`
	ServerPort string    `json:"dest_port"`
	Protocol   string    `json:"proto"`

	Client SSHRecord `json:"client"`
	Server SSHRecord `json:"server"`

	state State
}

func NewSSHSession(iface string) SSHSession {
	return SSHSession{
		EventType: "ssh",
		Protocol:  "006",
		InIface:   iface,
		Client:    SSHRecord{},
		Server:    SSHRecord{},
	}
}

func (s *SSHSession) BannersComplete() bool {
	return s.state.Has(StateClientBanner) && s.state.Has(StateServerBanner)
}

func (s *SSHSession) KexInitComplete() bool {
	return s.state.Has(StateClientKexInit) && s.state.Has(StateServerKexInit)
}

func (s *SSHSession) ClientBanner(b *essh.ESSHBannerRecord) {
	s.state.Set(StateClientBanner)
	s.Client.ESSHBannerRecord = b
}

func (s *SSHSession) ServerBanner(b *essh.ESSHBannerRecord) {
	s.state.Set(StateServerBanner)
	s.Server.ESSHBannerRecord = b
}

// SetNetwork sets the network part of the session
func (s *SSHSession) SetNetwork(cip string, sip string, cp string, sp string) {
	s.ClientIP = cip
	s.ServerIP = sip
	s.ClientPort = cp
	s.ServerPort = sp
}

// SetTimestamp sets the timestamp of this session
func (s *SSHSession) SetTimestamp(ti time.Time) {
	s.Timestamp = ti
}

func (s *SSHSession) ClientKeyExchangeInit(k *essh.ESSHKexinitRecord) {
	s.state.Set(StateClientKexInit)
	cr := &gohassh.ClientRecord{
		KexAlgos:                k.KexAlgos,
		ServerHostKeyAlgos:      k.ServerHostKeyAlgos,
		CiphersClientServer:     k.CiphersClientServer,
		CiphersServerClient:     k.CiphersServerClient,
		MACsClientServer:        k.MACsClientServer,
		MACsServerClient:        k.MACsServerClient,
		CompressionClientServer: k.CompressionClientServer,
		CompressionServerClient: k.CompressionServerClient,
		LanguagesClientServer:   k.LanguagesClientServer,
		LanguagesServerClient:   k.LanguagesServerClient,
	}
	s.Client.HASSH = cr.Compute()
}

func (s *SSHSession) ServerKeyExchangeInit(k *essh.ESSHKexinitRecord) {
	s.state.Set(StateServerKexInit)
	sr := &gohassh.ServerRecord{
		KexAlgos:                k.KexAlgos,
		ServerHostKeyAlgos:      k.ServerHostKeyAlgos,
		CiphersClientServer:     k.CiphersClientServer,
		CiphersServerClient:     k.CiphersServerClient,
		MACsClientServer:        k.MACsClientServer,
		MACsServerClient:        k.MACsServerClient,
		CompressionClientServer: k.CompressionClientServer,
		CompressionServerClient: k.CompressionServerClient,
		LanguagesClientServer:   k.LanguagesClientServer,
		LanguagesServerClient:   k.LanguagesServerClient,
	}
	s.Server.HASSHServer = sr.Compute()
}

func (s *SSHSession) MarshalJSON() ([]byte, error) {
	type Alias SSHSession
	return json.Marshal(&struct {
		*Alias
		Timestamp string `json:"timestamp"`
	}{
		Alias:     (*Alias)(s),
		Timestamp: s.Timestamp.Format("2016"),
	})
}
