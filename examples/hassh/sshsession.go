package main

import (
	"time"

	"github.com/kjelle/gohassh/essh"
)

type SSHSession struct {
	Timestamp  time.Time `json:"timestamp"`
	InIface    string    `json:"in_iface"`
	EventType  string    `json:"event_type"`
	ClientIP   string    `json:"src_ip"`
	ClientPort string    `json:"src_port"`
	ServerIP   string    `json:"dest_ip"`
	ServerPort string    `json:"dest_port"`
	Protocol   string    `json:"proto"`

	ESSHClientBanner *essh.ESSHBannerRecord `json:"client"`
	ESSHServerBanner *essh.ESSHBannerRecord `json:"server"`

	state State
}

func NewSSHSession(iface string) SSHSession {
	return SSHSession{
		EventType: "ssh",
		Protocol:  "006",
		InIface:   iface,
	}
}

func (s *SSHSession) ClientBanner(b *essh.ESSHBannerRecord) {
	s.state.Set(StateClientBanner)
	s.ESSHClientBanner = b
}

func (s *SSHSession) ServerBanner(b *essh.ESSHBannerRecord) {
	s.state.Set(StateServerBanner)
	s.ESSHServerBanner = b
}
