package main

// State flag which keeps record of which handeshake message types
// have been parsed.
type State uint8

const (
	StateClientBanner = 1 << iota
	StateServerBanner
	StateClientKexInit
	StateServerKexInit
)

func (s *State) Set(flag State) {
	*s |= flag
}

func (s State) Has(flag State) bool {
	return s&flag != 0
}
