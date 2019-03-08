package essh

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"golang.org/x/crypto/ssh"
)

const msgKexECDHReply = 31

type kexECDHReplyMsg struct {
	HostKey         []byte `sshtype:"31"`
	EphemeralPubKey []byte
	Signature       []byte
}

const msgKexDHReply = 31

type kexDHReplyMsg struct {
	HostKey   []byte `sshtype:"31"`
	Y         *big.Int
	Signature []byte
}

func TestFingerprint(t *testing.T) {
	p := `1f000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104c1476fc7fc13c09065726fd48c5fca0dfc69810167b74792dbbddaa5edd56dd313e7b3d8f6c9b75f484ed86b1f6ce67e04f4edea2fc9199dd6ed2f691bc7935f000000208258bdb8b20101673f64bb56b577dbd6c25da25b2f3cdaf5cfd7408c3fadc80c000000630000001365636473612d736861322d6e69737470323536000000480000002016b3135f33a46159757c10740822579b89fbcc1f4365f2461daf151bfd366aed00000020215ad1e25c8d527ba3607af9c829db971a06f45771bbb25ad0cc3e94a1b6b56400000000000000000000000000000c0a15000000000000000000007864bbfc23f1e178fb2a002dd676b0374a2d1e2db418ee965e46bb77ee575f71b260792f5ac6ed5c66ddd5c650f942c5e1ac7303d72ac422fa39e2ec8d442528fb0a6fe9c86af835b66878d51ba36348d60d7b35`

	packet, err := hex.DecodeString(p)
	if err != nil {
		t.Fatal(err)
	}

	packet_length := 260
	padding_length := 10
	_ = padding_length

	var reply kexECDHReplyMsg
	if err := ssh.Unmarshal(packet[0:(packet_length-padding_length-2)], &reply); err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%+v\n", reply)

	fmt.Printf("%02x\n", reply.HostKey)
	fmt.Printf("%02x\n", reply.EphemeralPubKey)

	pb, err := ssh.ParsePublicKey(reply.HostKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = pb

	fmt.Printf("%+v\n", pb)

	fmd5 := ssh.FingerprintLegacyMD5(pb)
	fmt.Printf("%s\n", fmd5)

	fsha256 := ssh.FingerprintSHA256(pb)
	fmt.Printf("%s\n", fsha256)

}
