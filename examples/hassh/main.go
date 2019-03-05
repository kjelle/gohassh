package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"

	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
	"github.com/kjelle/gohassh/essh"
)

var statsevery = flag.Int("stats", 100000, "Output statistics every N packets")
var nodefrag = flag.Bool("nodefrag", false, "If true, do not do IPv4 defrag")
var checksum = flag.Bool("checksum", false, "Check TCP checksum")
var nooptcheck = flag.Bool("nooptcheck", true, "Do not check TCP options (useful to ignore MSS on captures with TSO)")
var ignorefsmerr = flag.Bool("ignorefsmerr", false, "Ignore TCP FSM errors")
var verbose = flag.Bool("verbose", false, "Be verbose")
var debug = flag.Bool("debug", false, "Display debug information")
var quiet = flag.Bool("quiet", false, "Be quiet regarding errors")

var hexdumppkt = flag.Bool("dumppkt", false, "Dump packet as hex")

// capture
var iface = flag.String("i", "eth0", "Interface to read packets from")
var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
var fname = flag.String("r", "", "Filename to read from, overrides -i")

// writing
var jsonIndent = flag.Bool("jsonindent", true, "Write JSON with indent")
var outCerts = flag.String("w", "", "Folder to write certificates into")
var outJSON = flag.String("j", "", "Folder to write certificates into, stdin if not set")
var outFilename = flag.String("f", "", "Output all captures to a single filename")
var jobQ chan SSHSession

// debugging
var pprofenabled = flag.Bool("pprof", false, "enabling net/http/pprof")
var pprofint = flag.String("pprofint", "0.0.0.0", "interface to listen to")
var pprofport = flag.Int("pprofport", 8080, "port to listen for pprof")

const timeout time.Duration = time.Second * 5       // Pending bytes: TODO: from CLI
const closeTimeout time.Duration = time.Second * 10 // Closing inactive: TODO: from CLI

var assemblerOptions = reassembly.AssemblerOptions{
	MaxBufferedPagesPerConnection: 0,
	MaxBufferedPagesTotal:         0, // unlimited
}

var stats struct {
	ipdefrag            int
	missedBytes         int
	pkt                 int
	sz                  int
	totalsz             int
	rejectFsm           int
	rejectOpt           int
	rejectConnFsm       int
	reassembled         int
	outOfOrderBytes     int
	outOfOrderPackets   int
	biggestChunkBytes   int
	biggestChunkPackets int
	overlapBytes        int
	overlapPackets      int
}

var outputLevel int
var errorsMap map[string]uint
var errorsMapMutex sync.Mutex
var errors uint
var outFile *os.File
var done bool

// Too bad for perf that a... is evaluated
func Error(t string, s string, a ...interface{}) {
	errorsMapMutex.Lock()
	errors++
	nb, _ := errorsMap[t]
	errorsMap[t] = nb + 1
	errorsMapMutex.Unlock()
	if outputLevel >= 0 {
		//fmt.Printf(s, a...)
	}

	fmt.Printf(s, a...)
}
func Info(s string, a ...interface{}) {
	if outputLevel >= 1 {
		fmt.Printf(s, a...)
	}
}
func Debug(s string, a ...interface{}) {
	if outputLevel >= 2 {
		fmt.Printf(s, a...)
	}
}

/*
 * The TCP factory: returns a new Stream
 */
type tcpStreamFactory struct {
	wg sync.WaitGroup
}

func (factory *tcpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	fsmOptions := reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: true,
	}
	stream := &tcpStream{
		net:        net,
		transport:  transport,
		tcpstate:   reassembly.NewTCPSimpleFSM(fsmOptions),
		ident:      fmt.Sprintf("%s:%s", net, transport),
		optchecker: reassembly.NewTCPOptionCheck(),
		sshSession: NewSSHSession(*iface),
	}

	return stream
}

func (factory *tcpStreamFactory) WaitGoRoutines() {
	factory.wg.Wait()
}

/*
 * The assembler context
 */
type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}

/*
 * TCP stream
 */

/* It's a connection (bidirectional) */
type tcpStream struct {
	tcpstate       *reassembly.TCPSimpleFSM
	fsmerr         bool
	optchecker     reassembly.TCPOptionCheck
	net, transport gopacket.Flow
	reversed       bool
	urls           []string
	ident          string
	sshSession     SSHSession
	queued         bool
	ignorefsmerr   bool
	nooptcheck     bool
	checksum       bool
	sync.Mutex
}

func (t *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// FSM
	if !t.tcpstate.CheckState(tcp, dir) {
		Error("FSM", "%s: Packet rejected by FSM (state:%s)\n", t.ident, t.tcpstate.String())
		stats.rejectFsm++
		if !t.fsmerr {
			t.fsmerr = true
			stats.rejectConnFsm++
		}
		if !*ignorefsmerr {
			return false
		}
	}
	// Options
	err := t.optchecker.Accept(tcp, ci, dir, nextSeq, start)
	if err != nil {
		Error("OptionChecker", "%s: Packet rejected by OptionChecker: %s\n", t.ident, err)
		stats.rejectOpt++
		if !*nooptcheck {
			return false
		}
	}
	// Checksum
	accept := true
	if *checksum {
		c, err := tcp.ComputeChecksum()
		if err != nil {
			Error("ChecksumCompute", "%s: Got error computing checksum: %s\n", t.ident, err)
			accept = false
		} else if c != 0x0 {
			Error("Checksum", "%s: Invalid checksum: 0x%x\n", t.ident, c)
			accept = false
		}
	}
	if !accept {
		stats.rejectOpt++
	}
	return accept

}

func (t *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, start, end, skip := sg.Info()
	length, saved := sg.Lengths()
	// update stats
	sgStats := sg.Stats()
	if skip > 0 {
		stats.missedBytes += skip
	}
	stats.sz += length - saved
	stats.pkt += sgStats.Packets
	if sgStats.Chunks > 1 {
		stats.reassembled++
	}
	stats.outOfOrderPackets += sgStats.QueuedPackets
	stats.outOfOrderBytes += sgStats.QueuedBytes
	if length > stats.biggestChunkBytes {
		stats.biggestChunkBytes = length
	}
	if sgStats.Packets > stats.biggestChunkPackets {
		stats.biggestChunkPackets = sgStats.Packets
	}
	if sgStats.OverlapBytes != 0 && sgStats.OverlapPackets == 0 {
		fmt.Printf("bytes:%d, pkts:%d\n", sgStats.OverlapBytes, sgStats.OverlapPackets)
		panic("Invalid overlap")
	}
	stats.overlapBytes += sgStats.OverlapBytes
	stats.overlapPackets += sgStats.OverlapPackets

	var ident string
	if dir == reassembly.TCPDirClientToServer {
		ident = fmt.Sprintf("%v %v(%s): ", t.net, t.transport, dir)
	} else {
		ident = fmt.Sprintf("%v %v(%s): ", t.net.Reverse(), t.transport.Reverse(), dir)
	}
	Debug("%s: SG reassembled packet with %d bytes (start:%v,end:%v,skip:%d,saved:%d,nb:%d,%d,overlap:%d,%d)\n", ident, length, start, end, skip, saved, sgStats.Packets, sgStats.Chunks, sgStats.OverlapBytes, sgStats.OverlapPackets)

	/*fmt.Printf("%s: Data Length: %d   Skip: %d   BannersComplete: %t\n",
		ident,
		length,
		skip,
		t.sshSession.BannersComplete(),
	)*/

	if skip == -1 {
		// this is allowed
	} else if skip != 0 {
		/*		fmt.Printf("!! SKIP %d bytes (length:%d)\n",
					skip,
					length,
				)

				d := sg.Fetch(skip)
				fmt.Printf(" [...] %02x\n", d)*/

		// Missing bytes in stream: do not even try to parse it
		return
	}
	data := sg.Fetch(length)

	if length > 0 {

		// For all SSH we must first decode the banner, if no banner have been
		// completed, we do not parse the rest of the stream.
		var decb bool
		decb = t.sshSession.BannersComplete()
		ssh := essh.NewESSH(decb)

		var decoded []gopacket.LayerType
		p := gopacket.NewDecodingLayerParser(essh.LayerTypeESSH, ssh)
		p.DecodingLayerParserOptions.IgnoreUnsupported = true
		err := p.DecodeLayers(data, &decoded)
		//fmt.Printf("err: %s\n", err)
		if err == nil {

			//			fmt.Printf("SSH(%s): %s\n", dir, gopacket.LayerDump(ssh))

			//			Debug("SSH(%s): %s\n", dir, gopacket.LayerDump(ssh))
			//				Debug("SSH(%s): %s\n", dir, gopacket.LayerGoString(ssh))

			if ssh.Banner != nil {

				if t.sshSession.Timestamp.IsZero() {
					info := sg.CaptureInfo(0)
					t.sshSession.SetTimestamp(info.Timestamp)
				}

				if dir == reassembly.TCPDirClientToServer {
					t.sshSession.ClientBanner(ssh.Banner)
				} else {
					t.sshSession.ServerBanner(ssh.Banner)
					// Set network information in the session
					cip, sip, cp, sp := getIPPorts(t)
					t.sshSession.SetNetwork(cip, sip, cp, sp)

					t.queueSession()

				}
			}

			if ssh.Kexinit != nil {
				if dir == reassembly.TCPDirClientToServer {
					t.sshSession.ClientKeyExchangeInit(ssh.Kexinit)
					t.queueSession()
				} else {
					t.sshSession.ServerKeyExchangeInit(ssh.Kexinit)
					t.queueSession()
				}

			}

		}
	}

}

func getIPPorts(t *tcpStream) (string, string, string, string) {
	tmp := strings.Split(fmt.Sprintf("%v", t.net), "->")
	ipc := tmp[0]
	ips := tmp[1]
	tmp = strings.Split(fmt.Sprintf("%v", t.transport), "->")
	cp := tmp[0]
	ps := tmp[1]
	return ipc, ips, cp, ps
}

func (t *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	// TODO: What about partial sessions?

	// remove connection from the pool
	return true
}

func main() {

	defer util.Run()()
	var handle *pcap.Handle
	var err error
	if *debug {
		outputLevel = 2
	} else if *verbose {
		outputLevel = 1
	} else if *quiet {
		outputLevel = -1
	}
	errorsMap = make(map[string]uint)
	if *fname != "" {
		if handle, err = pcap.OpenOffline(*fname); err != nil {
			log.Fatal("PCAP OpenOffline error:", err)
		}
	} else {
		// Open live on interface
		if handle, err = pcap.OpenLive(*iface, 65536, true, 0); err != nil {
			log.Fatal("PCAP OpenOffline error:", err)
		}
		defer handle.Close()
	}
	if len(flag.Args()) > 0 {
		bpffilter := strings.Join(flag.Args(), " ")
		Info("Using BPF filter %q\n", bpffilter)
		if err = handle.SetBPFFilter(bpffilter); err != nil {
			log.Fatal("BPF filter error:", err)
		}
	}

	// For debug
	if *pprofenabled {
		//runtime.SetBlockProfileRate(1)
		go func() {
			fmt.Printf(" .. pprof listener on %d\n", *pprofport)
			http.ListenAndServe(fmt.Sprintf("%s:%d", *pprofint, *pprofport), nil)
			fmt.Println("!! Pprof listener stopped.\n")
		}()

	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.Lazy = false
	source.NoCopy = true
	Info("Starting to read packets\n")
	count := 0
	bytes := int64(0)
	defragger := ip4defrag.NewIPv4Defragmenter()

	streamFactory := &tcpStreamFactory{}
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)
	assembler.AssemblerOptions = assemblerOptions

	// Signal chan for system signals
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	// Job chan to hold Completed sessions to write
	jobQ = make(chan SSHSession, 4096)
	cancelC := make(chan string)

	// We start a worker to send the processed connection the outside world
	var w sync.WaitGroup
	w.Add(1)
	go processCompletedSession(cancelC, jobQ, &w)

	/*	var eth layers.Ethernet
		var ip4 layers.IPv4
		var ip6 layers.IPv6
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6)
		decoded := []gopacket.LayerType{}*/

	for packet := range source.Packets() {
		count++
		Debug("PACKET #%d\n", count)
		data := packet.Data()
		bytes += int64(len(data))
		if *hexdumppkt {
			Debug("Packet content (%d/0x%x)\n%s\n", len(data), len(data), hex.Dump(data))
		}

		// defrag the IPv4 packet if required
		if !*nodefrag {
			ip4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ip4Layer == nil {
				continue
			}
			ip4 := ip4Layer.(*layers.IPv4)
			l := ip4.Length
			newip4, err := defragger.DefragIPv4(ip4)
			if err != nil {
				log.Fatalln("Error while de-fragmenting", err)
			} else if newip4 == nil {
				Debug("Fragment...\n")
				continue // ip packet fragment, we don't have whole packet yet.
			}
			if newip4.Length != l {
				Debug("Decoding re-assembled packet: %s\n", newip4.NextLayerType())
				pb, ok := packet.(gopacket.PacketBuilder)
				if !ok {
					panic("Not a PacketBuilder")
				}
				nextDecoder := newip4.NextLayerType()
				nextDecoder.Decode(newip4.Payload, pb)
			}
		}

		tcp := packet.Layer(layers.LayerTypeTCP)
		if tcp != nil {
			tcp := tcp.(*layers.TCP)
			if *checksum {
				err := tcp.SetNetworkLayerForChecksum(packet.NetworkLayer())
				if err != nil {
					log.Fatalf("Failed to set network layer for checksum: %s\n", err)
				}
			}
			c := Context{
				CaptureInfo: packet.Metadata().CaptureInfo,
			}
			stats.totalsz += len(tcp.Payload)
			assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &c)
		}
		if count%*statsevery == 0 {
			ref := packet.Metadata().CaptureInfo.Timestamp
			flushed, closed := assembler.FlushWithOptions(reassembly.FlushOptions{T: ref.Add(-timeout), TC: ref.Add(-closeTimeout)})
			fmt.Printf(" -- forced flush: %d flushed, %d closed (%s)\n", flushed, closed, ref)
		}

		/*
			if err := parser.DecodeLayers(data, &decoded); err != nil {
				// Well it sures complaing about not knowing how to decode TCP
			}

			for _, layerType := range decoded {
				switch layerType {
				case layers.LayerTypeIPv6:
					//fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
				case layers.LayerTypeIPv4:
					//				fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP, len(data))

					//ref := packet.Metadata().CaptureInfo.Timestamp
					//flushed, closed := assembler.FlushWithOptions(reassembly.FlushOptions{T: ref.Add(time.Minute * 30), TC: ref.Add(time.Minute * 5)})
					//Debug("Forced flush: %d flushed, %d closed (%s)", flushed, closed, ref)
				}
			}
		*/

		select {
		case <-signalChan:
			fmt.Fprintf(os.Stderr, "\nCaught SIGINT: aborting\n")
			if outFile != nil {
				outFile.Close()
			}
			cancelC <- "stop"
			done = true
			break
		default:
			// NOP: continue
		}
		if done {
			break
		}
	}

	Info(fmt.Sprintf("%d Bytes read.\n", bytes))

	assembler.FlushAll()
	streamFactory.WaitGoRoutines()

	fmt.Printf("TCP stats:\n")
	fmt.Printf(" missed bytes:\t\t%d\n", stats.missedBytes)
	fmt.Printf(" total packets:\t\t%d\n", stats.pkt)
	fmt.Printf(" rejected FSM:\t\t%d\n", stats.rejectFsm)
	fmt.Printf(" rejected Options:\t%d\n", stats.rejectOpt)
	fmt.Printf(" reassembled bytes:\t%d\n", stats.sz)
	fmt.Printf(" total TCP bytes:\t%d\n", stats.totalsz)
	fmt.Printf(" conn rejected FSM:\t%d\n", stats.rejectConnFsm)
	fmt.Printf(" reassembled chunks:\t%d\n", stats.reassembled)
	fmt.Printf(" out-of-order packets:\t%d\n", stats.outOfOrderPackets)
	fmt.Printf(" out-of-order bytes:\t%d\n", stats.outOfOrderBytes)
	fmt.Printf(" biggest-chunk packets:\t%d\n", stats.biggestChunkPackets)
	fmt.Printf(" biggest-chunk bytes:\t%d\n", stats.biggestChunkBytes)
	fmt.Printf(" overlap packets:\t%d\n", stats.overlapPackets)
	fmt.Printf(" overlap bytes:\t\t%d\n", stats.overlapBytes)
	fmt.Printf("Errors: %d\n", errors)
	for e, _ := range errorsMap {
		fmt.Printf(" %s:\t\t%d\n", e, errorsMap[e])
	}

	// All systems gone
	// We close the processing queue
	close(jobQ)
	w.Wait()
}

// queueSession tries to enqueue the session for output
// returns true if it succeeded or false if it failed to publish the
func (t *tcpStream) queueSession() bool {
	t.queued = true
	select {
	case jobQ <- t.sshSession:
		return true
	default:
		return false
	}
}

func processCompletedSession(cancelC <-chan string, jobQ <-chan SSHSession, w *sync.WaitGroup) {
	defer func() {
		w.Done()

	}()
	for {
		select {
		case m, more := <-jobQ:
			if more {
				output(m)
			} else {
				return
			}
		case <-cancelC:
			return
		}
	}
}

func output(t SSHSession) {
	var jsonRecord []byte
	if *jsonIndent {
		jsonRecord, _ = json.MarshalIndent(t, "", "    ")
	} else {
		jsonRecord, _ = json.Marshal(t)
	}

	// If an output folder was specified for json files
	if *outJSON != "" {
		if _, err := os.Stat(fmt.Sprintf("./%s", *outJSON)); !os.IsNotExist(err) {
			var err error
			if len(*outFilename) < 1 {
				err = ioutil.WriteFile(fmt.Sprintf("./%s/%s.json", *outJSON, t.Timestamp.Format(time.RFC3339)), jsonRecord, 0644)
			} else {

				// First time, set the file descriptor
				if outFile == nil {
					filename := fmt.Sprintf("./%s/%s", *outJSON, *outFilename)
					outFile, err = os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
					if err != nil {
						panic("Could not open file to write")
					}
				}

				_, err = fmt.Fprintf(outFile, "%s", jsonRecord)
			}
			if err != nil {
				panic("Could not write to file.")
			}
		} else {
			panic(fmt.Sprintf("./%s does not exist", *outJSON))
		}
		// If not folder specidied, we output to stdout
	} else {
		r := bytes.NewReader(jsonRecord)
		_, err := io.Copy(os.Stdout, r)
		if err != nil {
			panic("Could not write to stdout.")
		}
		fmt.Println()
	}

	//	Debug(t.String())
}
