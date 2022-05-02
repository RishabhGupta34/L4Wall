package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vishvananda/netlink"
)

var objs struct {
	XCProg        *ebpf.Program `ebpf:"xdp_traffic_pass"`
	PktCnt        *ebpf.Map     `ebpf:"pkt_cnt"`
	PktDrop       *ebpf.Map     `ebpf:"pkt_drop"`
	AllowedSrcDst *ebpf.Map     `ebpf:"allowed_src_dst"`
}

type PktData struct {
	SrcAddr  [4]uint8
	DstAddr  [4]uint8
	DstPort  uint16
	Protocol [3]byte
}
type SrcConfig struct {
	SrcAddr [4]uint8
}
type DstConfig struct {
	DstSubnets []net.IPNet
}

func CreateLPMtrieKey(s string) net.IPNet {
	var ipnet *net.IPNet
	// Check if given address is CIDR
	if strings.Contains(s, "/") {
		_, ipnet, _ = net.ParseCIDR(s)
	} else {
		if strings.Contains(s, ":") {
			// IPv6
			_, ipnet, _ = net.ParseCIDR(s + "/128")
		} else {
			// IPv4
			_, ipnet, _ = net.ParseCIDR(s + "/32")
		}
	}
	return *ipnet
}

func setupSigHandlers(link *netlink.Link, cancel context.CancelFunc) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	go func() {
		sig := <-sigs
		err := delXdpFromLink(link)
		if err != nil {
			fmt.Println(err)
			return
		}
		log.Printf("Received syscall:%+v", sig)
		cancel()
	}()
}

func xdpFlags(linkType string) int {
	if linkType == "veth" || linkType == "tuntap" {
		return 2
	}
	return 0 // native xdp (xdpdrv) by default
}

func lookupLink(intf string) (*netlink.Link, error) {
	link, err := netlink.LinkByName(intf)
	if err != nil {
		return nil, err
	}
	return &link, nil
}

func delXdpFromLink(link *netlink.Link) error {
	err := netlink.LinkSetXdpFdWithFlags(*link, -1, xdpFlags((*link).Type()))
	return err
}

var (
	iface         = flag.String("iface", "eth0", "Interface")
	objFileName   = flag.String("obj_file", "./bpf/pkt_kern.o", "Object file name")
	srcIps        = flag.String("src_vip", "", "src vip")
	dstIps        = flag.String("dst_subnets", "", "dst subnets")
	dstPorts      = flag.String("dst_ports", "", "dst ports")
	protocols     = flag.String("protocols", "", "protocols")
	pktCntMetrics = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pkt_firewall",
		Name:      "pkt_count",
		Help:      "pkt count",
	}, []string{"host", "src_ip", "dst_ip", "dst_port", "protocol"})
	pktDropMetrics = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pkt_firewall",
		Name:      "pkt_drop",
		Help:      "pkt drop",
	}, []string{"host", "src_ip", "dst_ip", "dst_port", "protocol"})
)

func ConvertIPToUInt(ip string) [4]uint8 {
	s := strings.Split(ip, "/")
	s = strings.Split(ip, ".")
	var addr [4]uint8
	for i, bit := range s {
		a, err := strconv.ParseUint(bit, 10, 64)
		if err != nil {
			fmt.Println("Address invalid")
			return [4]uint8{}
		}
		addr[i] = uint8(a)
	}
	return addr
}

func ConvertUIntToIP(addr [4]uint8) string {
	s := ""
	for _, bit := range addr {
		s = s + strconv.Itoa(int(bit)) + "."
	}
	return s[:len(s)-1]
}

func setupMetricsServer(port string) {
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(port, nil); err != nil {
			log.Fatalf("Error while starting metrics server: %s", err)
		}
	}()
}

func InsertConfig(outerMap *ebpf.Map, config map[SrcConfig]DstConfig) {
	var test2 uint32
	innerMapSpec := ebpf.MapSpec{
		Type:       ebpf.LPMTrie,
		KeySize:    40,
		ValueSize:  uint32(reflect.TypeOf(test2).Size()),
		MaxEntries: 100,
	}

	for k, v := range config {
		newMap, err := ebpf.NewMap(&innerMapSpec)
		if err != nil {
			fmt.Println("Error in creating map: ", err)
		}
		for _, dst := range v.DstSubnets {
			if err := newMap.Put(dst, uint32(1)); err != nil {
				log.Fatalf("error in adding val to innermap: ", err)
			}
		}
		if err := outerMap.Put(v, uint32(1)); err != nil {
			log.Fatalf("error in adding val to innermap: ", err)
		}
		info, err := newMap.Info()
		if err != nil {
			log.Fatalf("Unable to fetch info for the map")
		}
		if _, ok := info.ID(); ok {
			if err := outerMap.Put(k, uint32(newMap.FD())); err != nil {
				log.Printf("error in adding val to outermap: ", err)
			}
		}
	}
}
func ReadMetrics(pktCnt, pktDrop *ebpf.Map) {
	for true {
		time.Sleep(10 * time.Second)
		var (
			key     PktData
			value   uint32
			entries = pktCnt.Iterate()
		)
		for entries.Next(&key, &value) {
			pktCntMetrics.WithLabelValues(ConvertUIntToIP(key.SrcAddr), ConvertUIntToIP(key.DstAddr), strconv.Itoa(int(key.DstPort)), string(key.Protocol[:])).Set(float64(value))
		}
		entries = pktDrop.Iterate()
		for entries.Next(&key, &value) {
			pktDropMetrics.WithLabelValues(ConvertUIntToIP(key.SrcAddr), ConvertUIntToIP(key.DstAddr), strconv.Itoa(int(key.DstPort)), string(key.Protocol[:])).Set(float64(value))
		}
	}
}

func ParseIPs(srcIps, dstIps, dstPorts, protocols string) map[SrcConfig]DstConfig {
	SrcIPs := strings.Split(strings.Trim(srcIps, " "), ",")
	DstIPs := strings.Split(strings.Trim(dstIps, " "), ",")
	DstPorts := strings.Split(strings.Trim(dstPorts, " "), ",")
	Protocols := strings.Split(strings.Trim(protocols, " "), ",")
	l := len(SrcIPs)
	config := make(map[SrcConfig]DstConfig, 0)
	for i := 0; i < l; i++ {
		var prt [3]byte
		copy(prt[:], Protocols[i])
		_, err := strconv.ParseUint(DstPorts[i], 10, 64)
		if err != nil {
			fmt.Println("invalid dst port")
			continue
		}
		config[SrcConfig{SrcAddr: ConvertIPToUInt(SrcIPs[i])}] = DstConfig{[]net.IPNet{CreateLPMtrieKey(DstIPs[i])}}
		//dst := PktData{
		//	SrcAddr:  ConvertIPToUInt(SrcIPs[i]),
		//	DstSubnet:  CreateLPMtrieKey(DstIPs[i]),
		//}
		//config = append(config, dst)
	}
	return config
}

func main() {
	flag.Parse()
	go setupMetricsServer(":9100")
	fmt.Printf("Interface: %s, Object file: %s", *iface, *objFileName)
	link, err := lookupLink(*iface)
	if err != nil {
		fmt.Printf("Link not found: %s\n", err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func(ctx context.Context, link *netlink.Link) {
		for {
			select {
			case <-ctx.Done():
				err := delXdpFromLink(link)
				if err != nil {
					fmt.Println(err)
					return
				}
				log.Printf("ctx.Done")
				return
			}
		}
	}(ctx, link)
	setupSigHandlers(link, cancel)
	fmt.Println("load coll.")
	spec, err := ebpf.LoadCollectionSpec(*objFileName)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("load and assign")
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Configuring firewall rules")
	config := ParseIPs(*srcIps, *dstIps, *dstPorts, *protocols)
	InsertConfig(objs.AllowedSrcDst, config)
	defer func(XCProg *ebpf.Program) {
		err := XCProg.Close()
		if err != nil {

		}
	}(objs.XCProg)
	log.Printf("Attaching xdp to the interface: %s\n", *iface)
	go ReadMetrics(objs.PktCnt, objs.PktDrop)
	err = netlink.LinkSetXdpFdWithFlags(*link, objs.XCProg.FD(), xdpFlags((*link).Type()))
	if err != nil {
		fmt.Println(err)
		return
	}
}
