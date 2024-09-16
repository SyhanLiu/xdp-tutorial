package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
)

const (
	filename string = "xdp_pass_kern.o"
	progname string = "xdp_prog_simple"
)

var (
	help        = flag.Bool("help", false, "Show help")
	dev         = flag.String("dev", "", "Operate on device <ifname>")
	skb_mode    = flag.Bool("skb-mode", false, "Install XDP program in SKB (AKA generic) mode")
	native_mode = flag.Bool("native-mode", false, "Install XDP program in native mode")
	auto_mode   = flag.Bool("auto-mode", false, "Auto-detect SKB or native mode")
	unload      = flag.Uint64("unload", 0, "Unload XDP program <id> instead of loading")
	unload_all  = flag.Bool("unload-all", false, "Unload all XDP programs on device")
)

func main() {
	flag.Parse()
	if *help == true || flag.NFlag() == 0 {
		flag.VisitAll(func(f *flag.Flag) {
			fmt.Printf("%s: %s, defaultVal:%s, realVal:%s\n", f.Name, f.Usage, f.DefValue, f.Value)
		})
		return
	}

	if dev == nil {
		fmt.Println("must input device <ifname>")
		return
	}
	iface, err := net.InterfaceByName(*dev)
	if err != nil {
		fmt.Printf("ifname:%s, not found\n", *dev)
		return
	}

	if *skb_mode {
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   nil,
			Interface: iface.Index,
		})
		if err != nil {
			fmt.Printf("ifname:%s skb_mode error:%s\n", iface.Name, err.Error())
			return
		}
		_ = l
		return
	}

	if *unload != 0 {

		return
	}

	if *unload_all {

		return
	}

	// ebpf.XDP.
}
