package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
)

//var (
//	//device:网络设备的名称，如 eth0,也可以填充 pcap.FindAllDevs() 返回的设备的 Name
//	device string = "en0"
//	//snaplen: 每个数据包读取的最大长度 the maximum size to read for each packet
//	snapshotLen int32 = 1024
//	//promiscuous:是否将网口设置为混杂模式,即是否接收目的地址不为本机的包
//	promiscuous bool = false
//	err         error
//	//timeout:设置抓到包返回的超时。如果设置成 30s，那么每 30s 才会刷新一次数据包；设置成负数，会立刻刷新数据包，即不做等待
//	timeout time.Duration = 3 * time.Second
//	//函数返回值：是一个 *Handle 类型的返回值，可能作为 gopacket 其他函数调用时作为函数参数来传递。
//
//	handle *pcap.Handle
//)

func main() {
	// 打开某一网络设备
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		fmt.Println(packet)
	}
}
