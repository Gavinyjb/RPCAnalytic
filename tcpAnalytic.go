package main

import (
	"fmt"
	"github.com/imroc/biu"
	"strconv"
)
func hex2bin(hex string) string {
	var bin string

	for i := 0; i < len(hex); i++ {
		hex2int, _ := strconv.ParseInt(string(hex[i]), 16, 64)
		bin = bin + fmt.Sprintf("%04b", hex2int)
	}

	return bin
}

func main() {
	atcp := "18568083740d80fb06e2dcaa08004500004b97bb40002906a1de23a599fe0a1b5055075bf3bf09e64248ef388e9c80180004774000000101080aa79e3d4a934589973015000a746f7069632f746573744d6573736167652039"
	bintcp := hex2bin(atcp)

	sourcePort, _  := strconv.ParseInt(bintcp[0:16], 2, 64)
	fmt.Printf("sourcePort is %d \n", sourcePort)

	destinationPort, _  := strconv.ParseInt(bintcp[16:32], 2, 64)
	fmt.Printf("destinationPort is %d \n", destinationPort)

	sequenceNumber, _  := strconv.ParseInt(bintcp[32:64], 2, 64)
	fmt.Printf("sequenceNumber is %d \n", sequenceNumber)

	acknowledgmentNumber, _  := strconv.ParseInt(bintcp[64:96], 2, 64)
	fmt.Printf("acknowledgmentNumber is %d \n", acknowledgmentNumber)

	dataOffset, _  := strconv.ParseInt(bintcp[96:100], 2, 64)
	fmt.Printf("dataOffset is %d \n", dataOffset)

	reserved, _  := strconv.ParseInt(bintcp[100:106], 2, 64)
	fmt.Printf("reserved is %d \n", reserved)

	// Control Bits 控制位，从106-1012共有6位，每位表示一个控制位的开关
	urg, _ := strconv.ParseInt(bintcp[106:107], 2, 64)
	ack, _ := strconv.ParseInt(bintcp[107:108], 2, 64)
	psh, _ := strconv.ParseInt(bintcp[108:109], 2, 64)
	rst, _ := strconv.ParseInt(bintcp[109:110], 2, 64)
	syn, _ := strconv.ParseInt(bintcp[110:111], 2, 64)
	fin, _ := strconv.ParseInt(bintcp[111:112], 2, 64)
	fmt.Printf("控制位标识如下:\n")
	fmt.Printf("    urg: %d\n", urg)
	fmt.Printf("    ack: %d\n", ack)
	fmt.Printf("    psh: %d\n", psh)
	fmt.Printf("    rst: %d\n", rst)
	fmt.Printf("    syn: %d\n", syn)
	fmt.Printf("    fin: %d\n", fin)

	// 数据窗口 16位
	window, _  := strconv.ParseInt(bintcp[112:128], 2, 64)
	fmt.Printf("window is %d \n", window)

	// checksum 16位
	checksum, _  := strconv.ParseInt(bintcp[128:144], 2, 64)
	fmt.Printf("checksum is %d \n", checksum)

	// urgentPointer
	urgentPointer, _ := strconv.ParseInt(bintcp[144:160], 2, 64)
	fmt.Printf("urgentPointer is %d \n", urgentPointer)

	// options and padding
	optionsAndPaddings := bintcp[160:]
	fmt.Printf("optionsAndPaddings is %s \n", optionsAndPaddings)

	fmt.Printf("tcp raw data is %s \n", atcp)
	fmt.Printf("tcp bin data is %s \n", bintcp)
	temp:=biu.BinaryStringToBytes(bintcp)
	fmt.Printf("bintcp:%v\n",string(temp))
	fmt.Printf("tcp bin data length is %d\n", len(bintcp))
}

