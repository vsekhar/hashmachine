package main

import (
	"fmt"
	"log"

	"github.com/vsekhar/hashmachine"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

func main() {
	// TODO: `hashmachine verify` command.

	// Try some stuff out
	var hashInput3 *hashmachine.Program = &hashmachine.Program{
		Metadata: &hashmachine.ProgramMetadata{
			HashConfig: &hashmachine.HashConfig{
				HashFunction: hashmachine.HashFunction_HASHFUNCTION_SHA_256,
			},
			ExpectedInputCount: 3,
			BranchingFactor:    0,
		},
		Ops: []*hashmachine.Op{
			{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 2},
			{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 1},
			{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0},
			{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH, Index: 3},
		},
	}

	fmt.Print(prototext.Format(hashInput3))
	out, err := proto.Marshal(hashInput3)
	if err != nil {
		log.Fatalln("Failed to encode hashmachine proto:", err)
	}
	log.Println("Encoded length:", len(out), "bytes")
}
