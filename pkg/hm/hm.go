// Package hm provides the implementation of the hash machine.
package hm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"

	"github.com/vsekhar/hashmachine"
)

type HashMaker interface {
	Make() hash.Hash
}

type HashMachine struct {
	program *hashmachine.Program
	inputs  [][]byte

	ip        int
	hashMaker func() hash.Hash
	stack     [][]byte
}

func New(p *hashmachine.Program, inputs [][]byte) (*HashMachine, error) {
	var hm func() hash.Hash
	switch p.Metadata.Hash {
	case hashmachine.Hash_HASH_SHA256:
		hm = sha256.New
	default:
		return nil, fmt.Errorf("unknown hash function: %s", p.Metadata.Hash.String())
	}
	if p.Metadata.BranchingFactor < 1 {
		return nil, fmt.Errorf("bad branching factor in metadata: %d", p.Metadata.BranchingFactor)
	}
	if int(p.Metadata.ExpectedInputCount) != len(inputs) {
		return nil, fmt.Errorf("invalid input count: program expected %d, got %d", p.Metadata.ExpectedInputCount, len(inputs))
	}

	return &HashMachine{
		program:   p,
		inputs:    inputs,
		hashMaker: hm,
	}, nil
}

func (hm *HashMachine) push(b []byte) {
	hm.stack = append(hm.stack, b)
}

func (hm *HashMachine) pop() []byte {
	r := hm.stack[len(hm.stack)-1]
	hm.stack = hm.stack[:len(hm.stack)-1]
	return r
}

func (hm *HashMachine) Output() ([]byte, error) {
	if len(hm.stack) != 1 {
		return nil, fmt.Errorf("invalid program: expected one output on stack, stack size: %d", len(hm.stack))
	}
	return hm.pop(), nil
}

func (hm *HashMachine) Step() error {
	op := hm.program.Ops[hm.ip]
	hm.ip++
	switch op.Opcode {
	case hashmachine.OpCode_OPCODE_UNKNOWN:
		return errors.New("invalid program: opcode is UNKNOWN")
	case hashmachine.OpCode_OPCODE_PUSH_INPUT:
		if int(op.Index) >= len(hm.inputs) {
			return fmt.Errorf("invalid program: input index out of bounds %d, %d inputs", op.Index, len(hm.inputs))
		}
		hm.push(hm.inputs[op.Index])
	case hashmachine.OpCode_OPCODE_PUSH_BYTES:
		hm.push(op.Payload)
	case hashmachine.OpCode_OPCODE_POP_CHILDREN_HASH_AND_PUSH:
		if len(hm.stack) < int(hm.program.Metadata.BranchingFactor) {
			return fmt.Errorf("invalid program: stack underflow, expected at least %d values, found %d", int(hm.program.Metadata.BranchingFactor), len(hm.stack))
		}
		h := hm.hashMaker()
		for i := 0; i < int(hm.program.Metadata.BranchingFactor); i++ {
			h.Write(hm.pop())
		}
		hm.push(h.Sum(nil))
	case hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH:
		if len(hm.stack) == 0 {
			return errors.New("invalid program: stack empty (OPCODE_POP_N_HASH_AND_PUSH)")
		}
		h := hm.hashMaker()
		for i := 0; i < int(op.Index); i++ {
			h.Write(hm.pop())
		}
		hm.push(h.Sum(nil))
		/*
			case hashmachine.OpCode_OPCODE_POP_AND_WRITE:
				b := hm.pop()
				if hm.curHash == nil {
					hm.curHash = hm.hashMaker()
				}
				hm.curHash.Write(b)
			case hashmachine.OpCode_OPCODE_READ_PUSH_AND_CLOSE:
				if hm.curHash == nil {
					return errors.New("invalid program: no active hasher")
				}
				b := hm.curHash.Sum(nil)
				hm.push(b)
				hm.curHash = nil
		*/
	default:
		return fmt.Errorf("invalid program: unkonwn opcode %d", op.Opcode)
	}
	return nil
}

func (hm *HashMachine) Done() bool {
	return hm.ip == len(hm.program.Ops)
}
