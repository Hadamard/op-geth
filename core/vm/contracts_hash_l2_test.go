// Copyright 2025 The op-geth Authors.
// Hash-Only L2 — ECDSA-free OP Stack rollup
// SPDX-License-Identifier: LGPL-2.1-or-later

package vm

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// TestHashAddrPrecompile verifies that the hashAddr precompile (0x0101) produces the
// same address as the Go helper and the Solidity commitmentToAddress() function.
func TestHashAddrPrecompile(t *testing.T) {
	t.Parallel()

	commitment := crypto.Keccak256Hash([]byte("test-commitment"))

	// Expected: trunc20(keccak256(domain ‖ commitment))
	domain := crypto.Keccak256Hash([]byte("OP_HASH_ADDR_v1"))
	var input [64]byte
	copy(input[:32], domain[:])
	copy(input[32:], commitment[:])
	expected := common.BytesToAddress(crypto.Keccak256Hash(input[:]).Bytes()[12:])

	// Run precompile
	p := &hashAddrPrecompile{}
	out, err := p.Run(commitment[:])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("expected 32-byte output, got %d", len(out))
	}
	got := common.BytesToAddress(out[12:])
	if got != expected {
		t.Errorf("address mismatch: got %s, want %s", got, expected)
	}

	// Gas must be fixed regardless of input length
	if g := p.RequiredGas(commitment[:]); g != HashAddrGas {
		t.Errorf("wrong gas: got %d, want %d", g, HashAddrGas)
	}
}

// TestHashAddrPrecompile_ShortInput verifies graceful handling of under-length input.
func TestHashAddrPrecompile_ShortInput(t *testing.T) {
	t.Parallel()

	p := &hashAddrPrecompile{}
	out, err := p.Run([]byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("short input should not error: %v", err)
	}
	// Should return zero address
	if common.BytesToAddress(out[12:]) != (common.Address{}) {
		t.Error("short input should return zero address")
	}
}

// TestVerifyHashChainPrecompile verifies both the valid and invalid chain-step cases.
func TestVerifyHashChainPrecompile(t *testing.T) {
	t.Parallel()

	p := &verifyHashChainPrecompile{}

	// Build a valid chain step: curr → prev = keccak256(curr)
	curr := crypto.Keccak256Hash([]byte("s_N-k"))
	prev := crypto.Keccak256Hash(curr[:]) // prev = keccak256(curr)

	var validInput [64]byte
	copy(validInput[:32], prev[:])
	copy(validInput[32:], curr[:])

	out, err := p.Run(validInput[:])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out[31] != 1 {
		t.Error("expected valid chain step to return 0x01")
	}

	// Invalid step: curr is wrong
	wrong := crypto.Keccak256Hash([]byte("wrong-element"))
	var invalidInput [64]byte
	copy(invalidInput[:32], prev[:])
	copy(invalidInput[32:], wrong[:])

	out, err = p.Run(invalidInput[:])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out[31] != 0 {
		t.Error("expected invalid chain step to return 0x00")
	}

	// Gas must be fixed
	if g := p.RequiredGas(validInput[:]); g != VerifyHashChainGas {
		t.Errorf("wrong gas: got %d, want %d", g, VerifyHashChainGas)
	}
}

// TestVerifyHashChainPrecompile_ShortInput verifies that short input returns an error.
func TestVerifyHashChainPrecompile_ShortInput(t *testing.T) {
	t.Parallel()

	p := &verifyHashChainPrecompile{}
	_, err := p.Run(make([]byte, 32))
	if err == nil {
		t.Error("expected error for short input (< 64 bytes)")
	}
}

// TestPrecompiledContractsOnyx verifies that the Onyx set contains the Hash-L2 precompiles.
func TestPrecompiledContractsOnyx(t *testing.T) {
	t.Parallel()

	if _, ok := PrecompiledContractsOnyx[HashAddrPrecompileAddress]; !ok {
		t.Errorf("Onyx set missing hashAddr at %s", HashAddrPrecompileAddress)
	}
	if _, ok := PrecompiledContractsOnyx[VerifyHashChainAddress]; !ok {
		t.Errorf("Onyx set missing verifyHashChain at %s", VerifyHashChainAddress)
	}

	// Onyx must be a superset of Isthmus
	for addr := range PrecompiledContractsIsthmus {
		if _, ok := PrecompiledContractsOnyx[addr]; !ok {
			t.Errorf("Onyx set missing Isthmus precompile at %s", addr)
		}
	}
}

// TestCommitmentRoundtrip verifies that hashAddr(precompile) == NullifierState address derivation.
// Both must agree for the deposit flow (op-node derives address, precompile used in contracts).
func TestCommitmentRoundtrip(t *testing.T) {
	t.Parallel()

	seed := []byte("test-seed-for-hash-l2-roundtrip")
	commitment := crypto.Keccak256Hash(seed)

	// Via precompile
	p := &hashAddrPrecompile{}
	out, _ := p.Run(commitment[:])
	addrFromPrecompile := common.BytesToAddress(out[12:])

	// Direct Go computation (same as NullifierState._deriveAddress and op-node CommitmentToL2Address)
	domain := crypto.Keccak256Hash([]byte("OP_HASH_ADDR_v1"))
	var buf [64]byte
	copy(buf[:32], domain[:])
	copy(buf[32:], commitment[:])
	addrDirect := common.BytesToAddress(crypto.Keccak256Hash(buf[:]).Bytes()[12:])

	if addrFromPrecompile != addrDirect {
		t.Errorf("address mismatch:\n  precompile: %s\n  direct:     %s", addrFromPrecompile, addrDirect)
	}
}
