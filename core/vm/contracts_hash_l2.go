// Copyright 2025 The op-geth Authors.
// Hash-Only L2 — ECDSA-free OP Stack rollup
// SPDX-License-Identifier: LGPL-2.1-or-later

package vm

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Hash-L2 precompile addresses — 0x01xx range (OP-Stack extended, avoids BLS12-381 at 0x0b–0x11).
var (
	// HashAddrPrecompileAddress is the address of the hashAddr precompile.
	// Computes: addr = trunc20(keccak256("OP_HASH_ADDR_v1" ‖ commitment))
	HashAddrPrecompileAddress = common.BytesToAddress([]byte{0x01, 0x01})

	// VerifyHashChainAddress is the address of the verifyHashChain precompile.
	// Verifies one hash-chain step: keccak256(curr) == prev.
	VerifyHashChainAddress = common.BytesToAddress([]byte{0x01, 0x02})
)

// hashAddrDomain is the domain tag for commitment-to-address derivation.
// Must match NullifierTree.ADDR_DOMAIN and OptimismPortalHash.HASH_ADDR_DOMAIN.
var hashAddrDomainBytes = crypto.Keccak256Hash([]byte("OP_HASH_ADDR_v1"))

// AddHashL2Precompiles inserts the Hash-L2 precompiles into an existing PrecompiledContracts
// map. Call this when constructing the Onyx (or later) fork's precompile set.
func AddHashL2Precompiles(contracts PrecompiledContracts) {
	contracts[HashAddrPrecompileAddress] = &hashAddrPrecompile{}
	contracts[VerifyHashChainAddress] = &verifyHashChainPrecompile{}
}

// -------------------------------------------------------------------------
// 0x0101  hashAddr
// -------------------------------------------------------------------------

// hashAddrPrecompile computes the L2 address for a given hash-chain commitment.
//
// Input:  32 bytes — the commitment C (e.g. keccak256("OP_COMMIT_v1" ‖ ...))
// Output: 32 bytes — left-padded 20-byte L2 address (same format as ecrecover)
//
// Computation: addr = trunc20(keccak256("OP_HASH_ADDR_v1" ‖ input[0:32]))
//
// Gas: HashAddrGas (flat, one keccak256 call equivalent)
//
// Error: returns nil output (not an error) if input is shorter than 32 bytes,
// consistent with how ecrecover handles malformed input.
type hashAddrPrecompile struct{}

const HashAddrGas = 600 // ~2× Keccak256WordGas for 64-byte input (domain + commitment)

func (c *hashAddrPrecompile) RequiredGas(_ []byte) uint64 {
	return HashAddrGas
}

func (c *hashAddrPrecompile) Run(input []byte) ([]byte, error) {
	if len(input) < 32 {
		// Under-length input: return zero address, not an error.
		return common.LeftPadBytes(nil, 32), nil
	}

	var commitment [32]byte
	copy(commitment[:], input[:32])

	addr := commitmentToAddr(commitment)
	return common.LeftPadBytes(addr[:], 32), nil
}

func (c *hashAddrPrecompile) Name() string { return "HASH_ADDR" }

// -------------------------------------------------------------------------
// 0x0102  verifyHashChain
// -------------------------------------------------------------------------

// verifyHashChainPrecompile verifies a single hash-chain step.
//
// Input:  64 bytes — [prev 32 bytes][curr 32 bytes]
//   where prev = lastReveal[account] (the stored parent element)
//   and   curr = preImage being revealed (s_{N-k})
//
// Output: 32 bytes — 0x00..01 (true) if keccak256(curr) == prev, else 0x00..00 (false)
//
// This is a gas-cheap alternative to performing the keccak check in Solidity.
// Gas: VerifyHashChainGas (flat, one keccak256 call equivalent)
//
// Error: returns (false, error) if input is shorter than 64 bytes.
type verifyHashChainPrecompile struct{}

const VerifyHashChainGas = 600 // same as HashAddrGas — one keccak on 32-byte input

func (c *verifyHashChainPrecompile) RequiredGas(_ []byte) uint64 {
	return VerifyHashChainGas
}

func (c *verifyHashChainPrecompile) Run(input []byte) ([]byte, error) {
	if len(input) < 64 {
		return nil, fmt.Errorf("verifyHashChain: input too short (%d bytes, need 64)", len(input))
	}

	var prev, curr [32]byte
	copy(prev[:], input[0:32])
	copy(curr[:], input[32:64])

	// Verify: keccak256(curr) == prev
	computed := crypto.Keccak256Hash(curr[:])
	result := make([]byte, 32)
	if computed == common.Hash(prev) {
		result[31] = 1
	}
	return result, nil
}

func (c *verifyHashChainPrecompile) Name() string { return "VERIFY_HASH_CHAIN" }

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

// commitmentToAddr derives the 20-byte L2 address from a commitment hash.
// Mirrors OptimismPortalHash.commitmentToAddress() and NullifierState address derivation.
func commitmentToAddr(commitment [32]byte) common.Address {
	var input [64]byte
	copy(input[:32], hashAddrDomainBytes[:])
	copy(input[32:], commitment[:])
	h := crypto.Keccak256Hash(input[:])
	return common.BytesToAddress(h[12:])
}
