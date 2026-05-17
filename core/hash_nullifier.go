// Copyright 2025 The op-geth Authors.
// Hash-Only L2 — ECDSA-free OP Stack rollup
// SPDX-License-Identifier: LGPL-2.1-or-later

package core

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/core/vm"
)

// NullifierTreeAddress is the predeploy address of the NullifierTree contract on L2.
// Must match the value declared in op-node/rollup/derive/deposit_log_hash.go and
// packages/contracts-bedrock/src/L2/NullifierTree.sol.
var NullifierTreeAddress = common.HexToAddress("0x4200000000000000000000000000000000000042")

// NullifierState wraps a vm.StateDB for typed access to NullifierTree predeploy storage.
//
// NullifierTree Solidity storage layout (relevant slots):
//   slot 0:   systemCaller (address, 20B) + _initialized (bool, 1B) — packed
//   slot 1:   spentNullifiers  mapping(address => mapping(bytes32 => bool))
//   slot 2:   commitmentOf     mapping(address => bytes32)
//   slot 3:   lastReveal       mapping(address => bytes32)
//   slot 4:   chainDepth       mapping(address => uint32)
//   slots 5–71: IMT state (nextLeafIndex, nullifierMerkleRoot, filledSubtrees, _zeros)
//   slot 72:  stealthPoolCaller (address)
//   slot 73:  pendingCommits   mapping(address => bytes32)  — cross-block commit value
//   slot 74:  commitExpiry     mapping(address => uint64)   — expiry block (right-aligned)
//
// All slot calculations use Solidity's standard keccak256(abi.encode(key, baseSlot)).
type NullifierState struct {
	state vm.StateDB
}

func NewNullifierState(state vm.StateDB) *NullifierState {
	return &NullifierState{state: state}
}

// IsRegistered returns true if the account has a registered commitment.
func (n *NullifierState) IsRegistered(account common.Address) bool {
	slot := mappingSlot(addrToHash(account), 2)
	v := n.state.GetState(NullifierTreeAddress, slot)
	return v != (common.Hash{})
}

// CommitmentOf returns the registered commitment for the account (zero if none).
func (n *NullifierState) CommitmentOf(account common.Address) common.Hash {
	slot := mappingSlot(addrToHash(account), 2)
	return n.state.GetState(NullifierTreeAddress, slot)
}

// LastReveal returns the last-revealed hash-chain element for the account.
// For Phase 0 one-time commitments this equals the commitment itself initially.
func (n *NullifierState) LastReveal(account common.Address) common.Hash {
	slot := mappingSlot(addrToHash(account), 3)
	return n.state.GetState(NullifierTreeAddress, slot)
}

// ChainDepth returns the remaining hash-chain depth for the account.
func (n *NullifierState) ChainDepth(account common.Address) uint32 {
	slot := mappingSlot(addrToHash(account), 4)
	v := n.state.GetState(NullifierTreeAddress, slot)
	// chainDepth is a uint32 stored right-aligned in the 32-byte slot.
	return uint32(v[28])<<24 | uint32(v[29])<<16 | uint32(v[30])<<8 | uint32(v[31])
}

// IsSpent returns true if the nullifier has been spent for the given account.
func (n *NullifierState) IsSpent(account common.Address, nullifier common.Hash) bool {
	innerSlot := mappingSlot(addrToHash(account), 1)
	slot := mappingSlot(nullifier, innerSlot)
	v := n.state.GetState(NullifierTreeAddress, slot)
	return v[31] != 0
}

// MarkSpent records a nullifier as spent and advances the hash-chain pointer.
// Caller must have already verified:
//   - keccak256(preImage) == LastReveal(account)
//   - !IsSpent(account, nullifier)
//   - ChainDepth(account) > 0
func (n *NullifierState) MarkSpent(account common.Address, nullifier common.Hash, preImage common.Hash) {
	// Mark nullifier spent: spentNullifiers[account][nullifier] = true
	innerSlot := mappingSlot(addrToHash(account), 1)
	nullSlot := mappingSlot(nullifier, innerSlot)
	var trueVal common.Hash
	trueVal[31] = 1
	n.state.SetState(NullifierTreeAddress, nullSlot, trueVal)

	// Advance hash-chain: lastReveal[account] = preImage
	revealSlot := mappingSlot(addrToHash(account), 3)
	n.state.SetState(NullifierTreeAddress, revealSlot, preImage)

	// Decrement chain depth: chainDepth[account]--
	depthSlot := mappingSlot(addrToHash(account), 4)
	cur := n.ChainDepth(account)
	if cur > 0 {
		cur--
	}
	var depthVal common.Hash
	depthVal[28] = byte(cur >> 24)
	depthVal[29] = byte(cur >> 16)
	depthVal[30] = byte(cur >> 8)
	depthVal[31] = byte(cur)
	n.state.SetState(NullifierTreeAddress, depthSlot, depthVal)
}

// RenewChain sets a new commitment anchor after the previous chain is exhausted.
// Must be called only when ChainDepth(account) == 0.
// Caller must have verified that newCommitment derives to account via trunc20(keccak256(ADDR_DOMAIN ‖ C)).
func (n *NullifierState) RenewChain(account common.Address, newCommitment common.Hash, newChainLength uint32) {
	// commitmentOf[account] = newCommitment
	commitSlot := mappingSlot(addrToHash(account), uint64(2))
	n.state.SetState(NullifierTreeAddress, commitSlot, newCommitment)

	// lastReveal[account] = newCommitment  (new chain anchor)
	revealSlot := mappingSlot(addrToHash(account), uint64(3))
	n.state.SetState(NullifierTreeAddress, revealSlot, newCommitment)

	// chainDepth[account] = newChainLength
	depthSlot := mappingSlot(addrToHash(account), uint64(4))
	var depthVal common.Hash
	depthVal[28] = byte(newChainLength >> 24)
	depthVal[29] = byte(newChainLength >> 16)
	depthVal[30] = byte(newChainLength >> 8)
	depthVal[31] = byte(newChainLength)
	n.state.SetState(NullifierTreeAddress, depthSlot, depthVal)
}

// PendingCommit returns the pending cross-block hashCommit for the account (zero if none).
func (n *NullifierState) PendingCommit(account common.Address) common.Hash {
	slot := mappingSlot(addrToHash(account), uint64(73))
	return n.state.GetState(NullifierTreeAddress, slot)
}

// CommitExpiry returns the last block number (inclusive) at which PendingCommit is valid.
func (n *NullifierState) CommitExpiry(account common.Address) uint64 {
	slot := mappingSlot(addrToHash(account), uint64(74))
	v := n.state.GetState(NullifierTreeAddress, slot)
	return uint64(v[24])<<56 | uint64(v[25])<<48 | uint64(v[26])<<40 | uint64(v[27])<<32 |
		uint64(v[28])<<24 | uint64(v[29])<<16 | uint64(v[30])<<8 | uint64(v[31])
}

// SetPendingCommit stores a cross-block hashCommit with its expiry block number.
// expiry is the last block number (inclusive) at which the reveal is valid.
func (n *NullifierState) SetPendingCommit(account common.Address, commit common.Hash, expiry uint64) {
	commitSlot := mappingSlot(addrToHash(account), uint64(73))
	n.state.SetState(NullifierTreeAddress, commitSlot, commit)

	expirySlot := mappingSlot(addrToHash(account), uint64(74))
	var expiryVal common.Hash
	expiryVal[24] = byte(expiry >> 56)
	expiryVal[25] = byte(expiry >> 48)
	expiryVal[26] = byte(expiry >> 40)
	expiryVal[27] = byte(expiry >> 32)
	expiryVal[28] = byte(expiry >> 24)
	expiryVal[29] = byte(expiry >> 16)
	expiryVal[30] = byte(expiry >> 8)
	expiryVal[31] = byte(expiry)
	n.state.SetState(NullifierTreeAddress, expirySlot, expiryVal)
}

// ClearPendingCommit removes the cross-block commit and expiry for the account.
func (n *NullifierState) ClearPendingCommit(account common.Address) {
	n.state.SetState(NullifierTreeAddress, mappingSlot(addrToHash(account), uint64(73)), common.Hash{})
	n.state.SetState(NullifierTreeAddress, mappingSlot(addrToHash(account), uint64(74)), common.Hash{})
}

// -------------------------------------------------------------------------
// Storage slot helpers
// -------------------------------------------------------------------------

// mappingSlot computes the Solidity storage slot for mapping[key] at baseSlot.
// For nested mappings, pass the result of a previous mappingSlot call as baseSlot.
//
//	slot = keccak256(abi.encode(key, baseSlot))
//
// Both key and baseSlot are treated as 32-byte values (Solidity ABI encoding).
func mappingSlot(key common.Hash, baseSlot interface{}) common.Hash {
	var b common.Hash
	switch v := baseSlot.(type) {
	case uint64:
		b[31] = byte(v)
		if v > 0xff {
			b[30] = byte(v >> 8)
		}
	case int:
		b[31] = byte(v)
		if v > 0xff {
			b[30] = byte(v >> 8)
		}
	case common.Hash:
		b = v
	}
	var buf [64]byte
	copy(buf[:32], key[:])
	copy(buf[32:], b[:])
	return crypto.Keccak256Hash(buf[:])
}

// addrToHash left-pads an address to a 32-byte hash (Solidity ABI encoding for mapping keys).
func addrToHash(addr common.Address) common.Hash {
	var h common.Hash
	copy(h[12:], addr[:])
	return h
}
