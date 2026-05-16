// Copyright 2025 The op-geth Authors.
// Hash-Only L2 — ECDSA-free OP Stack rollup
// SPDX-License-Identifier: LGPL-2.1-or-later

package core

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Domain tags for hash-account cryptography.
// These must exactly match the constants in NullifierTree.sol and the spec.
var (
	nullifierDomain = crypto.Keccak256Hash([]byte("OP_NULLIFIER_v1"))
	commitBindDomain = crypto.Keccak256Hash([]byte("OP_COMMIT_BIND_v1"))
)

// Sentinel errors for hash-reveal validation failures.
var (
	ErrHashReveal_NotRegistered    = errors.New("hash-reveal: account has no registered commitment")
	ErrHashReveal_ChainExhausted   = errors.New("hash-reveal: hash-chain depth is zero (account exhausted)")
	ErrHashReveal_InvalidPreImage  = errors.New("hash-reveal: keccak256(preImage) != lastReveal")
	ErrHashReveal_InvalidNullifier = errors.New("hash-reveal: nullifier does not match preImage/nonce/txDigest")
	ErrHashReveal_NullifierSpent   = errors.New("hash-reveal: nullifier already spent")
	ErrHashReveal_CommitMismatch   = errors.New("hash-reveal: hashCommit from commit-tx does not match reveal")
	ErrHashCommit_NotRegistered    = errors.New("hash-commit: account has no registered commitment")
)

// hashRevealPreCheck validates a HashRevealTx before EVM execution.
// This replaces the ECDSA signature check that would normally happen for other tx types.
//
// Steps (per spec §4.3, §4.4):
//  1. Account must be registered in NullifierTree
//  2. Chain depth must be > 0
//  3. keccak256(preImage) == NullifierTree.lastReveal[from]     (hash-chain step)
//  4. nullifier == keccak256(NULLIFIER_DOMAIN ‖ preImage ‖ nonce ‖ txDigest)
//  5. !NullifierTree.isSpent[from][nullifier]
//  6. hashCommit from the preceding commit-tx must match
//     keccak256(COMMIT_BIND_DOMAIN ‖ nullifier ‖ preImage ‖ txDigest ‖ nonce)
//
// On success, the caller (innerExecute) must call hashRevealPostCheck to advance
// the chain state.
func hashRevealPreCheck(st *stateTransition, tx *types.HashRevealTx) error {
	ns := NewNullifierState(st.state)
	from := tx.From

	// 1. Account registered?
	if !ns.IsRegistered(from) {
		return ErrHashReveal_NotRegistered
	}

	// 2. Chain not exhausted?
	if ns.ChainDepth(from) == 0 {
		return ErrHashReveal_ChainExhausted
	}

	// 3. Verify hash-chain step: keccak256(preImage) must equal lastReveal.
	gotParent := crypto.Keccak256Hash(tx.PreImage[:])
	lastReveal := ns.LastReveal(from)
	if gotParent != lastReveal {
		return fmt.Errorf("%w: got %s, want %s", ErrHashReveal_InvalidPreImage, gotParent, lastReveal)
	}

	// 4. Verify nullifier = keccak256(NULLIFIER_DOMAIN ‖ preImage ‖ nonce_u64 ‖ txDigest).
	txDigest := tx.TxDigest()
	expectedNullifier := computeNullifier(tx.PreImage, tx.Nonce, txDigest)
	if expectedNullifier != tx.Nullifier {
		return fmt.Errorf("%w: got %s, want %s", ErrHashReveal_InvalidNullifier, tx.Nullifier, expectedNullifier)
	}

	// 5. Nullifier must not be spent.
	if ns.IsSpent(from, tx.Nullifier) {
		return ErrHashReveal_NullifierSpent
	}

	// 6. Verify hashCommit from the preceding commit-tx.
	//    The commit-tx stored hashCommit in a transient/block-local mapping (BlockContext.HashCommitSlots).
	//    Phase 0 devnet bypass: if HashCommitSlots is nil (block builder did not initialise it),
	//    commit verification is skipped. In production the block builder always initialises this map.
	if st.evm.Context.HashCommitSlots != nil {
		expectedCommit := computeHashCommit(tx.Nullifier, tx.PreImage, txDigest, tx.Nonce)
		storedCommit, ok := st.evm.Context.HashCommitSlots[from]
		if !ok {
			return ErrHashReveal_CommitMismatch
		}
		if storedCommit != expectedCommit {
			return fmt.Errorf("%w: stored %s, computed %s", ErrHashReveal_CommitMismatch, storedCommit, expectedCommit)
		}
	}

	return nil
}

// hashRevealPostExec advances the NullifierTree state after a successful HashRevealTx.
// Must be called after EVM execution completes (even if EVM reverted — the auth is consumed).
func hashRevealPostExec(st *stateTransition, tx *types.HashRevealTx) {
	ns := NewNullifierState(st.state)
	ns.MarkSpent(tx.From, tx.Nullifier, tx.PreImage)
}

// hashCommitPreCheck validates a HashCommitTx: sender must be registered in NullifierTree.
func hashCommitPreCheck(st *stateTransition, tx *types.HashCommitTx) error {
	ns := NewNullifierState(st.state)
	if !ns.IsRegistered(tx.From) {
		return ErrHashCommit_NotRegistered
	}
	return nil
}

// hashCommitPostExec stores the hashCommit in the block-local commit map so the
// matching reveal can verify it.
func hashCommitPostExec(st *stateTransition, tx *types.HashCommitTx) {
	if st.evm.Context.HashCommitSlots == nil {
		st.evm.Context.HashCommitSlots = make(map[common.Address]common.Hash)
	}
	st.evm.Context.HashCommitSlots[tx.From] = tx.HashCommit
}

// -------------------------------------------------------------------------
// Cryptographic helpers
// -------------------------------------------------------------------------

// computeNullifier derives the expected nullifier:
//
//	nullifier = keccak256("OP_NULLIFIER_v1" ‖ preImage ‖ nonce_u64be ‖ txDigest)
func computeNullifier(preImage common.Hash, nonce uint64, txDigest common.Hash) common.Hash {
	var buf [32 + 32 + 8 + 32]byte
	copy(buf[0:32], nullifierDomain[:])
	copy(buf[32:64], preImage[:])
	buf[64] = byte(nonce >> 56)
	buf[65] = byte(nonce >> 48)
	buf[66] = byte(nonce >> 40)
	buf[67] = byte(nonce >> 32)
	buf[68] = byte(nonce >> 24)
	buf[69] = byte(nonce >> 16)
	buf[70] = byte(nonce >> 8)
	buf[71] = byte(nonce)
	copy(buf[72:104], txDigest[:])
	return crypto.Keccak256Hash(buf[:])
}

// computeHashCommit derives the expected hashCommit value that the sender must have
// broadcast in the preceding HashCommitTx:
//
//	hashCommit = keccak256("OP_COMMIT_BIND_v1" ‖ nullifier ‖ preImage ‖ txDigest ‖ nonce_u64be)
func computeHashCommit(nullifier, preImage common.Hash, txDigest common.Hash, nonce uint64) common.Hash {
	var buf [32 + 32 + 32 + 32 + 8]byte
	copy(buf[0:32], commitBindDomain[:])
	copy(buf[32:64], nullifier[:])
	copy(buf[64:96], preImage[:])
	copy(buf[96:128], txDigest[:])
	buf[128] = byte(nonce >> 56)
	buf[129] = byte(nonce >> 48)
	buf[130] = byte(nonce >> 40)
	buf[131] = byte(nonce >> 32)
	buf[132] = byte(nonce >> 24)
	buf[133] = byte(nonce >> 16)
	buf[134] = byte(nonce >> 8)
	buf[135] = byte(nonce)
	return crypto.Keccak256Hash(buf[:])
}
