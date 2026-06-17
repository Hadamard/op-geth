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
	ErrHashReveal_CommitExpired    = errors.New("hash-reveal: pending commit has expired")
	ErrHashReveal_EarlyRenew      = errors.New("hash-reveal: NewCommitment set but chain is not at final step (depth != 1)")
	ErrHashReveal_ZeroNewChainLen = errors.New("hash-reveal: NewCommitment set but NewChainLength is zero")
	ErrHashCommit_NotRegistered    = errors.New("hash-commit: account has no registered commitment")
	ErrHashReveal_HandleCooldown   = errors.New("hash-reveal: username may only be changed every 14 days")
	ErrHashReveal_OTATooYoung      = errors.New("hash-reveal: OTA must be at least 1 hour old before deletion")
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

	// 5b. Renewal validation: NewCommitment may only be set on the depth-exhausting step.
	// No address-derivation check: any commitment is valid for renewal because
	// authorization comes from revealing the final preimage (depth == 1 before this step).
	if tx.NewCommitment != (common.Hash{}) {
		if ns.ChainDepth(from) != 1 {
			return ErrHashReveal_EarlyRenew
		}
		if tx.NewChainLength == 0 {
			return ErrHashReveal_ZeroNewChainLen
		}
	}

	// 6. Verify hashCommit from the preceding commit-tx.
	//
	//    Devnet bypass: skipped when HashCommitSlots is nil (block builder did not initialise
	//    it) AND no cross-block pending commit exists in NullifierTree state.
	//    In production the block builder always initialises HashCommitSlots before processing
	//    transactions, so HashCommitSlots is non-nil even if no HashCommitTx was in this block.
	//
	//    Two accept paths:
	//      a) Same-block: HashCommitSlots[from] set by a HashCommitTx earlier in this block.
	//      b) Cross-block: pendingCommits[from] in persistent NullifierTree state (written by a
	//         HashCommitTx in a prior block) and block.Number <= commitExpiry[from].
	pendingCommit := ns.PendingCommit(from)
	if st.evm.Context.HashCommitSlots != nil || pendingCommit != (common.Hash{}) {
		expectedCommit := computeHashCommit(tx.Nullifier, tx.PreImage, txDigest, tx.Nonce)

		if storedCommit, ok := st.evm.Context.HashCommitSlots[from]; ok {
			// Same-block path.
			if storedCommit != expectedCommit {
				return fmt.Errorf("%w: stored %s, computed %s", ErrHashReveal_CommitMismatch, storedCommit, expectedCommit)
			}
		} else if pendingCommit != (common.Hash{}) {
			// Cross-block path.
			if pendingCommit != expectedCommit {
				return fmt.Errorf("%w: stored %s, computed %s", ErrHashReveal_CommitMismatch, pendingCommit, expectedCommit)
			}
			if st.evm.Context.BlockNumber.Uint64() > ns.CommitExpiry(from) {
				return ErrHashReveal_CommitExpired
			}
		} else {
			// HashCommitSlots non-nil (production mode) but no commit in either path.
			return ErrHashReveal_CommitMismatch
		}
	}

	// 7. Rate-limit: username may only be changed once every 14 days (protocol time).
	if tx.To != nil && *tx.To == HandleRegistryAddress {
		last := ns.LastHandleTimestamp(from)
		if last != 0 && st.evm.Context.Time-last < 14*24*3600 {
			return ErrHashReveal_HandleCooldown
		}
	}

	// 8. Rate-limit: OTA deletion requires at least 1 hour after the first RevealTx.
	if tx.To != nil && *tx.To == OTADeleteAddress {
		created := ns.CreationTimestamp(from)
		if created == 0 || st.evm.Context.Time-created < 3600 {
			return ErrHashReveal_OTATooYoung
		}
	}

	return nil
}

// hashRevealPostExec advances the NullifierTree state after a successful HashRevealTx.
// Must be called after EVM execution completes (even if EVM reverted — the auth is consumed).
// If tx.NewCommitment is non-zero and this was the depth-exhausting step, atomically
// renews the hash-chain to the new commitment.
func hashRevealPostExec(st *stateTransition, tx *types.HashRevealTx) {
	ns := NewNullifierState(st.state)

	// Record creation timestamp on the first-ever RevealTx for this OTA.
	if ns.CreationTimestamp(tx.From) == 0 {
		ns.SetCreationTimestamp(tx.From, st.evm.Context.Time)
	}

	ns.MarkSpent(tx.From, tx.Nullifier, tx.PreImage)
	// Consume the cross-block pending commit (no-op if already zero).
	ns.ClearPendingCommit(tx.From)
	// After MarkSpent, chainDepth is 0 iff this was the last step.
	if tx.NewCommitment != (common.Hash{}) && ns.ChainDepth(tx.From) == 0 {
		ns.RenewChain(tx.From, tx.NewCommitment, tx.NewChainLength)
	}
	// Handle registration: if tx targets HandleRegistry, register or release username.
	if tx.To != nil && *tx.To == HandleRegistryAddress {
		hr := NewHandleRegistryState(st.state)
		if name, ok := HandleDataToName(tx.Data); ok {
			if IsValidHandleName(name) {
				hr.Register(tx.From, name)
				ns.SetLastHandleTimestamp(tx.From, st.evm.Context.Time)
			}
		} else {
			hr.Release(tx.From)
		}
	}
	// OTA self-deletion: zero out NullifierTree state and release any username.
	if tx.To != nil && *tx.To == OTADeleteAddress {
		ns.DeleteOTA(tx.From)
		NewHandleRegistryState(st.state).Release(tx.From)
	}
}

// hashCommitPreCheck validates a HashCommitTx: sender must be registered in NullifierTree.
func hashCommitPreCheck(st *stateTransition, tx *types.HashCommitTx) error {
	ns := NewNullifierState(st.state)
	if !ns.IsRegistered(tx.From) {
		return ErrHashCommit_NotRegistered
	}
	return nil
}

// hashCommitPostExec stores the hashCommit for both the same-block and cross-block reveal paths.
//
// Same-block path: writes to BlockContext.HashCommitSlots (reset each block).
// Cross-block path: writes to NullifierTree persistent state (slots 73/74) with an
// expiry block number of currentBlock + ExpireAfterBlocks (default 5 if zero).
func hashCommitPostExec(st *stateTransition, tx *types.HashCommitTx) {
	// Same-block path.
	if st.evm.Context.HashCommitSlots == nil {
		st.evm.Context.HashCommitSlots = make(map[common.Address]common.Hash)
	}
	st.evm.Context.HashCommitSlots[tx.From] = tx.HashCommit

	// Cross-block path: persist with expiry.
	expireBlocks := uint64(tx.ExpireAfterBlocks)
	if expireBlocks == 0 {
		expireBlocks = 5 // default window
	}
	expiry := st.evm.Context.BlockNumber.Uint64() + expireBlocks
	NewNullifierState(st.state).SetPendingCommit(tx.From, tx.HashCommit, expiry)
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
