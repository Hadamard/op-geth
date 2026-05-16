// Copyright 2025 The op-geth Authors.
// Hash-Only L2 — ECDSA-free OP Stack rollup
// SPDX-License-Identifier: LGPL-2.1-or-later

package types

import "github.com/ethereum/go-ethereum/common"

// This file extends modernSigner.Sender() to handle HashCommitTx (0x7C) and HashRevealTx (0x7F).
//
// Neither type uses ECDSA. The sender address is stored explicitly in the From field (analogous
// to DepositTx). Authentication for HashRevealTx is performed in the state transition
// (core/state_transition_hash.go) by verifying the hash-chain pre-image and nullifier against
// NullifierTree predeploy storage — not here.
//
// To wire this in, the init() function below patches the two type codes into the modernSigner
// Sender dispatch by registering them as "self-declaring" types (like DepositTx).

// HashSenderFromTx extracts the From field from a HashCommitTx or HashRevealTx.
// Returns (address, true) on success, (zero, false) if the tx inner is not one of these types.
func HashSenderFromTx(tx *Transaction) (common.Address, bool) {
	switch inner := tx.inner.(type) {
	case *HashCommitTx:
		return inner.From, true
	case *HashRevealTx:
		return inner.From, true
	}
	return common.Address{}, false
}

// IsHashTxType returns true for transaction types used by the hash-account L2 system.
func IsHashTxType(txType byte) bool {
	return txType == HashCommitTxType || txType == HashRevealTxType
}

// HashRevealInner returns the inner *HashRevealTx, or nil if the transaction is not a HashRevealTx.
func (tx *Transaction) HashRevealInner() *HashRevealTx {
	inner, _ := tx.inner.(*HashRevealTx)
	return inner
}

// HashCommitInner returns the inner *HashCommitTx, or nil if the transaction is not a HashCommitTx.
func (tx *Transaction) HashCommitInner() *HashCommitTx {
	inner, _ := tx.inner.(*HashCommitTx)
	return inner
}
