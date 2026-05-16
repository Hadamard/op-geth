// Copyright 2025 The op-geth Authors.
// Hash-Only L2 — ECDSA-free OP Stack rollup (Phase 0)
// SPDX-License-Identifier: LGPL-2.1-or-later

package types

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// HashCommitTxType is EIP-2718 transaction type 0x7C.
// It is the first of the two-step Commit-Reveal mempool protocol for hash-account L2 txs.
// (0x7D is reserved for PostExecTxType in op-geth.)
//
// Phase 1 (Commit): the user broadcasts a HashCommitTx that binds txDigest without revealing
// the pre-image.  The sequencer includes this in block N.  Front-running is impossible because
// txDigest is fixed in the commitment hash — an attacker cannot change the destination while
// keeping the same hashCommit value.
//
// Phase 2 (Reveal): in block N+1 the user sends a HashRevealTx (0x7F).  The state transition
// verifies that keccak256(nullifier ‖ preImage ‖ txDigest ‖ nonce) == hashCommit stored in
// block N, and that the commitment window has not expired (default: 5 blocks).
//
// Spec ref: Hash-Only L2 Whitepaper §4.4
const HashCommitTxType = 0x7C

// HashCommitTx (TxType 0x7D) — commit phase of the Commit-Reveal protocol.
type HashCommitTx struct {
	ChainID *big.Int

	// From is the commitment-derived L2 address of the sender.
	// addr = trunc20(keccak256("OP_HASH_ADDR_v1" ‖ commitment))
	From common.Address

	// Nonce is the sender's current account nonce (for Mempool ordering).
	Nonce uint64

	// HashCommit binds the upcoming reveal without exposing the pre-image:
	//   hashCommit = keccak256("OP_COMMIT_BIND_v1" ‖ nullifier ‖ preImage ‖ txDigest ‖ nonce)
	// The reveal tx must produce a matching value.
	HashCommit common.Hash

	// Gas is the gas limit for this commit transaction.
	// Commit txs are cheap (only storage write + event).
	Gas uint64

	// GasFeeCap is the maximum gas price the sender is willing to pay.
	GasFeeCap *big.Int

	// GasTipCap is the miner tip.
	GasTipCap *big.Int

	// ExpireAfterBlocks is the maximum number of blocks the sequencer may wait before the
	// corresponding HashRevealTx must appear.  After expiry the commit slot is freed and the
	// nonce can be reused.  Defaults to 5 if zero.
	ExpireAfterBlocks uint8
}

// copy creates a deep copy of the transaction data.
func (tx *HashCommitTx) copy() TxData {
	cpy := &HashCommitTx{
		ChainID:           new(big.Int),
		From:              tx.From,
		Nonce:             tx.Nonce,
		HashCommit:        tx.HashCommit,
		Gas:               tx.Gas,
		GasFeeCap:         new(big.Int),
		GasTipCap:         new(big.Int),
		ExpireAfterBlocks: tx.ExpireAfterBlocks,
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap.Set(tx.GasFeeCap)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap.Set(tx.GasTipCap)
	}
	return cpy
}

// accessors for innerTx interface.
func (tx *HashCommitTx) txType() byte           { return HashCommitTxType }
func (tx *HashCommitTx) chainID() *big.Int      { return tx.ChainID }
func (tx *HashCommitTx) accessList() AccessList { return nil }
func (tx *HashCommitTx) data() []byte           { return nil }
func (tx *HashCommitTx) gas() uint64            { return tx.Gas }
func (tx *HashCommitTx) gasFeeCap() *big.Int    { return tx.GasFeeCap }
func (tx *HashCommitTx) gasTipCap() *big.Int    { return tx.GasTipCap }
func (tx *HashCommitTx) gasPrice() *big.Int     { return tx.GasFeeCap }
func (tx *HashCommitTx) value() *big.Int        { return common.Big0 }
func (tx *HashCommitTx) nonce() uint64          { return tx.Nonce }
func (tx *HashCommitTx) from() common.Address   { return tx.From }
func (tx *HashCommitTx) to() *common.Address    { return nil }
func (tx *HashCommitTx) isSystemTx() bool       { return false }

func (tx *HashCommitTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap)
	}
	tip := dst.Sub(tx.GasFeeCap, baseFee)
	if tip.Cmp(tx.GasTipCap) > 0 {
		tip.Set(tx.GasTipCap)
	}
	return tip.Add(tip, baseFee)
}

func (tx *HashCommitTx) effectiveNonce() *uint64 { return &tx.Nonce }

// HashCommitTx does not use ECDSA signatures. The sender is authenticated by verifying that
// From == trunc20(keccak256("OP_HASH_ADDR_v1" ‖ NullifierTree.commitmentOf[From])).
// The binding between the commit tx and the subsequent reveal is enforced by hashCommit.
func (tx *HashCommitTx) sigHash(*big.Int) common.Hash { return common.Hash{} }

func (tx *HashCommitTx) rawSignatureValues() (v, r, s *big.Int) {
	return common.Big0, common.Big0, common.Big0
}

func (tx *HashCommitTx) setSignatureValues(chainID, v, r, s *big.Int) {}

func (tx *HashCommitTx) encode(b *bytes.Buffer) error {
	return rlp.Encode(b, tx)
}

func (tx *HashCommitTx) decode(input []byte) error {
	return rlp.DecodeBytes(input, tx)
}
