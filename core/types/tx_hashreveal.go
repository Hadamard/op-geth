// Copyright 2025 The op-geth Authors.
// Hash-Only L2 — ECDSA-free OP Stack rollup (Phase 0)
// SPDX-License-Identifier: LGPL-2.1-or-later

package types

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// HashRevealTxType is EIP-2718 transaction type 0x7F.
// It is the second step of the Commit-Reveal mempool protocol for hash-account L2 txs.
//
// Authentication (performed in core/state_transition.go before EVM execution):
//  1. Look up lastReveal = NullifierTree.lastReveal[From]
//  2. Verify keccak256(PreImage) == lastReveal  (valid hash-chain step)
//  3. Compute nullifier = keccak256("OP_NULLIFIER_v1" ‖ PreImage ‖ Nonce ‖ txDigest)
//  4. Verify !NullifierTree.isSpent(From, nullifier)
//  5. Verify hashCommit = keccak256("OP_COMMIT_BIND_v1" ‖ nullifier ‖ PreImage ‖ txDigest ‖ Nonce)
//     matches the stored HashCommitTx.HashCommit from the previous block.
//  6. Call NullifierTree.markSpent(From, nullifier, PreImage, Nonce) to update chain state.
//
// After authentication the EVM executes the transaction normally with msg.sender = From.
//
// Spec ref: Hash-Only L2 Whitepaper §3.3, §4.3, §4.4
const HashRevealTxType = 0x7F

// HashRevealTx (TxType 0x7F) — reveal phase of the Commit-Reveal protocol.
type HashRevealTx struct {
	ChainID *big.Int

	// From is the commitment-derived L2 address of the sender.
	// addr = trunc20(keccak256("OP_HASH_ADDR_v1" ‖ commitment))
	From common.Address

	// Nonce is the sender's sequential account nonce.  Combined with PreImage and txDigest
	// in the nullifier to prevent both Mempool reordering attacks and replay attacks.
	Nonce uint64

	// To is the target address (nil = contract creation).
	To *common.Address `rlp:"nil"`

	// Value is the ETH to send from From to To.
	Value *big.Int

	// Gas is the gas limit for EVM execution.
	Gas uint64

	// GasFeeCap is the maximum gas price.
	GasFeeCap *big.Int

	// GasTipCap is the miner tip.
	GasTipCap *big.Int

	// Data is the transaction calldata.
	Data []byte

	// Nullifier is the one-time spend token:
	//   nullifier = keccak256("OP_NULLIFIER_v1" ‖ PreImage ‖ Nonce ‖ txDigest)
	// where txDigest = keccak256(RLP(tx fields without Nullifier and PreImage)).
	// The state transition verifies that this nullifier has not been spent.
	Nullifier common.Hash

	// PreImage is the hash-chain element being revealed (s_{N-k}).
	// The state transition verifies: keccak256(PreImage) == NullifierTree.lastReveal[From].
	// After verification PreImage becomes the new lastReveal (chain advances).
	PreImage common.Hash

	// ViewTag is a 1-byte hint for receiver-side fast scanning (analogous to ERC-5564 view tags).
	// Does not affect consensus.
	ViewTag byte

	// NewCommitment is the hash-chain anchor for the next chain, when this reveal is the
	// depth-exhausting Nth step (chainDepth goes 1→0). Zero means no renewal.
	// If non-zero, op-geth calls NullifierTree.renewChain() after markSpent().
	// Constraint: trunc20(keccak256("OP_HASH_ADDR_v1" ‖ NewCommitment)) == From.
	NewCommitment common.Hash

	// NewChainLength is the depth of the new hash-chain (ignored when NewCommitment is zero).
	NewChainLength uint32
}

// copy creates a deep copy of the transaction data.
func (tx *HashRevealTx) copy() TxData {
	cpy := &HashRevealTx{
		ChainID:        new(big.Int),
		From:           tx.From,
		Nonce:          tx.Nonce,
		To:             copyAddressPtr(tx.To),
		Value:          new(big.Int),
		Gas:            tx.Gas,
		GasFeeCap:      new(big.Int),
		GasTipCap:      new(big.Int),
		Data:           common.CopyBytes(tx.Data),
		Nullifier:      tx.Nullifier,
		PreImage:       tx.PreImage,
		ViewTag:        tx.ViewTag,
		NewCommitment:  tx.NewCommitment,
		NewChainLength: tx.NewChainLength,
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
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
func (tx *HashRevealTx) txType() byte           { return HashRevealTxType }
func (tx *HashRevealTx) chainID() *big.Int      { return tx.ChainID }
func (tx *HashRevealTx) accessList() AccessList { return nil }
func (tx *HashRevealTx) data() []byte           { return tx.Data }
func (tx *HashRevealTx) gas() uint64            { return tx.Gas }
func (tx *HashRevealTx) gasFeeCap() *big.Int    { return tx.GasFeeCap }
func (tx *HashRevealTx) gasTipCap() *big.Int    { return tx.GasTipCap }
func (tx *HashRevealTx) gasPrice() *big.Int     { return tx.GasFeeCap }
func (tx *HashRevealTx) value() *big.Int        { return tx.Value }
func (tx *HashRevealTx) nonce() uint64          { return tx.Nonce }
func (tx *HashRevealTx) from() common.Address   { return tx.From }
func (tx *HashRevealTx) to() *common.Address    { return tx.To }
func (tx *HashRevealTx) isSystemTx() bool       { return false }

func (tx *HashRevealTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap)
	}
	tip := dst.Sub(tx.GasFeeCap, baseFee)
	if tip.Cmp(tx.GasTipCap) > 0 {
		tip.Set(tx.GasTipCap)
	}
	return tip.Add(tip, baseFee)
}

func (tx *HashRevealTx) effectiveNonce() *uint64 { return &tx.Nonce }

// HashRevealTx does not use ECDSA. The sender is verified by the state transition via pre-image
// reveal against NullifierTree state. sigHash panics if accidentally called.
func (tx *HashRevealTx) sigHash(*big.Int) common.Hash {
	panic("HashRevealTx: sigHash must not be called (no ECDSA signature)")
}

func (tx *HashRevealTx) rawSignatureValues() (v, r, s *big.Int) {
	return common.Big0, common.Big0, common.Big0
}

func (tx *HashRevealTx) setSignatureValues(chainID, v, r, s *big.Int) {}

func (tx *HashRevealTx) encode(b *bytes.Buffer) error {
	return rlp.Encode(b, tx)
}

func (tx *HashRevealTx) decode(input []byte) error {
	return rlp.DecodeBytes(input, tx)
}

// TxDigest computes the hash of the HashRevealTx fields that are bound by the commit-phase
// hash and the nullifier.  It excludes Nullifier, PreImage, and ViewTag (post-auth fields).
//
// txDigest = keccak256(RLP(ChainID, From, Nonce, To, Value, Gas, GasFeeCap, GasTipCap, Data))
func (tx *HashRevealTx) TxDigest() common.Hash {
	type bindFields struct {
		ChainID        *big.Int
		From           common.Address
		Nonce          uint64
		To             *common.Address `rlp:"nil"`
		Value          *big.Int
		Gas            uint64
		GasFeeCap      *big.Int
		GasTipCap      *big.Int
		Data           []byte
		NewCommitment  common.Hash
		NewChainLength uint32
	}
	encoded, _ := rlp.EncodeToBytes(&bindFields{
		ChainID:        tx.ChainID,
		From:           tx.From,
		Nonce:          tx.Nonce,
		To:             tx.To,
		Value:          tx.Value,
		Gas:            tx.Gas,
		GasFeeCap:      tx.GasFeeCap,
		GasTipCap:      tx.GasTipCap,
		Data:           tx.Data,
		NewCommitment:  tx.NewCommitment,
		NewChainLength: tx.NewChainLength,
	})
	return crypto.Keccak256Hash(encoded)
}
