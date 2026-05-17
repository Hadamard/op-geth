// Copyright 2025 The op-geth Authors.
// Hash-Only L2 — ECDSA-free OP Stack rollup (E2E integration test)
// SPDX-License-Identifier: LGPL-2.1-or-later

package core

// TestHashRevealTxE2E is a self-contained integration test for the Hash-Only L2
// state transition. It builds an in-memory blockchain with NullifierTree storage
// pre-seeded in the genesis alloc, then exercises HashRevealTx (TxType 0x7F)
// spending through the full chain length.
//
// No external process (geth, op-node, RPC) is required.
//
// Flow:
//   1. Derive deterministic OTA keys (chain length 3)
//   2. Pre-seed NullifierTree slots in genesis alloc
//   3. Build blockchain (ethash faker, in-memory)
//   4. Insert blocks each containing one HashRevealTx
//   5. After each block verify NullifierTree state, balance, nonce
//   6. Verify the chain is exhausted after N spends

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// hashE2EKeccak is a convenience wrapper for the test (mirrors core.crypto.Keccak256Hash).
func hashE2EKeccak(chunks ...[]byte) common.Hash {
	return crypto.Keccak256Hash(chunks...)
}

// hashE2EChainElement computes chain[index] = keccak256^index(seed).
func hashE2EChainElement(seed [32]byte, index uint32) [32]byte {
	h := seed
	for i := uint32(0); i < index; i++ {
		h = [32]byte(hashE2EKeccak(h[:]))
	}
	return h
}

// hashE2EDeriveOTAAddress derives trunc20(keccak256("OP_HASH_ADDR_v1" || commitment)).
func hashE2EDeriveOTAAddress(commitment [32]byte) common.Address {
	domain := hashE2EKeccak([]byte("OP_HASH_ADDR_v1"))
	h := hashE2EKeccak(domain[:], commitment[:])
	return common.Address(h[12:])
}

// hashE2EGenesisStorage returns the NullifierTree storage alloc for the given OTA.
// It sets commitmentOf[addr], lastReveal[addr], and chainDepth[addr].
func hashE2EGenesisStorage(addr common.Address, commitment [32]byte, chainLen uint32) map[common.Hash]common.Hash {
	// Mirroring NullifierState.mappingSlot / addrToHash logic.
	addrHash := addrToHash(addr)
	slot2 := mappingSlot(addrHash, uint64(2)) // commitmentOf
	slot3 := mappingSlot(addrHash, uint64(3)) // lastReveal
	slot4 := mappingSlot(addrHash, uint64(4)) // chainDepth (uint32, right-aligned)

	var depthVal common.Hash
	depthVal[28] = byte(chainLen >> 24)
	depthVal[29] = byte(chainLen >> 16)
	depthVal[30] = byte(chainLen >> 8)
	depthVal[31] = byte(chainLen)

	return map[common.Hash]common.Hash{
		slot2: common.Hash(commitment),
		slot3: common.Hash(commitment),
		slot4: depthVal,
	}
}

// buildHashRevealTx constructs and returns a HashRevealTx ready for insertion into
// a block. The caller must have already computed preImage for spend step k
// (preImage = chain[chainLen - k], keccak256(preImage) == lastReveal).
func buildHashRevealTx(
	chainID *big.Int,
	from common.Address,
	nonce uint64,
	to common.Address,
	value *big.Int,
	preImage [32]byte,
) *types.Transaction {
	domainNullifier := hashE2EKeccak([]byte("OP_NULLIFIER_v1"))

	inner := &types.HashRevealTx{
		ChainID:   chainID,
		From:      from,
		Nonce:     nonce,
		To:        &to,
		Value:     value,
		Gas:       100_000,
		GasFeeCap: big.NewInt(params.InitialBaseFee * 2),
		GasTipCap: big.NewInt(1),
		PreImage:  common.Hash(preImage),
	}

	// Compute nullifier = keccak256(NULLIFIER_DOMAIN || preImage || nonce_u64be || txDigest).
	txDigest := inner.TxDigest()
	var nonceBuf [8]byte
	nonceBuf[0] = byte(nonce >> 56)
	nonceBuf[1] = byte(nonce >> 48)
	nonceBuf[2] = byte(nonce >> 40)
	nonceBuf[3] = byte(nonce >> 32)
	nonceBuf[4] = byte(nonce >> 24)
	nonceBuf[5] = byte(nonce >> 16)
	nonceBuf[6] = byte(nonce >> 8)
	nonceBuf[7] = byte(nonce)
	nullifier := hashE2EKeccak(domainNullifier[:], preImage[:], nonceBuf[:], txDigest[:])
	inner.Nullifier = nullifier

	return types.NewTx(inner)
}

func TestHashRevealTxE2E(t *testing.T) {
	const chainLen = uint32(3)

	// Deterministic test seed — never used on any real network.
	var spendSK [32]byte
	spendSK[31] = 0x42
	var r [32]byte
	r[31] = 0x07

	// Derive OTA spend SK and hash-chain.
	// otaSpendSK = chain[0]; chain[k] = keccak256(chain[k-1]); commitment = chain[chainLen].
	domainOTASpend := hashE2EKeccak([]byte("OP_OTA_SPEND_v1"))
	otaSpendSK := [32]byte(hashE2EKeccak(domainOTASpend[:], spendSK[:], r[:]))

	// chain[0..chainLen]
	chain := make([][32]byte, chainLen+1)
	chain[0] = otaSpendSK
	for i := uint32(1); i <= chainLen; i++ {
		chain[i] = [32]byte(hashE2EKeccak(chain[i-1][:]))
	}
	commitment := chain[chainLen] // = chain[3]
	otaAddr := hashE2EDeriveOTAAddress(commitment)

	t.Logf("OTA address:  %s", otaAddr.Hex())
	t.Logf("commitment:   %x", commitment)

	// Recipient of all spends.
	recipient := common.HexToAddress("0x000000000000000000000000000000000000dead")

	// Genesis: pre-fund OTA + pre-seed NullifierTree storage.
	initialBalance := new(big.Int).Mul(big.NewInt(1e9), big.NewInt(1e9)) // 1 ETH

	genesis := &Genesis{
		Config:  params.AllEthashProtocolChanges,
		BaseFee: big.NewInt(params.InitialBaseFee),
		Alloc: GenesisAlloc{
			otaAddr: {Balance: initialBalance},
			NullifierTreeAddress: {
				// Nonce: 1 prevents EIP158 from deleting this account during Finalise(true).
				// In production NullifierTree has code; here any non-zero field suffices.
				Nonce:   1,
				Storage: hashE2EGenesisStorage(otaAddr, commitment, chainLen),
			},
		},
	}

	// Build in-memory blockchain.
	db := rawdb.NewMemoryDatabase()
	blockchain, err := NewBlockChain(db, genesis, ethash.NewFaker(), DefaultConfig())
	if err != nil {
		t.Fatalf("NewBlockChain: %v", err)
	}
	defer blockchain.Stop()

	// -------------------------------------------------------------------------
	// Generate all chainLen blocks in sequence, each with one spend.
	// Block i contains spend step i+1: reveals chain[chainLen-(i+1)].
	// Each block builds on the previous state (lastReveal advances each step).
	// -------------------------------------------------------------------------
	sendValue := big.NewInt(1000)

	genDB, allBlocks, _ := GenerateChainWithGenesis(genesis, ethash.NewFaker(), int(chainLen), func(i int, b *BlockGen) {
		step := uint32(i + 1)
		preImageIdx := chainLen - step
		preImage := chain[preImageIdx]
		nonce := uint64(step - 1)

		tx := buildHashRevealTx(
			params.AllEthashProtocolChanges.ChainID,
			otaAddr,
			nonce,
			recipient,
			sendValue,
			preImage,
		)
		b.AddTx(tx)
	})
	_ = genDB

	n, err := blockchain.InsertChain(allBlocks)
	if err != nil {
		t.Fatalf("InsertChain failed at block %d: %v", n+1, err)
	}
	if n != int(chainLen) {
		t.Fatalf("expected %d blocks inserted, got %d", chainLen, n)
	}

	// -------------------------------------------------------------------------
	// Verify final NullifierTree state.
	// -------------------------------------------------------------------------
	stateDB, err := blockchain.State()
	if err != nil {
		t.Fatalf("blockchain.State: %v", err)
	}

	ns := NewNullifierState(stateDB)

	// After chainLen spends, depth must be 0 (exhausted).
	depth := ns.ChainDepth(otaAddr)
	if depth != 0 {
		t.Errorf("chainDepth: got %d, want 0 (exhausted)", depth)
	}

	// lastReveal must equal chain[0] (the final revealed preimage is chain[0]).
	gotLastReveal := ns.LastReveal(otaAddr)
	wantLastReveal := common.Hash(chain[0])
	if gotLastReveal != wantLastReveal {
		t.Errorf("lastReveal: got %x, want %x", gotLastReveal, wantLastReveal)
	}

	// All chainLen nullifiers must be marked spent.
	domainNullifier := hashE2EKeccak([]byte("OP_NULLIFIER_v1"))
	for step := uint32(1); step <= chainLen; step++ {
		preImageIdx := chainLen - step
		preImage := chain[preImageIdx]
		nonce := uint64(step - 1)

		// Reconstruct the tx to get its digest and nullifier.
		inner := &types.HashRevealTx{
			ChainID:   params.AllEthashProtocolChanges.ChainID,
			From:      otaAddr,
			Nonce:     nonce,
			To:        &recipient,
			Value:     sendValue,
			Gas:       100_000,
			GasFeeCap: big.NewInt(params.InitialBaseFee * 2),
			GasTipCap: big.NewInt(1),
			PreImage:  common.Hash(preImage),
		}
		txDigest := inner.TxDigest()
		var nonceBuf [8]byte
		nonceBuf[7] = byte(nonce)
		nullifier := hashE2EKeccak(domainNullifier[:], preImage[:], nonceBuf[:], txDigest[:])

		if !ns.IsSpent(otaAddr, nullifier) {
			t.Errorf("step %d: nullifier not marked spent", step)
		}
	}

	// Recipient should have received chainLen * sendValue.
	recipientBal := stateDB.GetBalance(recipient)
	wantBal := new(big.Int).Mul(sendValue, big.NewInt(int64(chainLen)))
	if recipientBal.ToBig().Cmp(wantBal) != 0 {
		t.Errorf("recipient balance: got %s, want %s", recipientBal, wantBal)
	}

	t.Logf("✓ All %d HashRevealTx spends processed successfully", chainLen)
	t.Logf("  recipient balance: %s wei", recipientBal)
	t.Logf("  chain depth: %d (exhausted)", depth)
	t.Logf("  lastReveal: %x (= chain[0])", gotLastReveal)
}

// buildHashCommitTx constructs a HashCommitTx for the given reveal parameters.
// txNonce is the commit tx's account nonce (for ordering).
// revealNonce is the matching HashRevealTx's nonce — it is bound into hashCommit so the
// commit cannot be replayed for a different reveal nonce.
// hashCommit = keccak256("OP_COMMIT_BIND_v1" || nullifier || preImage || txDigest || revealNonce_u64be)
func buildHashCommitTx(
	chainID *big.Int,
	from common.Address,
	txNonce uint64,
	revealNonce uint64,
	nullifier common.Hash,
	preImage [32]byte,
	txDigest common.Hash,
	expireAfterBlocks uint8,
) *types.Transaction {
	domainCommitBind := hashE2EKeccak([]byte("OP_COMMIT_BIND_v1"))
	var nonceBuf [8]byte
	nonceBuf[0] = byte(revealNonce >> 56)
	nonceBuf[1] = byte(revealNonce >> 48)
	nonceBuf[2] = byte(revealNonce >> 40)
	nonceBuf[3] = byte(revealNonce >> 32)
	nonceBuf[4] = byte(revealNonce >> 24)
	nonceBuf[5] = byte(revealNonce >> 16)
	nonceBuf[6] = byte(revealNonce >> 8)
	nonceBuf[7] = byte(revealNonce)
	hashCommit := hashE2EKeccak(domainCommitBind[:], nullifier[:], preImage[:], txDigest[:], nonceBuf[:])

	inner := &types.HashCommitTx{
		ChainID:           chainID,
		From:              from,
		Nonce:             txNonce,
		HashCommit:        hashCommit,
		Gas:               100_000,
		GasFeeCap:         big.NewInt(params.InitialBaseFee * 2),
		GasTipCap:         big.NewInt(1),
		ExpireAfterBlocks: expireAfterBlocks,
	}
	return types.NewTx(inner)
}

// TestHashRevealTxCrossBlock verifies the cross-block Commit-Reveal path:
// block N contains a HashCommitTx, block N+1 contains the matching HashRevealTx.
// The pending commit is stored in NullifierTree state (slots 73/74) and consumed
// on reveal. ExpireAfterBlocks=3 means the reveal is valid for blocks N..N+3.
func TestHashRevealTxCrossBlock(t *testing.T) {
	// Single spend: chainLen=1 keeps the test minimal.
	const chainLen = uint32(1)

	var spendSK [32]byte
	spendSK[31] = 0x11
	var r [32]byte
	r[31] = 0x22

	domainOTASpend := hashE2EKeccak([]byte("OP_OTA_SPEND_v1"))
	otaSpendSK := [32]byte(hashE2EKeccak(domainOTASpend[:], spendSK[:], r[:]))

	// chain[0] = otaSpendSK, chain[1] = keccak256(chain[0]) = commitment
	chain := make([][32]byte, chainLen+1)
	chain[0] = otaSpendSK
	chain[1] = [32]byte(hashE2EKeccak(chain[0][:]))
	commitment := chain[1]
	otaAddr := hashE2EDeriveOTAAddress(commitment)

	recipient := common.HexToAddress("0x000000000000000000000000000000000000dead")
	initialBalance := new(big.Int).Mul(big.NewInt(1e9), big.NewInt(1e9))
	sendValue := big.NewInt(500)

	genesis := &Genesis{
		Config:  params.AllEthashProtocolChanges,
		BaseFee: big.NewInt(params.InitialBaseFee),
		Alloc: GenesisAlloc{
			otaAddr: {Balance: initialBalance},
			NullifierTreeAddress: {
				Nonce:   1,
				Storage: hashE2EGenesisStorage(otaAddr, commitment, chainLen),
			},
		},
	}

	db := rawdb.NewMemoryDatabase()
	blockchain, err := NewBlockChain(db, genesis, ethash.NewFaker(), DefaultConfig())
	if err != nil {
		t.Fatalf("NewBlockChain: %v", err)
	}
	defer blockchain.Stop()

	// CommitTx uses nonce=0; RevealTx uses nonce=1 (account nonce advances after commit).
	// All cryptographic values (txDigest, nullifier, hashCommit) are derived from revealNonce=1.
	commitNonce := uint64(0)
	revealNonce := uint64(1)

	preImage := chain[0] // step 1: reveal chain[0], keccak256(chain[0])==chain[1]==commitment
	revealTx := buildHashRevealTx(
		params.AllEthashProtocolChanges.ChainID,
		otaAddr, revealNonce, recipient, sendValue, preImage,
	)
	revealInner := revealTx.HashRevealInner()
	txDigest := revealInner.TxDigest()
	nullifier := revealInner.Nullifier

	// Block 1: HashCommitTx (ExpireAfterBlocks=3 → valid through block 1+3=4).
	const expireAfterBlocks = uint8(3)
	commitTx := buildHashCommitTx(
		params.AllEthashProtocolChanges.ChainID,
		otaAddr, commitNonce, revealNonce,
		nullifier, preImage, txDigest,
		expireAfterBlocks,
	)

	// Block 2: HashRevealTx (cross-block: pendingCommit from block 1).
	// Generate 2 blocks: block 0 (commit), block 1 (reveal).
	_, allBlocks, _ := GenerateChainWithGenesis(genesis, ethash.NewFaker(), 2, func(i int, b *BlockGen) {
		switch i {
		case 0:
			b.AddTx(commitTx)
		case 1:
			b.AddTx(revealTx)
		}
	})

	n, err := blockchain.InsertChain(allBlocks)
	if err != nil {
		t.Fatalf("InsertChain failed at block %d: %v", n+1, err)
	}
	if n != 2 {
		t.Fatalf("expected 2 blocks inserted, got %d", n)
	}

	stateDB, err := blockchain.State()
	if err != nil {
		t.Fatalf("blockchain.State: %v", err)
	}
	ns := NewNullifierState(stateDB)

	// chainDepth must be 0 (exhausted after 1 spend).
	if depth := ns.ChainDepth(otaAddr); depth != 0 {
		t.Errorf("chainDepth: got %d, want 0", depth)
	}
	// lastReveal must equal chain[0].
	if got := ns.LastReveal(otaAddr); got != common.Hash(chain[0]) {
		t.Errorf("lastReveal: got %x, want %x", got, chain[0])
	}
	// Nullifier must be spent.
	if !ns.IsSpent(otaAddr, nullifier) {
		t.Errorf("nullifier not marked spent")
	}
	// Cross-block pending commit must be cleared after reveal.
	if got := ns.PendingCommit(otaAddr); got != (common.Hash{}) {
		t.Errorf("pendingCommit not cleared: %x", got)
	}
	// Recipient balance.
	if bal := stateDB.GetBalance(recipient).ToBig(); bal.Cmp(sendValue) != 0 {
		t.Errorf("recipient balance: got %s, want %s", bal, sendValue)
	}

	t.Logf("✓ Cross-block Commit-Reveal: commit in block 1, reveal in block 2")
	t.Logf("  pendingCommit cleared: %v", ns.PendingCommit(otaAddr) == (common.Hash{}))
	t.Logf("  nullifier spent: %v", ns.IsSpent(otaAddr, nullifier))
}
