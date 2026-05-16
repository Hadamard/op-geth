// Copyright 2025 The op-geth Authors.
// Hash-Only L2 — ECDSA-free OP Stack rollup — Phase 3: PQ Stealth
// SPDX-License-Identifier: LGPL-2.1-or-later

package core

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// StealthPoolAddress is the predeploy address of the StealthPool contract on L2.
// Must match packages/contracts-bedrock/src/L2/StealthPool.sol.
var StealthPoolAddress = common.HexToAddress("0x4200000000000000000000000000000000000044")

// One-Time Address (OTA) key derivation domains — must match StealthPool.sol constants.
var (
	otaSpendDomain = crypto.Keccak256Hash([]byte("OP_OTA_SPEND_v1"))
	otaViewDomain  = crypto.Keccak256Hash([]byte("OP_OTA_VIEW_v1"))
	otaTagDomain   = crypto.Keccak256Hash([]byte("OP_OTA_TAG_v1"))
	otaCommitDomain = crypto.Keccak256Hash([]byte("OP_COMMIT_v1"))
	hashAddrDomainStealth = crypto.Keccak256Hash([]byte("OP_HASH_ADDR_v1"))
)

// DeriveOTASpendSK derives the OTA spend secret key from the account's spend_sk and a random nonce r.
//
//	ota_spend_sk = keccak256("OP_OTA_SPEND_v1" ‖ spend_sk ‖ r)
func DeriveOTASpendSK(spendSK, r common.Hash) common.Hash {
	return crypto.Keccak256Hash(otaSpendDomain[:], spendSK[:], r[:])
}

// DeriveOTAViewSK derives the OTA view secret key from the account's view_sk and a random nonce r.
//
//	ota_view_sk = keccak256("OP_OTA_VIEW_v1" ‖ view_sk ‖ r)
func DeriveOTAViewSK(viewSK, r common.Hash) common.Hash {
	return crypto.Keccak256Hash(otaViewDomain[:], viewSK[:], r[:])
}

// DeriveOTAScanTag computes the 4-byte scan tag for an OTA slot.
//
//	scan_tag = bytes4(keccak256("OP_OTA_TAG_v1" ‖ view_sk ‖ r))
//
// The scan tag is published alongside the OTA address so that recipients
// can efficiently filter announcements without scanning all known nonces.
func DeriveOTAScanTag(viewSK, r common.Hash) [4]byte {
	h := crypto.Keccak256Hash(otaTagDomain[:], viewSK[:], r[:])
	var tag [4]byte
	copy(tag[:], h[:4])
	return tag
}

// DeriveOTACommitment computes the OTA commitment from the derived spend/view keys and chainId.
//
//	ota_commitment = keccak256("OP_COMMIT_v1" ‖ ota_spend_sk ‖ ota_view_sk ‖ chainId32)
//
// chainId is encoded as a 32-byte big-endian value (same as in the main hash-account scheme).
func DeriveOTACommitment(otaSpendSK, otaViewSK, chainID32 common.Hash) common.Hash {
	return crypto.Keccak256Hash(otaCommitDomain[:], otaSpendSK[:], otaViewSK[:], chainID32[:])
}

// DeriveOTAAddress computes the L2 address for an OTA commitment.
//
//	ota_address = trunc20(keccak256("OP_HASH_ADDR_v1" ‖ ota_commitment))
func DeriveOTAAddress(otaCommitment common.Hash) common.Address {
	h := crypto.Keccak256Hash(hashAddrDomainStealth[:], otaCommitment[:])
	return common.BytesToAddress(h[12:])
}

// GenerateOTA is a convenience function that derives all OTA fields from the account's root
// keys and a per-slot random nonce r. Returns (otaAddress, scanTag, otaCommitment).
//
// The caller keeps (spendSK, viewSK, r) private and publishes (otaAddress, scanTag).
// chainID32 is the L2 chain ID encoded as 32-byte big-endian.
func GenerateOTA(spendSK, viewSK, r, chainID32 common.Hash) (addr common.Address, tag [4]byte, commitment common.Hash) {
	otaSpend := DeriveOTASpendSK(spendSK, r)
	otaView := DeriveOTAViewSK(viewSK, r)
	commitment = DeriveOTACommitment(otaSpend, otaView, chainID32)
	addr = DeriveOTAAddress(commitment)
	tag = DeriveOTAScanTag(viewSK, r)
	return
}

// StealthPoolState wraps a vm.StateDB for typed read access to StealthPool predeploy storage.
//
// StealthPool Solidity storage layout:
//   slot 0: scanTagOf   mapping(address => bytes4)
//   slot 1: isFunded    mapping(address => bool)
//   slot 2: isRegistered mapping(address => bool)
//   slot 3: totalOTAs   uint32
type StealthPoolState struct {
	state interface {
		GetState(common.Address, common.Hash) common.Hash
	}
}

func NewStealthPoolState(state interface {
	GetState(common.Address, common.Hash) common.Hash
}) *StealthPoolState {
	return &StealthPoolState{state: state}
}

// IsRegistered returns true if the OTA address has been registered in the pool.
func (s *StealthPoolState) IsRegistered(otaAddr common.Address) bool {
	slot := mappingSlot(addrToHash(otaAddr), 2)
	v := s.state.GetState(StealthPoolAddress, slot)
	return v[31] != 0
}

// IsFunded returns true if the OTA has been marked as funded.
func (s *StealthPoolState) IsFunded(otaAddr common.Address) bool {
	slot := mappingSlot(addrToHash(otaAddr), 1)
	v := s.state.GetState(StealthPoolAddress, slot)
	return v[31] != 0
}

// ScanTagOf returns the 4-byte scan tag for a registered OTA.
func (s *StealthPoolState) ScanTagOf(otaAddr common.Address) [4]byte {
	slot := mappingSlot(addrToHash(otaAddr), 0)
	v := s.state.GetState(StealthPoolAddress, slot)
	// bytes4 is stored left-aligned (high bytes) in a bytes32 slot.
	var tag [4]byte
	copy(tag[:], v[:4])
	return tag
}
