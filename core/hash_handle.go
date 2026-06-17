// Copyright 2025 The op-geth Authors.
// Hash-Only L2 — ECDSA-free OP Stack rollup — OTA Handle Registry
// SPDX-License-Identifier: LGPL-2.1-or-later

package core

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
)

// HandleRegistryAddress is the predeploy address of the HandleRegistry on L2.
// Usernames are registered here and globally unique on-chain.
var HandleRegistryAddress = common.HexToAddress("0x4200000000000000000000000000000000000046")

// OTADeleteAddress is the predeploy address for OTA self-deletion on L2.
// A HashRevealTx targeting this address zeroes the sender's NullifierTree state
// and releases any registered handle, making the OTA permanently inactive.
var OTADeleteAddress = common.HexToAddress("0x4200000000000000000000000000000000000047")

// isGasFreeHashTx reports whether the tx is processed without charging ETH gas.
// On the Hash-Only L2, preimage-chain authentication provides spam protection;
// ETH gas fees only apply to value-transfer RevealTxs. Metadata operations
// (handle registration, OTA deletion) and the commit phase are always free.
func isGasFreeHashTx(msg *Message) bool {
	if msg.IsHashCommitTx {
		return true
	}
	if msg.IsHashRevealTx && msg.To != nil {
		return *msg.To == HandleRegistryAddress || *msg.To == OTADeleteAddress
	}
	return false
}

// HandleRegistryState wraps a vm.StateDB for typed access to HandleRegistry storage.
//
// Storage layout:
//   slot 0: nameToAddr  mapping(bytes32 => address)  — username → OTA address
//   slot 1: addrToName  mapping(address  => bytes32) — OTA address → username
//
// Usernames are stored as raw UTF-8 bytes, right-padded with zeros to 32 bytes.
// Only lowercase alphanumeric characters plus '_' and '-' are valid.
// Max length: 32 bytes.
type HandleRegistryState struct {
	state vm.StateDB
}

func NewHandleRegistryState(state vm.StateDB) *HandleRegistryState {
	return &HandleRegistryState{state: state}
}

// AddressOf returns the OTA address registered for the given username (zero if none).
func (h *HandleRegistryState) AddressOf(name [32]byte) common.Address {
	slot := mappingSlot(common.Hash(name), uint64(0))
	v := h.state.GetState(HandleRegistryAddress, slot)
	return common.BytesToAddress(v[12:])
}

// NameOf returns the username registered for the given OTA address (zero if none).
func (h *HandleRegistryState) NameOf(addr common.Address) [32]byte {
	slot := mappingSlot(addrToHash(addr), uint64(1))
	return [32]byte(h.state.GetState(HandleRegistryAddress, slot))
}

// Register claims a username for an OTA address.
// Returns false if the username is already taken by a different address.
// If the address already owns a different username, it is released first.
func (h *HandleRegistryState) Register(addr common.Address, name [32]byte) bool {
	existing := h.AddressOf(name)
	if existing != (common.Address{}) && existing != addr {
		return false // taken by someone else
	}
	if existing == addr && h.NameOf(addr) == name {
		return true // already registered, no-op (preimage is still consumed by the TX)
	}
	// Release old name if address already had one
	old := h.NameOf(addr)
	if old != ([32]byte{}) && old != name {
		oldSlot := mappingSlot(common.Hash(old), uint64(0))
		h.state.SetState(HandleRegistryAddress, oldSlot, common.Hash{})
	}
	// Forward: nameToAddr[name] = addr
	nameSlot := mappingSlot(common.Hash(name), uint64(0))
	var addrVal common.Hash
	copy(addrVal[12:], addr[:])
	h.state.SetState(HandleRegistryAddress, nameSlot, addrVal)
	// Reverse: addrToName[addr] = name
	addrSlot := mappingSlot(addrToHash(addr), uint64(1))
	h.state.SetState(HandleRegistryAddress, addrSlot, common.Hash(name))
	return true
}

// Release removes the username binding for the given OTA address.
func (h *HandleRegistryState) Release(addr common.Address) {
	name := h.NameOf(addr)
	if name == ([32]byte{}) {
		return
	}
	nameSlot := mappingSlot(common.Hash(name), uint64(0))
	h.state.SetState(HandleRegistryAddress, nameSlot, common.Hash{})
	addrSlot := mappingSlot(addrToHash(addr), uint64(1))
	h.state.SetState(HandleRegistryAddress, addrSlot, common.Hash{})
}

// IsValidHandleName checks that name contains only [a-z0-9_-] with no embedded zeros
// before a non-zero byte, and at least one non-zero byte.
func IsValidHandleName(name [32]byte) bool {
	sawContent := false
	seenZero := false
	for _, b := range name {
		if b == 0 {
			seenZero = true
			continue
		}
		if seenZero {
			return false // non-zero byte after zero padding
		}
		if !isHandleChar(b) {
			return false
		}
		sawContent = true
	}
	return sawContent
}

func isHandleChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-'
}

// HandleDataToName converts TX data bytes to a 32-byte handle name.
// Returns zeros and false if data is empty or all-zero (treat as release).
func HandleDataToName(data []byte) ([32]byte, bool) {
	var name [32]byte
	if len(data) == 0 {
		return name, false
	}
	n := len(data)
	if n > 32 {
		n = 32
	}
	copy(name[:], data[:n])
	// Check if non-zero
	for _, b := range name {
		if b != 0 {
			return name, true
		}
	}
	return name, false
}
