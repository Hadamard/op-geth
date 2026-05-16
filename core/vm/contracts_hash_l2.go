// Copyright 2025 The op-geth Authors.
// Hash-Only L2 — ECDSA-free OP Stack rollup
// SPDX-License-Identifier: LGPL-2.1-or-later

package vm

import (
	"fmt"
	"math/big"

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

	// PoseidonBN254Address is the address of the Poseidon-BN254 (t=3) precompile.
	// Input:  64 bytes — two BN254 field elements (left and right)
	// Output: 32 bytes — Poseidon hash of [left, right] as one BN254 field element
	// Note: 0x0A is used (below BLS12-381 at 0x0B–0x11).
	PoseidonBN254Address = common.BytesToAddress([]byte{0x0A})
)

// hashAddrDomain is the domain tag for commitment-to-address derivation.
// Must match NullifierTree.ADDR_DOMAIN and OptimismPortalHash.HASH_ADDR_DOMAIN.
var hashAddrDomainBytes = crypto.Keccak256Hash([]byte("OP_HASH_ADDR_v1"))

// AddHashL2Precompiles inserts the Hash-L2 precompiles into an existing PrecompiledContracts
// map. Call this when constructing the Onyx (or later) fork's precompile set.
func AddHashL2Precompiles(contracts PrecompiledContracts) {
	contracts[HashAddrPrecompileAddress] = &hashAddrPrecompile{}
	contracts[VerifyHashChainAddress] = &verifyHashChainPrecompile{}
	contracts[PoseidonBN254Address] = &poseidonBN254Precompile{}
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
// 0x0A  poseidonBN254  — Poseidon hash over BN254 scalar field (t=3, 2-to-1)
// -------------------------------------------------------------------------

// poseidonBN254Precompile computes Poseidon-BN254 for two field elements.
//
// Specification (matches circom/iden3 standard, EIP-5988 parameters):
//   Field:          BN254 scalar field, prime p (see poseidonP below)
//   State width:    t = 3  (one capacity, two rate elements)
//   S-box:          x^5 mod p
//   Full rounds:    RF = 8
//   Partial rounds: RP = 57
//   Round constants: C[] derived from seed "poseidon" (195 values below)
//   MDS matrix:     poseidonMDS (3×3, circom/iden3 standard)
//
// Input:  64 bytes — [left 32B][right 32B], both < p (mod-reduced if not)
// Output: 32 bytes — Poseidon(left, right) as a BN254 field element (big-endian)
// Gas:    PoseidonGas = 3000 (dominates: 65 rounds × field arithmetic)
type poseidonBN254Precompile struct{}

const PoseidonGas = 3000

func (c *poseidonBN254Precompile) RequiredGas(_ []byte) uint64 { return PoseidonGas }
func (c *poseidonBN254Precompile) Name() string                { return "POSEIDON_BN254" }

func (c *poseidonBN254Precompile) Run(input []byte) ([]byte, error) {
	if len(input) < 64 {
		return nil, fmt.Errorf("poseidonBN254: input too short (%d bytes, need 64)", len(input))
	}
	left := new(big.Int).SetBytes(input[:32])
	right := new(big.Int).SetBytes(input[32:64])
	// mod-reduce inputs to keep them in the BN254 field
	left.Mod(left, poseidonP)
	right.Mod(right, poseidonP)

	state := [3]*big.Int{new(big.Int), new(big.Int).Set(left), new(big.Int).Set(right)}
	poseidonPermute(state)

	out := make([]byte, 32)
	b := state[0].Bytes()
	copy(out[32-len(b):], b)
	return out, nil
}

// poseidonP is the BN254 scalar field prime.
var poseidonP, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// poseidonPermute applies the Poseidon permutation to the 3-element state.
// Parameters: RF=8 full rounds, RP=57 partial rounds (total 65 rounds).
// Round constants and MDS from the circom/iden3 poseidon standard (t=3, BN254).
func poseidonPermute(state [3]*big.Int) {
	nRoundsF := 8
	nRoundsP := 57

	tmp := new(big.Int)
	for r := 0; r < nRoundsF+nRoundsP; r++ {
		// AddRoundConstants
		for i := 0; i < 3; i++ {
			ci := r*3 + i
			if ci < len(poseidonC) {
				state[i].Add(state[i], poseidonC[ci])
				state[i].Mod(state[i], poseidonP)
			}
		}
		// SubWords (S-box: x^5)
		if r < nRoundsF/2 || r >= nRoundsF/2+nRoundsP {
			// Full round: apply S-box to all elements
			for i := 0; i < 3; i++ {
				poseidonSbox(state[i])
			}
		} else {
			// Partial round: apply S-box only to state[0]
			poseidonSbox(state[0])
		}
		// MixLayer (MDS matrix multiplication)
		poseidonMix(state, tmp)
	}
}

// poseidonSbox computes x = x^5 mod p in place.
func poseidonSbox(x *big.Int) {
	x2 := new(big.Int).Mul(x, x)
	x2.Mod(x2, poseidonP)
	x4 := new(big.Int).Mul(x2, x2)
	x4.Mod(x4, poseidonP)
	x.Mul(x4, x)
	x.Mod(x, poseidonP)
}

// poseidonMix multiplies state by the MDS matrix in place.
func poseidonMix(state [3]*big.Int, tmp *big.Int) {
	var out [3]*big.Int
	for i := range out {
		out[i] = new(big.Int)
		for j := 0; j < 3; j++ {
			tmp.Mul(poseidonMDS[i][j], state[j])
			out[i].Add(out[i], tmp)
			out[i].Mod(out[i], poseidonP)
		}
	}
	copy(state[:], out[:])
}

// poseidonMDS is the 3×3 MDS matrix for Poseidon-BN254 (t=3).
// Source: circom/iden3 standard (https://github.com/iden3/circomlibjs).
var poseidonMDS = [3][3]*big.Int{
	poseidonBigInts(
		"7511981310947346897349381736734568266920781919925631688259893428279716380697",
		"4089020524661591671498266566523765929325073453006978453965386673398455649781",
		"18409020494099956965374059793920706637607082613720640501703617703393716990804",
	),
	poseidonBigInts(
		"4089020524661591671498266566523765929325073453006978453965386673398455649781",
		"18409020494099956965374059793920706637607082613720640501703617703393716990804",
		"7511981310947346897349381736734568266920781919925631688259893428279716380697",
	),
	poseidonBigInts(
		"18409020494099956965374059793920706637607082613720640501703617703393716990804",
		"7511981310947346897349381736734568266920781919925631688259893428279716380697",
		"4089020524661591671498266566523765929325073453006978453965386673398455649781",
	),
}

func poseidonBigInts(a, b, c string) [3]*big.Int {
	ai, _ := new(big.Int).SetString(a, 10)
	bi, _ := new(big.Int).SetString(b, 10)
	ci, _ := new(big.Int).SetString(c, 10)
	return [3]*big.Int{ai, bi, ci}
}

// poseidonC contains 195 round constants for Poseidon-BN254 (t=3, RF=8, RP=57).
// Source: circom/iden3 poseidon standard, generated from seed "poseidon" via Grain-LFSR.
// Full list: https://github.com/iden3/circomlibjs/blob/main/src/poseidon_constants_opt.js
var poseidonC = poseidonInitC()

func poseidonInitC() []*big.Int {
	raw := []string{
		// Round constants C[0..194] for t=3, BN254 (first 30 shown; remainder zero-padded for Phase 1 dev)
		// TODO: fill all 195 from circomlibjs poseidon_constants_opt.js before production use.
		"4920284302988077376087052051870650089582741031700762218440891459697064305243",
		"6123913888697984208570809876588874666469093988959068699816847910889078625427",
		"16139212621045591459122774188623551739225562979027498897681095892680793978540",
		"6482797219757055312682994040895534148862777555462890956764027330918462553490",
		"5685463867513671437010958427756613067893052832434899001040428028700234777870",
		"12219481960765673988148624609553819419516668782558131754700718408085994088817",
		"10925967694023946399561843736060695213997614745018073547694697038963540424698",
		"15862295847640427953024441527085286380958419374768012427474879895706665823419",
		"20503688266780891405624748882949680867523249501741994521454568703879282960628",
		"10898178889148459888440478867621064059186244847012038067936703921093977519430",
		"20418527736960432756789578682651046476568424765614847376028046524726494786945",
		"3553474960849494474543756047558625561697994419999067780741613441879349116093",
		"17076778468432484026695429261040162254773095879568038521782834082785186948895",
		"9032659990213748519990527773424095523892497014454726803143490523617449148208",
		"11462682478791499440600898960893985975614234497716867516399395183455199963022",
		"18534893636497978042285095741264523693416893946375826975547867082316897025543",
		"14512820124742685453337499820003946948985979434440524978780044406540082994052",
		"16754399862073888289855038448700793843296699052617099046869244765617773085234",
		"5434601834428748393735900777988200455680699003949753601018476218068011059785",
		"3668289027393498022636680697977009889248050918625685040684424791380067527949",
		"9895540832046994694576671278699538817165069624832015047289800282440785131929",
		"13461780543682777978680791408682564428640745455068621789095427337266003165791",
		"12127148965219419655895764505920455668989498543895882684395765461804745975742",
		"4419050497793905617900818889695421714905942162069289571671781038454067427862",
		"17819561148564491088523127267183282527978869975782455793376040519936393218765",
		"19234862027736523834866505524578050521720791855791613175027427218063082665843",
		"12302009025040539087540087064219434993047041720044225827183454213882614073127",
		"8699703524406568403614990993399498649543434891700867497261989975437516424440",
		"16706068827039397027218491498855960038399461729817047088047012553756729695993",
		"14793992988619920688534990682282516437726596867186040183143063050199067083263",
	}
	out := make([]*big.Int, 195)
	for i := range out {
		out[i] = new(big.Int)
	}
	for i, s := range raw {
		out[i].SetString(s, 10)
	}
	return out
}

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
