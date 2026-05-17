package vm

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// TestPoseidonBN254_KnownVectors verifies the precompile against circomlibjs test vectors.
// Reference: https://github.com/iden3/circomlibjs/blob/main/test/poseidon.js
func TestPoseidonBN254_KnownVectors(t *testing.T) {
	precompile := &poseidonBN254Precompile{}

	tests := []struct {
		name     string
		left     string // decimal
		right    string // decimal
		expected string // decimal
	}{
		// circomlibjs: poseidon([1, 2]) = 7853200120776062878684798364095072458815029376092732009249414926327459813530
		{
			name:     "poseidon([1,2])",
			left:     "1",
			right:    "2",
			expected: "7853200120776062878684798364095072458815029376092732009249414926327459813530",
		},
		// circomlibjs: poseidon([0, 0]) — the zero-hash; result from circomlibjs
		// We derive this by running poseidonPermute on state=[0,0,0]:
		// Just test that (0,0) produces a non-zero deterministic output
		{
			name:  "poseidon([0,0])_nonzero",
			left:  "0",
			right: "0",
			// We don't hardcode the expected value here — just check determinism below
		},
	}

	var lastZeroResult []byte
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			left, _ := new(big.Int).SetString(tc.left, 10)
			right, _ := new(big.Int).SetString(tc.right, 10)

			input := make([]byte, 64)
			lb := left.Bytes()
			rb := right.Bytes()
			copy(input[32-len(lb):32], lb)
			copy(input[64-len(rb):64], rb)

			out, err := precompile.Run(input)
			if err != nil {
				t.Fatalf("Run error: %v", err)
			}
			if len(out) != 32 {
				t.Fatalf("expected 32-byte output, got %d", len(out))
			}

			result := new(big.Int).SetBytes(out)

			if tc.expected != "" {
				exp, _ := new(big.Int).SetString(tc.expected, 10)
				if result.Cmp(exp) != 0 {
					t.Errorf("poseidon(%s, %s) = %s, want %s",
						tc.left, tc.right, result.String(), tc.expected)
				} else {
					t.Logf("OK: poseidon(%s, %s) = %s", tc.left, tc.right, result.String())
				}
			}

			if tc.name == "poseidon([0,0])_nonzero" {
				if result.Sign() == 0 {
					t.Error("poseidon(0,0) should not be zero")
				}
				lastZeroResult = append([]byte{}, out...)
			}
		})
	}

	// Verify determinism: run (0,0) again
	t.Run("determinism", func(t *testing.T) {
		if lastZeroResult == nil {
			t.Skip("no baseline result from zero test")
		}
		left := new(big.Int)
		right := new(big.Int)
		input := make([]byte, 64)
		lb, rb := left.Bytes(), right.Bytes()
		copy(input[32-len(lb):32], lb)
		copy(input[64-len(rb):64], rb)
		out, _ := precompile.Run(input)
		if hex.EncodeToString(out) != hex.EncodeToString(lastZeroResult) {
			t.Error("poseidon is not deterministic")
		}
	})

	// Verify that poseidon(a,b) != poseidon(b,a) in general (non-commutative for non-symmetric inputs)
	t.Run("non_commutative", func(t *testing.T) {
		one := big.NewInt(1)
		two := big.NewInt(2)

		in12 := make([]byte, 64)
		copy(in12[31:32], one.Bytes())
		copy(in12[63:64], two.Bytes())

		in21 := make([]byte, 64)
		copy(in21[31:32], two.Bytes())
		copy(in21[63:64], one.Bytes())

		out12, _ := precompile.Run(in12)
		out21, _ := precompile.Run(in21)
		if hex.EncodeToString(out12) == hex.EncodeToString(out21) {
			t.Error("poseidon(1,2) == poseidon(2,1) — unexpectedly commutative")
		}
	})
}

// TestPoseidonBN254_FieldReduction verifies that inputs > p are reduced mod p.
func TestPoseidonBN254_FieldReduction(t *testing.T) {
	precompile := &poseidonBN254Precompile{}

	p, _ := new(big.Int).SetString(
		"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	// p and p+1: poseidon(p, x) == poseidon(0, x)
	left_p := make([]byte, 32)
	copy(left_p, p.Bytes())

	left_0 := make([]byte, 32)
	right := make([]byte, 32)
	right[31] = 1

	in_p1 := append(left_p, right...)
	in_01 := append(left_0, right...)

	out_p, err1 := precompile.Run(in_p1)
	out_0, err2 := precompile.Run(in_01)
	if err1 != nil || err2 != nil {
		t.Fatalf("run errors: %v, %v", err1, err2)
	}
	if hex.EncodeToString(out_p) != hex.EncodeToString(out_0) {
		t.Errorf("poseidon(p, 1) != poseidon(0, 1): field reduction broken\ngot %x\nexp %x",
			out_p, out_0)
	}
}
