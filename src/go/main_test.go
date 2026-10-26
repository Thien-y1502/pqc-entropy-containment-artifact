package main

import "testing"

func TestCaptureAndParseHybridShare(t *testing.T) {
	item, err := runUnit("A3_ROLE_ROUTED", "origin_rng_state_reuse", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !item.ClientHelloParseAccepted || item.ConfigRandBytes == 0 {
		t.Fatalf("unexpected trace: %+v", item)
	}
}

func TestRoleRoutedPartitionPreservesPeerFreshness(t *testing.T) {
	anchor, err := runUnit("A3_ROLE_ROUTED", "origin_rng_state_reuse", 1000)
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := runUnit("A3_ROLE_ROUTED", "origin_rng_state_reuse", 1001)
	if err != nil {
		t.Fatal(err)
	}
	if anchor.MLKEMPublicKeySHA256 != comparison.MLKEMPublicKeySHA256 {
		t.Fatal("fault-origin ML-KEM output should repeat")
	}
	if anchor.X25519PublicKeySHA256 == comparison.X25519PublicKeySHA256 {
		t.Fatal("role-routed X25519 output should remain fresh")
	}
}

func TestGlobalSplitShamIsUnreached(t *testing.T) {
	item, err := runUnit("A2_GLOBAL_SPLIT_SHAM", "origin_rng_state_reuse", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if item.CryptoRandReads != 0 {
		t.Fatalf("global crypto/rand unexpectedly reached: %+v", item)
	}
}

func TestModeledReaderRollbackIsReplayable(t *testing.T) {
	first, _ := readers("A0_SHARED", "origin_rng_state_reuse", 0)
	second, _ := readers("A0_SHARED", "origin_rng_state_reuse", 1)
	left := make([]byte, 32)
	right := make([]byte, 32)
	if _, err := first.Read(left); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Read(right); err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) {
		t.Fatal("modeled reader state did not replay")
	}
}
