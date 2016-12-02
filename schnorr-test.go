package main

import (
	"fmt"
	"github.com/bford/golang-x-crypto/ed25519"
	"github.com/bford/golang-x-crypto/ed25519/cosi"
)

func main() {
	N := 100;
	pubKeys := make([]ed25519.PublicKey, N)
	priKeys := make([]ed25519.PrivateKey, N)
	for i := 0; i < N; i++ {
		pubKeys[i], priKeys[i], _ = ed25519.GenerateKey(nil)
	}

	cosigners := cosi.NewCosigners(pubKeys, nil)
	cosigners.SetMaskBit(1, cosi.Disabled)
	cosigners.SetPolicy( cosi.ThresholdPolicy(N/2) )

	// Sign a test message.
	message := []byte("Hello World")
	sig := Sign(message, cosigners, priKeys)
    fmt.Printf("signature: %v\n", sig)

	// Now verify the resulting collective signature.
	// This can be done by anyone any time, not just the leader.
	valid := cosigners.Verify(message, sig)
	fmt.Printf("signature valid: %v\n", valid)
}

func Sign(message []byte, cosigners *cosi.Cosigners, priKeys []ed25519.PrivateKey) []byte {
	N := len(priKeys)

	// Each cosigner first needs to produce a per-message commit.
	commits := make([]cosi.Commitment, N)
	secrets := make([]*cosi.Secret, N)
	for i := 0; i < N; i++ {
		commits[i], secrets[i], _ = cosi.Commit(nil)
	}

	// The leader then aggregate public keys and commit.
	aggregatePublicKey := cosigners.AggregatePublicKey()
	aggregateCommit := cosigners.AggregateCommit(commits)

	// The cosigners now produce their parts of the collective signature.
	sigParts := make([]cosi.SignaturePart, N)
	for i := 0; i < N; i++ {
		sigParts[i] = cosi.Cosign(priKeys[i], secrets[i], message, aggregatePublicKey, aggregateCommit)
	}

	// Finally, the leader combines the  signature parts
	// into a final collective signature.
	sig := cosigners.AggregateSignature(aggregateCommit, sigParts)

	return sig
}
