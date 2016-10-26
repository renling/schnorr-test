package main

// copied from bford/golang-x-crypto/ed25519/cosi/example_test.go

import (
	"fmt"
	"github.com/bford/golang-x-crypto/ed25519"
	"github.com/bford/golang-x-crypto/ed25519/cosi"
)

func main() {    
	pubKey1, priKey1, _ := ed25519.GenerateKey(nil)
	pubKey2, priKey2, _ := ed25519.GenerateKey(nil)
	pubKeys := []ed25519.PublicKey{pubKey1, pubKey2}

	// Sign a test message.
	message := []byte("Hello World")
	sig := Sign(message, pubKeys, priKey1, priKey2)
    fmt.Printf("signature: %v\n", sig)

	// Now verify the resulting collective signature.
	// This can be done by anyone any time, not just the leader.
	valid := cosi.Verify(pubKeys, nil, message, sig)
	fmt.Printf("signature valid: %v\n", valid)
}

func Sign(message []byte, pubKeys []ed25519.PublicKey, priKey1, priKey2 ed25519.PrivateKey) []byte {

	// Each cosigner first needs to produce a per-message commit.
	commit1, secret1, _ := cosi.Commit(nil)
	commit2, secret2, _ := cosi.Commit(nil)
	commits := []cosi.Commitment{commit1, commit2}

	// The leader then combines these into an aggregate commit.
	cosigners := cosi.NewCosigners(pubKeys, nil)
	aggregatePublicKey := cosigners.AggregatePublicKey()
	aggregateCommit := cosigners.AggregateCommit(commits)

	// The cosigners now produce their parts of the collective signature.
	sigPart1 := cosi.Cosign(priKey1, secret1, message, aggregatePublicKey, aggregateCommit)
	sigPart2 := cosi.Cosign(priKey2, secret2, message, aggregatePublicKey, aggregateCommit)
	sigParts := []cosi.SignaturePart{sigPart1, sigPart2}

	// Finally, the leader combines the two signature parts
	// into a final collective signature.
	sig := cosigners.AggregateSignature(aggregateCommit, sigParts)

	return sig
}
