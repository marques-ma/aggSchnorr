package main

import (
	"fmt"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"

	"crypto/ecdsa"
	"crypto/rand"
	"crypto/elliptic"
	"math/big"
)

// Set parameters
var (
	curve = edwards25519.NewBlakeSHA256Ed25519()
	sha256 = curve.Hash()
	g = curve.Point().Base()
)

type Signature struct {
    R kyber.Point
    S kyber.Scalar
}

// Sign using Schnorr EdDSA
// m: Message
// z: Private key
func Sign(m kyber.Scalar, z kyber.Scalar) Signature {

    // Pick a random k from allowed set.
    k := curve.Scalar().Pick(curve.RandomStream())

    // r = k * G (a.k.a the same operation as r = g^k)
    r := curve.Point().Mul(k, g)

    // h := Hash(r.String() + m + publicKey)
    // publicKey := curve.Point().Mul(z, g)
    // h := Hash(publicKey.String() + m)
    
    // s = k + e * x
    s := curve.Scalar().Add(k, curve.Scalar().Mul(m, z))

    return Signature{R: r, S: s}
}

// Verify Schnorr EdDSA signatures
// m: Message
// s: Signature
// y: Public key
func Verify(m kyber.Scalar , S Signature, y kyber.Point) bool {

    // Attempt to reconstruct 's * G' with a provided signature; s * G = r - h * y
    sGv := curve.Point().Add(S.R, curve.Point().Mul(m, y))

    // Construct the actual 's * G'
    sG := curve.Point().Mul(S.S, g)

    // Equality check; ensure signature and public key outputs to s * G.
    return sG.Equal(sGv)
}

// Return a new random key pair
func RandomKeyPair() (kyber.Scalar, kyber.Point){

    privateKey	:= curve.Scalar().Pick(curve.RandomStream())
    publicKey 	:= curve.Point().Mul(privateKey, g)

    return privateKey, publicKey
}

// Given string, return hash Scalar
func Hash(s string) kyber.Scalar {
    sha256.Reset()
    sha256.Write([]byte(s))

    return curve.Scalar().SetBytes(sha256.Sum(nil))
}

// Given private key in big.Int, return its hash as Scalar
func convKey(d *big.Int) kyber.Scalar {
    sha256.Reset()
    sha256.Write(d.Bytes())

    return curve.Scalar().SetBytes(sha256.Sum(nil))
}

// ------------------------------------ //
// Generate a multi-signature given 2 signatures and the corresponding public keys
func mulSig(sigA, sigB Signature, pubKeyA, pubKeyB kyber.Point) (Signature, kyber.Point) {
	newR := curve.Point().Add(sigA.R, sigB.R)
	newS := curve.Scalar().Add(sigA.S, sigB.S)
	newPubKey := curve.Point().Add(pubKeyA, pubKeyB)
	// fmt.Println("Aggregated publicKey in aggSig: ", newPubKey)

	var sigC Signature
	sigC = Signature{
		R: newR,
		S: newS,
	}

	return sigC, newPubKey
}

func main() {
	message := "message-2b-signed"
	fmt.Println("Message: ", message)
	fmt.Printf("\n------------- Key generation -------------\n")
	// Generate EdDSA Keypair
	sk1, pk1 := RandomKeyPair()
	fmt.Printf("key pair 1: %v %v\n", sk1, pk1)

	// // Generate Keypair 2
	// sk2, pk2 := RandomKeyPair()

	// -------------ECDSA------------------ //
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("Error generating ECDSA key pair: %s\n", err)
		return
	}
	fmt.Printf("Original ECDSA private key: %v\n", privateKey.D.String())
	// Convert ECDSA privKey to EdDSA privKey
	eddPrivKey := convKey(privateKey.D)
	eddPublicKey := curve.Point().Mul(eddPrivKey, g)
	fmt.Printf("Key pair 2: %v %v\n", eddPrivKey, eddPublicKey)
	// ------------------------------------ //

	// Aggregate public keys
	aggPubKey := curve.Point().Add(pk1, eddPublicKey)

	// Create the hash with aggregated Public Key
	// TODO: This way it is vulnerable to rogue-key. Add r in hash.
	h := Hash(message + aggPubKey.String())
	fmt.Printf("\n------------- Signature generation -------------\n")
	// Generate signatures
	fmt.Println("Signing message with key pair 1...")
	sig1 := Sign(h, sk1)
	fmt.Println("Signature 1: ", sig1)
	fmt.Println("Signing message with key pair 2...")
	sig2 := Sign(h, eddPrivKey)
	fmt.Println("Signature 2: ", sig2)
	fmt.Printf("\n------------- Signature validation -------------\n")
	// Verify partial signatures
	fmt.Println("Checking signatures...")
	if !Verify(h, sig1, pk1) && !Verify(h, sig2, eddPublicKey) {
		fmt.Println("Failed verifying partial signatures!")
		return
	} else {
		fmt.Println("Success verifying partial signatures!")
	}
	fmt.Printf("\n------------- Multi-signature generation -------------\n")
	// Multi-signature construction
	fmt.Println("Aggregating keys and signatures with musig...")
	mulSig, aggPubKey := mulSig(sig1, sig2, pk1, eddPublicKey)
	fmt.Printf("\n------------- Multi-signature validation -------------\n")
	// validate aggregated signature
	fmt.Println("Validating aggregated keys and signatures...")
	if !Verify(h, mulSig, aggPubKey) {
		fmt.Println("Failed verifying aggregated signature!")
		return
	} else {
		fmt.Println("Success verifying aggregated signatures!")
	}

	// Debug
	// fmt.Println("Message: ", message)
	// fmt.Println("Sig1   : ", sig1)
	// fmt.Println("Sig2   : ", sig2)
	fmt.Printf("\n------------- Output -------------\n")
	fmt.Println("Multi-signature : ", mulSig)
	fmt.Println("Aggregated Keys : ", aggPubKey)
}