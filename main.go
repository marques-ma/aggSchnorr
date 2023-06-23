package main

import (
	"fmt"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"

	// "crypto/ecdsa"
	// "crypto/rand"
	// "crypto/elliptic"
	"math/big"
)

// Set global parameters
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

// --- Helper functions --- //
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

func main() {

	fmt.Printf("\n------------- Key1 generation -------------\n")
	// Generate EdDSA Keypair 1
	sk1, pk1 := RandomKeyPair()
	fmt.Printf("key pair 1: %v %v\n", sk1, pk1)

	fmt.Printf("\n------------- Create Token1 -------------\n")
	// Create dummy Token1
	payload1 := "Payload of token 1"
	fmt.Println("Payload 1  : ", payload1)
	h := Hash(pk1.String() + payload1)
	fmt.Printf("\n------------- Signature generation -------------\n")
	fmt.Println("Signing payload1 with key pair 1...")
	sig1 := Sign(h, sk1)
	fmt.Println("Signature 1: ", sig1)

	fmt.Printf("\n------------- Key2 generation -------------\n")
	// Generate EdDSA Keypair 2
	sk2, pk2 := RandomKeyPair()
	fmt.Printf("key pair 2: %v %v\n", sk2, pk2)

	// Extract s part from sig1 and create new private key
	combinedSk := curve.Scalar().Add(sig1.S, sk2)
	fmt.Println("combined sk (sig1.s + sk2)    : ", combinedSk)
	// calculate pubkey from sig1.S
	calcPkS1 := curve.Point().Mul(sig1.S, g)
	combinedPk := curve.Point().Add(calcPkS1, pk2)
	fmt.Println("combined pk (sig1.s * g + sk2): ", combinedPk)


	fmt.Printf("\n------------- Create Token2 -------------\n")
	// Create dummy Token2
	payload2 := payload1 + ". Appended informations in token2"
	fmt.Println("Payload 2  : ", payload2)
	h2 := Hash(combinedPk.String() + payload2 + payload1 + sig1.R.String())
	fmt.Printf("\n------------- Signature generation -------------\n")
	fmt.Println("Signing payload2 with combined private key (sig1.s + sk2)...")
	sig2 := Sign(h2, combinedSk)
	fmt.Println("Signature 2: ", sig2)


	// Failure test
	payload3 := payload2 + ". Appended informations in token2"
	fmt.Println("Payload 3  : ", payload3)
	h3 := Hash(combinedPk.String() + payload1 + payload2 + sig1.R.String()) 

	fmt.Printf("\n------------- Validation -------------\n")
	fmt.Println("Validating signature 2 with aggregated key...")
	if !Verify(h2, sig2, combinedPk) {
		fmt.Println("Failed verifying aggregated signature!")
		return
	} else {
		fmt.Println("Success verifying aggregated signature!")
	}

	fmt.Printf("\n------ Validation with wrong key --------\n")
	fmt.Println("Validating signature 2 with wrong key...")
	if !Verify(h3, sig2, calcPkS1) {
		fmt.Println("Failed verifying aggregated signature!")
		return
	} else {
		fmt.Println("Success verifying aggregated signature!")
	}

}

// agora esquema é pegar multisig.S e usar como sk para gerar nova sig. Lembrar q a msg q assinamos aqui é msg2 = message + multisig.R.
// em seguida, gerar mais uma sig de msg2 usando uma chave privada (pode ser key2)
//  por fim, agregar ambas. 

//  Como funcionaria validacao aqui? Usamos parte de uma sig para gerar chave da proxima, e agregamos as pk. 

// Gera par de chave 
// Gera primeiro token: T1 = (P1 + S1)
// Extrai s de S1
// gera sk2 = s + sk (soma s com chave privada do usuario)
// assina P2 (P1 + S1.R) com sk2
// T2 = P2 + S2

// Validação:
//Penso em duas possibilidades: Tn ja possui a chave pública pkn para validar Tn. Então a validacao pode ser simplesmente uma validacao comum
// Parece mais sensato reconstruir as chaves públicas: cada nova "camada (i.e. novas claims e assinatura)" traz a chave publica do Schoco.
// O validador pega a chave pública que está nno token, combina com a do usuario que está no LSVID e usa para validar a assinatura.