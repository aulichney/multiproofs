package main

import (
	"fmt"
	mcl "github.com/alinush/go-mcl"
	kzg2 "github.com/protolambda/go-kzg"
	"github.com/protolambda/go-kzg/bls"
)

func main() {
	//module initialization function, we use bls12-381, pairing-friendly elliptic curve
	mcl.InitFromString("bls12-381")

	//fft settings initialize
	//FFT used to efficiently multiply polynomials
	fs := kzg2.NewFFTSettings(4)

	//creates setup of n values from given secret, s^i for i = 0...n-1, group elements available to prover and verifier
	s1, s2 := kzg2.GenerateTestingSetup("1927409816240961209460912649124", 16+1)

	//input 2 secret vectors of length n
	ks := kzg2.NewKZGSettings(fs, s1, s2)

	//list of coefficients for polynomial
	polynomial := [16]uint64{1, 2, 3, 4, 7, 7, 7, 7, 13, 13, 13, 13, 13, 13, 13, 13}
	//polynomial := [16]uint64{1, 2, 3, 4, 7, 7, 7, 7, 13, 13, 13, 13, 13, 13, 13, 14}
	//polynomial := [16]uint64{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	//initialize bls.Fr struct to fill with polynomial coefficients
	//what exactly is this structure?
	polynomialFr := make([]bls.Fr, len(polynomial), len(polynomial))

	for i := 0; i < len(polynomial); i++ {
		bls.AsFr(&polynomialFr[i], polynomial[i])
	}

	//commit to polynomial
	commitment := ks.CommitToPoly(polynomialFr)

	//Compute Kate proof for polynomial in coefficient form at positions x * w^y where w is
	// an n-th root of unity
	x := uint64(5431)
	var xFr bls.Fr
	bls.AsFr(&xFr, x)

	//what is the coset and cosetScale?
	cosetScale := uint8(3)
	coset := make([]bls.Fr, 1<<cosetScale, 1<<cosetScale) //1 << cosetScale is 2^cosetScale

	s1, s2 = kzg2.GenerateTestingSetup("1927409816240961209460912649124", 8+1)
	ks = kzg2.NewKZGSettings(kzg2.NewFFTSettings(cosetScale), s1, s2)

	for i := 0; i < len(coset); i++ {
		fmt.Printf("rootz %d: %s\n", i, bls.FrStr(&ks.ExpandedRootsOfUnity[i]))
		bls.MulModFr(&coset[i], &xFr, &ks.ExpandedRootsOfUnity[i])
		fmt.Printf("coset %d: %s\n", i, bls.FrStr(&coset[i]))
	}

	//evaluate polynomial at each point
	ys := make([]bls.Fr, len(coset), len(coset))
	for i := 0; i < len(coset); i++ {
		bls.EvalPolyAt(&ys[i], polynomialFr, &coset[i])
		fmt.Printf("ys %d: %s\n", i, bls.FrStr(&ys[i]))
	}

	//compute proof
	proof := ks.ComputeProofMulti(polynomialFr, x, uint64(len(coset)))
	fmt.Printf("proof: %s\n", bls.StrG1(proof))

	//Check that proof matches expected
	if !ks.CheckProofMulti(commitment, proof, &xFr, ys) {
		fmt.Printf("could not verify proof")
	}
	if ks.CheckProofMulti(commitment, proof, &xFr, ys) {
		fmt.Printf("proof verified!")
	}
}
