package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
)

func attestation_example() int {
	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		log.Fatal("Unable to open TPM")
	}

	eks, err := tpm.EKs()
	if err != nil {
		log.Fatal("Unable to fetch EK")
	}
	for i := 0; i < len(eks); i++ {
		fmt.Println(eks[i].Certificate.PublicKeyAlgorithm)
	}
	ek := eks[0]

	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		log.Fatal("Unable to create AK")
	}

	attestParams := ak.AttestationParameters()

	akBytes, err := ak.Marshal()
	if err != nil {
		log.Fatal("Unable to perform AK Marshal")
	}

	if err := os.WriteFile("encrypted_ak.json", akBytes, 0600); err != nil {
		log.Fatal("Unable to write AK")
	}

	if err := os.WriteFile("ek.out", ek.Certificate.Raw, 0600); err != nil {
		log.Fatal("Unable to write EK")
	}

	if err := os.WriteFile("attest_params.out", attestParams.Public, 0600); err != nil {
		log.Fatal("Unable to write attest Params")
	}
	return 0
}

func rand_example() int {
	f, err := os.OpenFile("/dev/tpmrm0", os.O_RDWR, 0)
	if err != nil {
		log.Fatalf("opening tpm: %v", err)
	}
	defer f.Close()

	out, err := tpm2.GetRandom(f, 16)
	if err != nil {
		log.Fatalf("getting random bytes: %v", err)
	}

	fmt.Printf("%x\n", out)

	return 0
}

func main() {
	ret := 0
	//ret = attestation_example()
	ret = rand_example()
	os.Exit(ret)
}
