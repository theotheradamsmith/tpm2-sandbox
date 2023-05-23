package main

import (
	"log"
	"os"

	"github.com/google/go-attestation/attest"
)

func main() {
	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		log.Fatal("Unable to open TPM")
		os.Exit(1)
	}

	eks, err := tpm.EKs()
	if err != nil {
		log.Fatal("Unable to fetch EK")
		os.Exit(1)
	}
	ek := eks[0]

	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		log.Fatal("Unable to create AK")
		os.Exit(1)
	}

	attestParams := ak.AttestationParameters()

	akBytes, err := ak.Marshal()
	if err != nil {
		log.Fatal("Unable to perform AK Marshal")
		os.Exit(1)
	}

	if err := os.WriteFile("encrypted_ak.json", akBytes, 0600); err != nil {
		log.Fatal("Unable to write AK")
		os.Exit(1)
	}

	if err := os.WriteFile("ek.out", ek.Certificate.Raw, 0600); err != nil {
		log.Fatal("Unable to write EK")
		os.Exit(1)
	}

	if err := os.WriteFile("attest_params.out", attestParams.Public, 0600); err != nil {
		log.Fatal("Unable to write attest Params")
		os.Exit(1)
	}

}
