package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
)

const pathTPM string = "/dev/tpmrm0"

func attestationExample() int {
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

func randExample() int {
	f, err := os.OpenFile(pathTPM, os.O_RDWR, 0)
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

func generateEK() {
	fmt.Println("Generating EK...")
	f, err := os.OpenFile(pathTPM, os.O_RDWR, 0)
	if err != nil {
		log.Fatalf("opening tpm: %v", err)
	}
	defer f.Close()

	tmpl := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | // Key can't leave the TPM
			tpm2.FlagFixedParent | // Key can't change parent
			tpm2.FlagSensitiveDataOrigin | // Key created by the TPM (not imported)
			tpm2.FlagAdminWithPolicy | // Key has an authPolicy
			tpm2.FlagRestricted | // Key used for TPM challenges, not general decryption
			tpm2.FlagDecrypt, // Key can be used to decrypt data
		AuthPolicy: []byte{
			// TPM2_PolicySecret(TPM_RH_ENDORSEMENT)
			// Endorsement hierarchy must be unlocked to use this key
			// AuthPolicy is a hash that represents a sequence of authorizations
			0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
			0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
			0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
			0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
			0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
			0x69, 0xAA,
		},
		RSAParameters: &tpm2.RSAParams{
			Symmetric:  &tpm2.SymScheme{Alg: tpm2.AlgAES, KeyBits: 128, Mode: tpm2.AlgCFB},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}

	ek, pub, err := tpm2.CreatePrimary(f, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", tmpl)
	if err != nil {
		log.Fatalf("creating ek: %v", err)
	}

	out, err := tpm2.ContextSave(f, ek)
	if err != nil {
		log.Fatalf("saving context: %v", err)
	}
	if err := ioutil.WriteFile("ek.ctx", out, 0644); err != nil {
		log.Fatalf("writing context: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatalf("encoding public key: %v", err)
	}
	b := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}
	pem.Encode(os.Stdout, b)
}

func generateSRK() {
	fmt.Println("Generating SRK...")
	f, err := tpm2.OpenTPM(pathTPM)
	if err != nil {
		log.Fatalf("opening tpm: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatalf("closing tpm: %v", err)
		}
	}()

	tmpl := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | // Uses (empty) password
			tpm2.FlagNoDA | // This flag doesn't do anything, but it's in the spec
			tpm2.FlagRestricted |
			tpm2.FlagDecrypt,
		RSAParameters: &tpm2.RSAParams{
			Symmetric:  &tpm2.SymScheme{Alg: tpm2.AlgAES, KeyBits: 128, Mode: tpm2.AlgCFB},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}

	srk, _, err := tpm2.CreatePrimary(f, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", tmpl)
	if err != nil {
		log.Fatalf("creating srk: %v", err)
	}
	out, err := tpm2.ContextSave(f, srk)
	if err != nil {
		log.Fatalf("saving context: %v", err)
	}
	if err := ioutil.WriteFile("srk.ctx", out, 0644); err != nil {
		log.Fatalf("writing context: %v", err)
	}
}

func main() {
	ret := 0
	//ret = attestationExample()
	//ret = randExample()
	generateEK()
	generateSRK()
	os.Exit(ret)
}
