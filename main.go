package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/go-tpm/tpm2"
)

const (
	fileAKPubBlob     = "ak.pub.tpmt"
	fileAppKPubBlob   = "appk.pub.tpmt"
	fileAppKAttestSig = "appk.attestation.sig"
	fileAppKAttestDat = "appk.attestation.dat"
)

var (
	defaultEKTemplate = tpm2.Public{
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
	defaultSRKTemplate = tpm2.Public{
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
	defaultAKTemplate = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagRestricted |
			tpm2.FlagUserWithAuth |
			tpm2.FlagSign, // Key can be used to sign data
		ECCParameters: &tpm2.ECCParams{
			Sign:    &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256},
			CurveID: tpm2.CurveNISTP256,
			Point: tpm2.ECPoint{
				XRaw: make([]byte, 32),
				YRaw: make([]byte, 32),
			},
		},
	}
	// A key without the "restricted" flag can sign arbitrary data
	defaultAppKTemplate = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth |
			tpm2.FlagSign,
		ECCParameters: &tpm2.ECCParams{
			Sign:    &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256},
			CurveID: tpm2.CurveNISTP256,
			Point: tpm2.ECPoint{
				XRaw: make([]byte, 32),
				YRaw: make([]byte, 32),
			},
		},
	}
)

func clientTest() error {
	if err := createEK(); err != nil {
		return fmt.Errorf("error generating EK: %v", err)
	}
	if err := createSRK(); err != nil {
		return fmt.Errorf("error generating SRK: %v", err)
	}
	if err := createAK(); err != nil {
		return fmt.Errorf("error generating AK: %v", err)
	}
	if err := createAppK(); err != nil {
		return fmt.Errorf("error generating AppK: %v", err)
	}
	if err := signIID(); err != nil {
		return fmt.Errorf("error signing IID: %v", err)
	}
	return nil
}

func serverTest() error {
	akNameData, err := os.ReadFile("ak.name")
	if err != nil {
		return fmt.Errorf("unable to open ak.name: %v", err)
	}
	akPubBlob, err := os.ReadFile(fileAKPubBlob)
	if err != nil {
		return fmt.Errorf("unable to open "+fileAKPubBlob+": %v", err)
	}
	appkAttestDat, err := os.ReadFile(fileAppKAttestDat)
	if err != nil {
		return fmt.Errorf("unable to open "+fileAppKAttestDat+": %v", err)
	}
	appkAttestSig, err := os.ReadFile(fileAppKAttestSig)
	if err != nil {
		return fmt.Errorf("unable to open "+fileAppKAttestSig+": %v", err)
	}
	appkPubBlob, err := os.ReadFile(fileAppKPubBlob)
	if err != nil {
		return fmt.Errorf("unable to open "+fileAppKPubBlob+": %v", err)
	}
	if err := credentialActivation(akNameData, akPubBlob); err != nil {
		return fmt.Errorf("unable to perform credential activation: %v", err)
	}
	if err := servVerifyAppK(appkAttestDat, appkAttestSig, akPubBlob, appkPubBlob); err != nil {
		return fmt.Errorf("unable to verify AppK: %v", err)
	}
	if err := servVerifyIID(appkPubBlob); err != nil {
		return fmt.Errorf("unable to verify IID: %v", err)
	}
	return nil
}

func main() {
	/*
		if len(os.Args) < 2 {
			fmt.Println("This is the arguments version of this nonsense")
			return
		}

		attestation := os.Args[1]
		pub := os.Args[2]
		if attestation != "99" {
			attestation_verification_test(pub, attestation)
		} else {
			if err := clientTest(); err != nil {
				log.Fatalf("Failure during Client Test: %v", err)
			}
			if err := serverTest(); err != nil {
				log.Fatalf("Failure during Server Test: %v", err)
			}
		}
	*/
	if len(os.Args) == 2 && os.Args[1] == "clean" {
		cleanClient()
		return
	} else {
		if err := clientTest(); err != nil {
			cleanClient()
			log.Fatalf("Failure during Client Test: %v", err)
		}
		if err := serverTest(); err != nil {
			log.Fatalf("Failure during Server Test: %v", err)
		}
	}
}
