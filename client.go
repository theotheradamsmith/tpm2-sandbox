package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/google/go-tpm/tpm2"
)

const (
	// Defined in "Registry of reserved TPM 2.0 handles and localities", and checked on a glinux machine.
	srkHandle  = 0x81000001
	akHandle   = 0x81000002
	appkHandle = 0x81000003
)

func storePublicKey(prefix string, pub crypto.PublicKey) (*pem.Block, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Println("encoding public key")
		return nil, err
	}

	if err := os.WriteFile(prefix+".pub", pubDER, 0644); err != nil {
		log.Println("writing " + prefix + ".pub")
		return nil, err
	}

	b := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}

	if err := os.WriteFile(prefix+".pub.pem", pem.EncodeToMemory(b), 0644); err != nil {
		log.Println("writing " + prefix + ".pub.pem")
		return nil, err
	}

	return b, nil
}

func createEK() error {
	fmt.Println("Generating EK...")
	f, err := tpm2.OpenTPM(pathTPM)
	if err != nil {
		log.Fatalf("opening tpm: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatalf("closing tpm: %v", err)
		}
	}()

	ek, pub, err := tpm2.CreatePrimary(f, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", defaultEKTemplate)
	if err != nil {
		log.Println("creating EK")
		return err
	}

	// Save EK context
	out, err := tpm2.ContextSave(f, ek)
	if err != nil {
		log.Println("Failed to generate EK context")
		return err
	}
	if err := os.WriteFile("ek.ctx", out, 0644); err != nil {
		log.Println("Failed to save EK context")
		return err
	}

	// Store EK public key
	b, err := storePublicKey("ek", pub)
	if err != nil {
		log.Println("Unable to store EK public key")
		return err
	}

	return pem.Encode(os.Stdout, b)
}

func createSRK() error {
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

	srk, pub, err := tpm2.CreatePrimary(f, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", defaultSRKTemplate)
	if err != nil {
		log.Println("creating SRK")
		return err
	}

	// Persist the Key
	if err := tpm2.EvictControl(f, "", tpm2.HandleOwner, srk, srkHandle); err != nil {
		log.Println("Failed to make SRK persistent")
		return err
	}

	// Save SRK context
	out, err := tpm2.ContextSave(f, srk)
	if err != nil {
		log.Println("Failed to generate SRK context")
		return err
	}
	if err := os.WriteFile("srk.ctx", out, 0644); err != nil {
		log.Println("Failed to save SRK context")
		return err
	}

	// Store SRK public key
	b, err := storePublicKey("srk", pub)
	if err != nil {
		log.Println("Unable to store SRK public key")
		return err
	}

	return pem.Encode(os.Stdout, b)
}

func createAK() error {
	fmt.Println("Generating AK...")
	f, err := tpm2.OpenTPM(pathTPM)
	if err != nil {
		log.Fatalf("opening tpm: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatalf("closing tpm: %v", err)
		}
	}()

	privBlob, pubBlob, _, _, _, err := tpm2.CreateKey(f, srkHandle, tpm2.PCRSelection{}, "", "", defaultAKTemplate)
	if err != nil {
		log.Println("Failed to create AK")
		return err
	}
	ak, nameData, err := tpm2.Load(f, srkHandle, "", pubBlob, privBlob)
	if err != nil {
		log.Println("Failed to load AK")
		return err
	}

	// Persist the Key
	if err := tpm2.EvictControl(f, "", tpm2.HandleOwner, ak, akHandle); err != nil {
		log.Println("Failed to make AK persistent")
		return err
	}

	// Store AK context
	akCtx, err := tpm2.ContextSave(f, ak)
	if err != nil {
		log.Println("Failed to generate AK ctx")
		return err
	}
	if err := os.WriteFile("ak.ctx", akCtx, 0644); err != nil {
		log.Println("Failed to save AK ctx")
		return err
	}

	// Store the AK name, which is a hash of the public key blob
	if err := os.WriteFile("ak.name", nameData, 0644); err != nil {
		log.Println("Failed to write ak.name")
		return err
	}

	// Store the AK public key blob, which includes content such as the key attributes
	if err := os.WriteFile(fileAKPubBlob, pubBlob, 0644); err != nil {
		log.Println("Failed to write ak.pub.tpmt")
		return err
	}

	// Store AK public key
	akTPMPub, _, _, err := tpm2.ReadPublic(f, ak)
	if err != nil {
		log.Fatalf("read ak public: %v", err)
	}
	akPub, err := akTPMPub.Key()
	if err != nil {
		log.Fatalf("decode ak public key: %v", err)
	}
	b, err := storePublicKey("ak", akPub)
	if err != nil {
		log.Fatalf("Unable to store AK public key")
	}
	return pem.Encode(os.Stdout, b)
}

func createAppK() error {
	fmt.Println("Generating Application Key...")
	f, err := tpm2.OpenTPM(pathTPM)
	if err != nil {
		log.Fatalf("opening tpm: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatalf("closing tpm: %v", err)
		}
	}()

	// Create and load AppK
	privBlob, pubBlob, _, hash, ticket, err := tpm2.CreateKey(f, srkHandle, tpm2.PCRSelection{}, "", "", defaultAppKTemplate)
	if err != nil {
		log.Println("Failed to create AppK")
		return err
	}
	appk, nameData, err := tpm2.Load(f, srkHandle, "", pubBlob, privBlob)
	if err != nil {
		log.Println("Failed to load AppK")
		return err
	}

	// Persist AppK
	if err := tpm2.EvictControl(f, "", tpm2.HandleOwner, appk, appkHandle); err != nil {
		log.Println("Failed to make AppK persistent")
		return err
	}

	// Store AppK context
	appkCtx, err := tpm2.ContextSave(f, appk)
	if err != nil {
		log.Fatalf("Failed to generate AppK context: %v", err)
	}
	if err := os.WriteFile("appk.ctx", appkCtx, 0644); err != nil {
		log.Fatalf("Failed to save AppK context: %v", err)
	}

	// Store the AppK name, which is a hash of the public key blob
	if err := os.WriteFile("appk.name", nameData, 0644); err != nil {
		log.Println("Failed to write appk.name")
		return err
	}

	// Store the AppK public key blob, which includes content such as the key attributes
	if err := os.WriteFile(fileAppKPubBlob, pubBlob, 0644); err != nil {
		log.Println("Failed to write appk.pub.tpmt")
		return err
	}

	// To certify the new key, call CertifyCreation, passing the AK as the signing object.
	// This returns an attestation and a signature
	akTPMPub, _, _, err := tpm2.ReadPublic(f, akHandle)
	if err != nil {
		log.Println("Failed to read AK pub")
		return err
	}
	sigParams := akTPMPub.ECCParameters.Sign
	attestData, sigData, err := tpm2.CertifyCreation(f, "", appk, akHandle, nil, hash, *sigParams, ticket)
	if err != nil {
		log.Println("Failed to certify AppK creation")
		return err
	}

	// Write attestation and signature to disk
	if err := os.WriteFile("appk.attestation", attestData, 0644); err != nil {
		log.Println("Failed to write appk.attestation")
		return err
	}
	if err := os.WriteFile("appk.attestation.sig", sigData, 0644); err != nil {
		log.Println("Failed to write appk.attestation.sig")
		return err
	}

	// Store appk.pub and PEM and print PEM to stdout
	appkTPMPub, err := tpm2.DecodePublic(pubBlob)
	if err != nil {
		log.Println("Failed to decode AppK blob")
		return err
	}
	appkPub, err := appkTPMPub.Key()
	if err != nil {
		log.Println("Failed to get AppK public key")
		return err
	}
	b, err := storePublicKey("appk", appkPub)
	if err != nil {
		log.Println("Unable to store AppK public key")
		return err
	}
	return pem.Encode(os.Stdout, b)
}

func cleanClient() {
	// Cleaning persistent handles
	f, err := tpm2.OpenTPM(pathTPM)
	if err != nil {
		log.Fatalf("opening tpm: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatalf("closing tpm: %v", err)
		}
	}()

	if err := tpm2.EvictControl(f, "", tpm2.HandleOwner, appkHandle, appkHandle); err != nil {
		log.Printf("Unable to evict AppK: %v", err)
	}
	if err := tpm2.EvictControl(f, "", tpm2.HandleOwner, akHandle, akHandle); err != nil {
		log.Printf("Unable to evict AK: %v", err)
	}
	if err := tpm2.EvictControl(f, "", tpm2.HandleOwner, srkHandle, srkHandle); err != nil {
		log.Printf("Unable to evict SRK: %v", err)
	}
}

/*
	ekTPMPub, _, _, err := tpm2.ReadPublic(f, ek)
	if err != nil {
		log.Fatalf("read ek public: %v", err)
	}
	ekPub, err := ekTPMPub.Key()
	if err != nil {
		log.Fatalf("decode ek public key: %v", err)
	}
*/
/*
	akTPMPub, err := tpm2.DecodePublic(pubBlob)
	if err != nil {
		log.Println("FAILED TEST PUBLIC DECODE")
		return err
	}
*/
