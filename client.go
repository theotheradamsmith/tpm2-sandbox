package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
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
		log.Println("saving context")
		return err
	}
	if err := os.WriteFile("ek.ctx", out, 0644); err != nil {
		log.Println("writing context")
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
		log.Fatalf("evict ak: %v", err)
	}

	// Save SRK context
	out, err := tpm2.ContextSave(f, srk)
	if err != nil {
		log.Println("saving context")
		return err
	}
	if err := os.WriteFile("srk.ctx", out, 0644); err != nil {
		log.Println("writing context")
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
		log.Fatalf("evict ak: %v", err)
	}

	akCtx, err := tpm2.ContextSave(f, ak)
	if err != nil {
		log.Println("Failed to save AK ctx")
		return err
	}
	if err := os.WriteFile("ak.ctx", akCtx, 0644); err != nil {
		log.Println("Failed to write AK ctx")
		return err
	}
	// Store the AK name, which is a hash of the public key blob
	if err := os.WriteFile("ak.name", nameData, 0644); err != nil {
		log.Println("Failed to write ak.name")
		return err
	}
	// Store the AK public key blob, which includes content such as the key attributes
	if err := os.WriteFile("ak.pub.tpmt", pubBlob, 0644); err != nil {
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
	pem.Encode(os.Stdout, b)

	return nil
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

	privBlob, pubBlob, _, hash, ticket, err := tpm2.CreateKey(f, srkHandle, tpm2.PCRSelection{}, "", "", defaultAppKTemplate)
	if err != nil {
		log.Fatalf("create appk: %v", err)
	}
	appk, _, err := tpm2.Load(f, srkHandle, "", pubBlob, privBlob)
	if err != nil {
		log.Fatalf("load app key: %v", err)
	}

	// Persist the Key
	if err := tpm2.EvictControl(f, "", tpm2.HandleOwner, appk, appkHandle); err != nil {
		log.Fatalf("evict ak: %v", err)
	}

	// Write key context to disk
	appkCtx, err := tpm2.ContextSave(f, appk)
	if err != nil {
		log.Fatalf("saving context: %v", err)
	}
	if err := os.WriteFile("appk.ctx", appkCtx, 0644); err != nil {
		log.Fatalf("writing context: %v", err)
	}

	// To certify the new key, call CertifyCreation, passing the AK as the signing object.
	// This returns an attestation and a signature
	akTPMPub, _, _, err := tpm2.ReadPublic(f, akHandle)
	if err != nil {
		log.Fatalf("read ak pub: %v", err)
	}
	sigParams := akTPMPub.ECCParameters.Sign
	akPub, err := akTPMPub.Key()
	if err != nil {
		log.Fatalf("getting ak public key: %v", err)
	}

	attestData, sigData, err := tpm2.CertifyCreation(f, "", appk, akHandle, nil, hash, *sigParams, ticket)
	if err != nil {
		log.Fatalf("certify creation: %v", err)
	}

	// Instead of a challenge and response dance, the CA simply verifies the signature
	// using the AK's public key
	akPubECDSA, ok := akPub.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("expected ecdsa public key, got: %T", akPub)
	}

	if len(sigData) != 64 {
		fmt.Printf("expected ecdsa signature len 64: got %d\n", len(sigData))
	}
	/*
		var r, s big.Int
		r.SetBytes(sigData[:len(sigData)/2])
		s.SetBytes(sigData[len(sigData)/2:])

		// Verify attested data is signed by the EK public key
		digest := sha256.Sum256(attestData)
		if !ecdsa.Verify(akPubECDSA, digest[:], &r, &s) {
			log.Fatalf("signature didn't match")
		}
	*/

	// Verify attested data is signed by the EK public key
	digest := sha256.Sum256(attestData)
	if !ecdsa.VerifyASN1(akPubECDSA, digest[:], sigData) {
		fmt.Println("VerifyASN1: signature didn't match")
	}

	// At this point the attestation data's signature is correct and can be used to
	// further verify the application key's public key blob. Unpack the blob to
	// inspect the attributes of the newly-created key

	// Verify the signed attestation was for this public blob
	a, err := tpm2.DecodeAttestationData(attestData)
	if err != nil {
		log.Fatalf("decode attestation: %v", err)
	}
	pubDigest := sha256.Sum256(pubBlob)
	if !bytes.Equal(a.AttestedCertifyInfo.Name.Digest.Value, pubDigest[:]) {
		log.Fatalf("attestation was not for public blob")
	}

	// Decode public key and inspect key attributes
	tpmPub, err := tpm2.DecodePublic(pubBlob)
	if err != nil {
		log.Fatalf("decode public blob: %v", err)
	}
	pub, err := tpmPub.Key()
	if err != nil {
		log.Fatalf("decode public key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatalf("encoding public key: %v", err)
	}
	b := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}
	fmt.Printf("Key attributres: 0x%08x\n", tpmPub.Attributes)
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
