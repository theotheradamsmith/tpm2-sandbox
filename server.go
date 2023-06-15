package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"reflect"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"
	"github.com/google/go-tpm/tpmutil"
)

var secret = []byte("Aren't cats just the best?")

func credentialActivation(akNameData []byte, akPubBlob []byte) error {
	credBlob, encSecret, err := servChallenge(akNameData, akPubBlob)
	if err != nil {
		log.Println("CA failed to generate challenge")
		return err
	}
	response, err := cliActivateCredential(credBlob, encSecret)
	if err != nil {
		log.Printf("Failed to activate credential with %s", response)
		return err
	}

	if !reflect.DeepEqual(response, secret) {
		log.Printf("Credential activation failed! Do not trust this agent.")
	} else {
		log.Printf("EK and AK exist on the same TPM. This agent is trustworthy!")
	}

	return nil
}

func servChallenge(nameData []byte, pubBlob []byte) ([]byte, []byte, error) {
	/*
		The challenge asks the EK to verify another key name is also loaded into the TPM.
		Because key names are digests of the public key blob, the CA can verify public key
		attributes and reject any that don't match expectations.

		Included in the encrypted blob is a secret that the CA tracks with the challenge.
	*/

	// Verify digest matches the public blob that was provided
	name, err := tpm2.DecodeName(bytes.NewBuffer(nameData))
	if err != nil {
		log.Fatalf("unpacking name: %v", err)
	}
	if name.Digest == nil {
		log.Fatalf("name was not a digest")
	}
	h, err := name.Digest.Alg.Hash()
	if err != nil {
		log.Fatalf("failed to get name hash: %v", err)
	}
	pubHash := h.New()
	pubHash.Write(pubBlob)
	pubDigest := pubHash.Sum(nil)
	if !bytes.Equal(name.Digest.Value, pubDigest) {
		log.Fatalf("name was not for public blob")
	}

	// Inspect key attributes
	pub, err := tpm2.DecodePublic(pubBlob)
	if err != nil {
		log.Fatalf("decode public blob: %v", err)
	}
	fmt.Printf("Key attributes: 0x08%x\n", pub.Attributes)

	// Generate a challenge for the name.
	//
	// Note that some TPMs enforce a maximum secret size of 32 bytes
	ekPubDer, err := os.ReadFile("ek.pub")
	if err != nil {
		log.Println("Unable to read ek.pub")
		return nil, nil, err
	}
	ekPub, err := x509.ParsePKIXPublicKey(ekPubDer)
	if err != nil {
		log.Println("Unable to parse EK public key")
		return nil, nil, err
	}

	symBlockSize := 16
	credBlob, encSecret, err := credactivation.Generate(name.Digest, ekPub, symBlockSize, secret)
	if err != nil {
		log.Println("Unable to generate credential")
		return nil, nil, err
	}

	return credBlob, encSecret, nil
}

func servVerifyAppK(appkAttestDat []byte, appkAttestSig []byte, akPubBlob []byte, appkPubBlob []byte) error {
	// Instead of a challenge and response dance, the CA simply verifies the signature
	// using the AK's public key
	akTPMPub, err := tpm2.DecodePublic(akPubBlob)
	if err != nil {
		log.Println("FAILED TEST PUBLIC DECODE")
		return err
	}
	akPub, err := akTPMPub.Key()
	if err != nil {
		log.Println("Unable to retrieve AK public key")
	}
	akPubECDSA, ok := akPub.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("expected ecdsa public key, got: %T", akPub)
	}

	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(appkAttestSig))
	if err != nil {
		log.Println("Unable to decode appk.attestation.sig")
		return err
	}

	// Verify attested data is signed by the EK public key
	digest := sha256.Sum256(appkAttestDat)
	if !ecdsa.Verify(akPubECDSA, digest[:], sig.ECC.R, sig.ECC.S) {
		log.Fatalf("signature didn't match")
	} else {
		log.Println("WE HAVE A MATCH WHAT?!?!?!")
	}

	/*
		// Verify attested data is signed by the EK public key
		digest := sha256.Sum256(appkAttestDat)
		if !ecdsa.VerifyASN1(akPubECDSA, digest[:], appkAttestSig) {
			fmt.Println("VerifyASN1: signature didn't match")
		}
	*/

	// At this point the attestation data's signature is correct and can be used to
	// further verify the application key's public key blob. Unpack the blob to
	// inspect the attributes of the newly-created key

	// Verify the signed attestation was for this public blob
	a, err := tpm2.DecodeAttestationData(appkAttestDat)
	if err != nil {
		log.Fatalf("decode attestation: %v", err)
	}
	log.Printf("Contents of attest dat: %v\n", a)
	pubDigest := sha256.Sum256(appkPubBlob)
	if !bytes.Equal(a.AttestedCertifyInfo.Name.Digest.Value, pubDigest[:]) {
		log.Fatalf("attestation was not for public blob")
	}

	// Decode public key and inspect key attributes
	tpmPub, err := tpm2.DecodePublic(appkPubBlob)
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

func getAttestedCreationNameDigest(attestData []byte) (tpmutil.U16Bytes, error) {
	a, err := tpm2.DecodeAttestationData(attestData)
	if err != nil {
		return nil, err
	}

	return a.AttestedCreationInfo.Name.Digest.Value, nil
}

func attestation_verification_test(p string, a string) {
	pubBlob, err := os.ReadFile(p)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}
	fmt.Printf("Contents of pubBlob: %x\n", pubBlob)
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
	fmt.Printf("Key attributes: 0x%08x\n", tpmPub.Attributes)
	pem.Encode(os.Stdout, b)

	attestData, err := os.ReadFile(a)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}
	attestedNameDigest, err := getAttestedCreationNameDigest(attestData)
	if err != nil {
		fmt.Printf("Error parsing attestation: %v\n", err)
	}

	pubDigest := sha256.Sum256(pubBlob)
	if !bytes.Equal(attestedNameDigest, pubDigest[:]) {
		fmt.Printf("\n\nAttested Name: %v\n", attestedNameDigest)
		fmt.Printf("PubDigest Val: %v\n\n", pubDigest[:])
		log.Fatalf("attestation was not for public blob")
	} else {
		fmt.Println("Attestation was valid")
	}
}
