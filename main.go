package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"
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

func generateAK() {
	// First, generate AK
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

	srkCtx, err := ioutil.ReadFile("srk.ctx")
	if err != nil {
		log.Fatalf("read srk: %v", err)
	}
	srk, err := tpm2.ContextLoad(f, srkCtx)
	if err != nil {
		log.Fatalf("load srk: %v", err)
	}

	ekCtx, err := ioutil.ReadFile("ek.ctx")
	if err != nil {
		log.Fatalf("read ek: %v", err)
	}
	ek, err := tpm2.ContextLoad(f, ekCtx)
	if err != nil {
		log.Fatalf("load ek: %v", err)
	}

	tmpl := tpm2.Public{
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

	// After creating the AK, we'll need to pass a few values back to the CA:
	//   1) The EK public key to encrypt the challenge to
	//   2) The AK public key blob, which includes content such as the key attributes
	//   3) The AK name, which is a hash of the public key blob

	privBlob, pubBlob, _, _, _, err := tpm2.CreateKey(f, srk, tpm2.PCRSelection{}, "", "", tmpl)
	if err != nil {
		log.Fatalf("create ak: %v", err)
	}
	ak, nameData, err := tpm2.Load(f, srk, "", pubBlob, privBlob)
	if err != nil {
		log.Fatalf("load ak: %v", err)
	}

	akCtx, err := tpm2.ContextSave(f, ak)
	if err != nil {
		log.Fatalf("saving ak ctx: %v", err)
	}
	if err := ioutil.WriteFile("ak.ctx", akCtx, 0644); err != nil {
		log.Fatalf("writing ak ctx: %v", err)
	}

	ekTPMPub, _, _, err := tpm2.ReadPublic(f, ek)
	if err != nil {
		log.Fatalf("read ek public: %v", err)
	}
	ekPub, err := ekTPMPub.Key()
	if err != nil {
		log.Fatalf("decode ek public key: %v", err)
	}

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
	secret := []byte("Brevity is the soul of wit")
	symBlockSize := 16
	credBlob, encSecret, err := credactivation.Generate(name.Digest, ekPub, symBlockSize, secret)
	if err != nil {
		log.Fatalf("generate credential: %v", err)
	}

	/*
		The EK passes the challenge by returning the decrypted secret to the CA.
		During this process, it verifies the named credential is bound to the same
		TPM. Because our EK uses an authPolicy, we have to configure a session and
		authenticate in order to use it. In this case the policy is generated by
		TPM2_PolicySecret(TPM_RH_ENDORSEMENT), so we execute the same command
		to match the digest
	*/

	session, _, err := tpm2.StartAuthSession(f,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		log.Fatalf("creating auth session: %v", err)
	}

	auth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	if _, _, err := tpm2.PolicySecret(f, tpm2.HandleEndorsement, auth, session, nil, nil, nil, 0); err != nil {
		log.Fatalf("policy secret failed: %v", err)
	}

	auths := []tpm2.AuthCommand{auth, {Session: session, Attributes: tpm2.AttrContinueSession}}
	out, err := tpm2.ActivateCredentialUsingAuth(f, auths, ak, ek, credBlob[2:], encSecret[2:])
	if err != nil {
		log.Fatalf("activate credential: %v", err)
	}
	fmt.Printf("%s\n", out)
}

func generateAppK() {
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

	srkCtx, err := ioutil.ReadFile("srk.ctx")
	if err != nil {
		log.Fatalf("read srk: %v", err)
	}
	srk, err := tpm2.ContextLoad(f, srkCtx)
	if err != nil {
		log.Fatalf("load srk: %v", err)
	}

	akCtx, err := ioutil.ReadFile("ak.ctx")
	if err != nil {
		log.Fatalf("read ak: %v", err)
	}
	ak, err := tpm2.ContextLoad(f, akCtx)
	if err != nil {
		log.Fatalf("load ak: %v", err)
	}

	// This time, generate a key without the "restricted" flag, letting it sign arbitrary data
	tmpl := tpm2.Public{
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

	privBlob, pubBlob, _, hash, ticket, err := tpm2.CreateKey(f, srk, tpm2.PCRSelection{}, "", "", tmpl)
	if err != nil {
		log.Fatalf("create appk: %v", err)
	}
	appKey, _, err := tpm2.Load(f, srk, "", pubBlob, privBlob)
	if err != nil {
		log.Fatalf("load app key: %v", err)
	}

	// Write key context to disk
	appKeyCtx, err := tpm2.ContextSave(f, appKey)
	if err != nil {
		log.Fatalf("saving context: %v", err)
	}
	if err := ioutil.WriteFile("app.ctx", appKeyCtx, 0644); err != nil {
		log.Fatalf("writing context: %v", err)
	}

	// To certify the new key, call CertifyCreation, passing the AK as the signing object.
	// This returns an attestation and a signature
	akTPMPub, _, _, err := tpm2.ReadPublic(f, ak)
	if err != nil {
		log.Fatalf("read ak pub: %v", err)
	}
	sigParams := akTPMPub.ECCParameters.Sign
	akPub, err := akTPMPub.Key()
	if err != nil {
		log.Fatalf("getting ak public key: %v", err)
	}

	attestData, sigData, err := tpm2.CertifyCreation(f, "", appKey, ak, nil, hash, *sigParams, ticket)
	if err != nil {
		log.Fatalf("certify creation: %v", err)
	}

	// Instead of a challenge and response dance, the CA simply verifies the signature
	// using the AK's public key
	akECDSAPub, ok := akPub.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("expected ecdsa public key, got: %T", akPub)
	}
	if len(sigData) != 64 {
		log.Fatalf("expected ecdsa signature")
	}
	var r, s big.Int
	r.SetBytes(sigData[:len(sigData)/2])
	s.SetBytes(sigData[len(sigData)/2:])

	// Verify attested data is signed by the EK public key
	digest := sha256.Sum256(attestData)
	if !ecdsa.Verify(akECDSAPub, digest[:], &r, &s) {
		log.Fatalf("signature didn't match")
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
	pem.Encode(os.Stdout, b)
}

func main() {
	ret := 0
	//ret = attestationExample()
	//ret = randExample()
	//generateEK()
	//generateSRK()
	//generateAK()
	generateAppK()
	os.Exit(ret)
}
