package main

import (
	"flag"
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

func serverTest(checkCA bool) error {
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
	if err := credentialActivation(akNameData, akPubBlob, checkCA); err != nil {
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

func fullTest() error {
	fmt.Println("Performing client functions...")
	if err := clientTest(); err != nil {
		cleanClient()
		return fmt.Errorf("failure during client test: %v", err)
	}
	fmt.Println("Performing server/verification functions...")
	if err := serverTest(false); err != nil {
		return fmt.Errorf("failure during server test: %v", err)
	}
	return nil
}

func main() {
	attestCmd := flag.NewFlagSet("attest", flag.ExitOnError)
	attestAttest := attestCmd.String("attest", "", "the attestation file")
	attestPubBlob := attestCmd.String("pub", "", "the public key blob")

	clientCmd := flag.NewFlagSet("client", flag.ExitOnError)
	clientRunTest := clientCmd.Bool("test", false, "perform full client test")
	clientRunClean := clientCmd.Bool("clean", false, "evict persistent handles")

	serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
	serverRunTest := serverCmd.Bool("test", false, "perform full server test")
	serverCheckCA := serverCmd.Bool("ca", false, "use the EK cert and perform a CA check")

	if len(os.Args) < 2 {
		fmt.Println("Executing full test procedure")
		if err := fullTest(); err != nil {
			log.Fatalf("full test failure: %v", err)
		}
		os.Exit(1)
	}

	switch os.Args[1] {
	case "attest":
		attestCmd.Parse(os.Args[2:])
	case "client":
		clientCmd.Parse(os.Args[2:])
	case "server":
		serverCmd.Parse(os.Args[2:])
	default:
		fmt.Println("expected 'attest', 'client', or 'server' subcommands")
		os.Exit(1)
	}

	if attestCmd.Parsed() {
		if *attestAttest == "" || *attestPubBlob == "" {
			log.Fatalf("attestation verification test requires 'attest' and 'pub'")
		}

		if err := attestation_verification_test(*attestPubBlob, *attestAttest); err != nil {
			log.Fatalf("failure during attestation verification test: %v", err)
		}
		os.Exit(1)
	}

	if clientCmd.Parsed() {
		if *clientRunTest {
			fmt.Println("running client tests...")
			if err := clientTest(); err != nil {
				cleanClient()
				log.Fatalf("failure during client test: %v", err)
			}
		}
		if *clientRunClean {
			fmt.Println("cleaning client...")
			cleanClient()
		}
		os.Exit(1)
	}

	if serverCmd.Parsed() {
		if *serverRunTest {
			fmt.Println("running server/verification tests")
			if err := serverTest(*serverCheckCA); err != nil {
				log.Fatalf("filure during server test: %v", err)
			}
		}
		os.Exit(1)
	}
}
