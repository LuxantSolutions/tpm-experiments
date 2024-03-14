package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	tpm2l "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/nats-io/nkeys"
)

// How this works:
// Create a Storage Root Key (SRK) in the TPM.
// If existing JS Encrpytion keys do not exist on disk.
// 	  - Create a JetStream encryption key (js key) and seal it to the SRK
//      using a provided js encryption key password.
// 	  - Save the public and private blobs to disk.
//    - Return the new js key (it's just a private portion of the nkey)
// Otherwise (keys exist on disk)
//    - Read the public and private blobs from disk
//    - Load them into the TPM
//    - Unseal the js key using the TPM, and the provided js encryption keys password.
//
// Notes: an owner passwords for the SRK is supported, but not tested here.

// TODO:
// Add HMAC (or something) to the TPM session to make it more secure.
// Add ECC support for the SRK key.
// Combine and save the SRK and js key blobs to NVM to retain them in the TPM???

// Gets/Regenerates the Storage Root Key (SRK) from the TPM. Caller MUST flush this handle when done.
func regenerateSRK(rwc io.ReadWriteCloser, srkPassword string) (tpmutil.Handle, error) {
	// Default EK template defined in:
	// https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
	// Shared SRK template based off of EK template and specified in:
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	srkTemplate := tpm2l.Public{
		Type:       tpm2l.AlgRSA,
		NameAlg:    tpm2l.AlgSHA256,
		Attributes: tpm2l.FlagFixedTPM | tpm2l.FlagFixedParent | tpm2l.FlagSensitiveDataOrigin | tpm2l.FlagUserWithAuth | tpm2l.FlagRestricted | tpm2l.FlagDecrypt | tpm2l.FlagNoDA,
		AuthPolicy: nil,
		RSAParameters: &tpm2l.RSAParams{ // TODO ECC
			Symmetric: &tpm2l.SymScheme{
				Alg:     tpm2l.AlgAES,
				KeyBits: 128,
				Mode:    tpm2l.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}

	// Create the parent key against which to seal the data
	srkHandle, _, err := tpm2l.CreatePrimary(rwc, tpm2l.HandleOwner, tpm2l.PCRSelection{}, "", srkPassword, srkTemplate)
	return srkHandle, err
}

// Writes they private and public blobs to disk. If the directory does not exist, it will be created.
// If the files already exist, they will be overwritten.
// TODO:  Write these to NVM to retain entirely in the TPM?
func writeKeyFiles(keyDir string, privateBlob []byte, publicBlob []byte) error {
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return fmt.Errorf("unable to create directory %q: %v", keyDir, err)
	}

	privateFile := filepath.Join(keyDir, "js_tpm_priv.key")
	if err := os.WriteFile(privateFile, privateBlob, 0600); err != nil {
		return fmt.Errorf("unable to write private blob to %q: %v", privateFile, err)
	}

	publicFile := filepath.Join(keyDir, "js_tpm_pub.key")
	if err := os.WriteFile(publicFile, publicBlob, 0644); err != nil {
		return fmt.Errorf("unable to write public blob to %q: %v", publicFile, err)
	}
	return nil
}

// Reads the key files from disk. If the path or either file is missing,
// os.ErrNotExist is returned.
func readKeyFiles(keyDir string) ([]byte, []byte, error) {
	if _, err := os.Stat(keyDir); err != nil {
		return nil, nil, err
	}
	publicFile := filepath.Join(keyDir, "js_tpm_pub.key")
	publicBlob, err := os.ReadFile(publicFile)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read public blob from %q: %v", publicFile, err)
	}
	privateFile := filepath.Join(keyDir, "js_tpm_priv.key")
	privateBlob, err := os.ReadFile(privateFile)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read public blob from %q: %v", publicFile, err)
	}
	return publicBlob, privateBlob, nil
}

func createAndSealJsEncryptionKey(rwc io.ReadWriteCloser, srkHandle tpmutil.Handle, srkPassword, jsKeyDir, jsKeyPassword string, pcr int) (string, error) {
	// Get the authorization policy that will protect the data to be sealed
	sessHandle, policy, err := policyPCRPasswordSession(rwc, pcr, jsKeyPassword)
	if err != nil {
		return "", fmt.Errorf("unable to get policy: %v", err)
	}
	if err := tpm2l.FlushContext(rwc, sessHandle); err != nil {
		return "", fmt.Errorf("unable to flush session: %v", err)
	}

	// Seal the data to the parent key and the policy
	user, err := nkeys.CreateUser()
	if err != nil {
		return "", fmt.Errorf("unable to create seed: %v", err)
	}
	jsStoreKey, err := user.Seed()
	if err != nil {
		return "", fmt.Errorf("unable to get seed: %v", err)
	}
	privateArea, publicArea, err := tpm2l.Seal(rwc, srkHandle, srkPassword, jsKeyPassword, policy, jsStoreKey)
	if err != nil {
		return "", fmt.Errorf("unable to seal data: %v", err)
	}
	err = writeKeyFiles(jsKeyDir, privateArea, publicArea)
	if err != nil {
		return "", fmt.Errorf("unable to write key files: %v", err)
	}
	return string(jsStoreKey), nil
}

// Returns the unsealed data
func unsealJsEncrpytionKey(rwc io.ReadWriteCloser, pcr int, srkHandle tpmutil.Handle, srkPassword, objectPassword string, publicBlob, privateBlob []byte) (string, error) {
	// Load the public/private blobs into the TPM for decryption.
	objectHandle, _, err := tpm2l.Load(rwc, srkHandle, srkPassword, publicBlob, privateBlob)
	if err != nil {
		return "", fmt.Errorf("unable to load data: %v", err)
	}
	defer func() {
		tpm2l.FlushContext(rwc, objectHandle)
	}()
	// Create the authorization session with TPM.
	sessHandle, _, err := policyPCRPasswordSession(rwc, pcr, objectPassword)
	if err != nil {
		return "", fmt.Errorf("unable to get auth session: %v", err)
	}
	defer func() {
		tpm2l.FlushContext(rwc, sessHandle)
	}()

	// Unseal the data we've loaded into the TPM with the object (js key) password.
	unsealedData, err := tpm2l.UnsealWithSession(rwc, sessHandle, objectHandle, objectPassword)
	if err != nil {
		return "", fmt.Errorf("unable to unseal data: %v", err)
	}
	return string(unsealedData), nil
}

// Returns session handle and policy digest.
// TODO - this is not a secure session - need to add HMAC or something.
func policyPCRPasswordSession(rwc io.ReadWriteCloser, pcr int, password string) (sessHandle tpmutil.Handle, policy []byte, retErr error) {
	sessHandle, _, err := tpm2l.StartAuthSession(
		rwc,
		tpm2l.HandleNull, /*tpmKey*/
		tpm2l.HandleNull, /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2l.SessionPolicy,
		tpm2l.AlgNull,
		tpm2l.AlgSHA256)
	if err != nil {
		return tpm2l.HandleNull, nil, fmt.Errorf("unable to start session: %v", err)
	}
	defer func() {
		if sessHandle != tpm2l.HandleNull && err != nil {
			if err := tpm2l.FlushContext(rwc, sessHandle); err != nil {
				retErr = fmt.Errorf("%v\nunable to flush session: %v", retErr, err)
			}
		}
	}()

	pcrSelection := tpm2l.PCRSelection{
		Hash: tpm2l.AlgSHA256,
		PCRs: []int{pcr},
	}

	// An empty expected digest means that digest verification is skipped.
	if err := tpm2l.PolicyPCR(rwc, sessHandle, nil /*expectedDigest*/, pcrSelection); err != nil {
		return sessHandle, nil, fmt.Errorf("unable to bind PCRs to auth policy: %v", err)
	}

	if err := tpm2l.PolicyPassword(rwc, sessHandle); err != nil {
		return sessHandle, nil, fmt.Errorf("unable to require password for auth policy: %v", err)
	}

	policy, err = tpm2l.PolicyGetDigest(rwc, sessHandle)
	if err != nil {
		return sessHandle, nil, fmt.Errorf("unable to get policy digest: %v", err)
	}
	return sessHandle, policy, nil
}

// LoadJetStreamEncryptionKeyFromTPM loads the JetStream encryption key from the TPM.
// If the key does not exist, it will be created and sealed. Public and private blobs
// used to decrypt the key in future sessions will be saved to disk in the jsKeyDir.
// The key will be unsealed and returned only with the correct password and PCR value.
func LoadJetStreamEncryptionKeyFromTPM(srkPassword, jsKeydir, jsKeyPassword string, pcr int) (string, error) {
	var err error
	rwc, err := tpm2l.OpenTPM()
	if err != nil {
		return "", fmt.Errorf("could not open the TPM: %v", err)
	}
	defer rwc.Close()

	// Load the key from the TPM
	srkHandle, err := regenerateSRK(rwc, srkPassword)
	defer func() {
		tpm2l.FlushContext(rwc, srkHandle)
	}()

	if err != nil {
		return "", fmt.Errorf("unable to regenerate SRK from the TPM: %v", err)
	}

	// Read the key files from disk. If they don't exist it means we need to create
	// a new js encrytpion key.
	publicBlob, privateBlob, err := readKeyFiles(jsKeydir)
	if err != nil {
		if os.IsNotExist(err) {
			jsek, err := createAndSealJsEncryptionKey(rwc, srkHandle, srkPassword, jsKeydir, jsKeyPassword, pcr)
			if err != nil {
				return "", fmt.Errorf("unable to generate new key from the TPM: %v", err)
			}
			// we've created and sealed the JS Encryption key, now we just return it.
			return jsek, nil
		}
		return "", fmt.Errorf("unable to load key from TPM: %v", err)
	}

	// Unseal the data
	jsek, err := unsealJsEncrpytionKey(rwc, pcr, srkHandle, srkPassword, jsKeyPassword, publicBlob, privateBlob)
	if err != nil {
		return "", fmt.Errorf("unable to unseal key from the TPM: %v", err)
	}
	return jsek, nil
}
