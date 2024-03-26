package main

import (
	"os"
	"testing"
)

func getTempFile() string {
	return os.TempDir() + "/jskeys.json"
}

func TestLoadJetStreamEncryptionKeyFromTPM(t *testing.T) {
	testFile := getTempFile()
	defer os.Remove(testFile)
	type args struct {
		srkPassword   string
		jsKeydir      string
		jsKeyPassword string
		pcr           int
	}
	tests := []struct {
		name    string
		args    args
		clear   bool
		wantErr bool
	}{
		{"TestLoadJetStreamEncryptionKeyFromTPM-Load", args{"", testFile, "password", 22}, true, false},
		{"TestLoadJetStreamEncryptionKeyFromTPM-Read", args{"", testFile, "password", 22}, false, false},
		{"TestLoadJetStreamEncryptionKeyFromTPM-BadPass", args{"", testFile, "badpass", 22}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.clear {
				os.Remove(tt.args.jsKeydir)
			}
			_, err := LoadJetStreamEncryptionKeyFromTPM(tt.args.srkPassword, tt.args.jsKeydir, tt.args.jsKeyPassword, tt.args.pcr)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadJetStreamEncryptionKeyFromTPM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

// TestLoadJetStreamEncryptionKeyFromTPMBasic tests the basic functionality.
// The first pass will create the keys and generate the js encrpytion key.
// the second pass will read the keys from disk, decrypt with the TPM (unseal),
// and return the same key.
func TestLoadJetStreamEncryptionKeyFromTPMBasic(t *testing.T) {
	testFile := getTempFile()
	defer os.Remove(testFile)

	// Create the key file.
	key1, err := LoadJetStreamEncryptionKeyFromTPM("", testFile, "password", 22)
	if err != nil {
		t.Errorf("LoadJetStreamEncryptionKeyFromTPM() failed: %v", err)
	}

	// Now obtain the newly generated key from the file.
	key2, err := LoadJetStreamEncryptionKeyFromTPM("", testFile, "password", 22)
	if err != nil {
		t.Errorf("LoadJetStreamEncryptionKeyFromTPM() failed: %v", err)
	}
	if key1 != key2 {
		t.Errorf("Keys should match")
	}
}
