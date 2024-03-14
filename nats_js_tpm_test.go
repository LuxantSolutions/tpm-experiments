package main

import (
	"os"
	"testing"
)

func TestLoadJetStreamEncryptionKeyFromTPM(t *testing.T) {
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
		{"TestLoadJetStreamEncryptionKeyFromTPM-Load", args{"", "/tmp/jskeys", "password", 22}, true, false},
		{"TestLoadJetStreamEncryptionKeyFromTPM-Read", args{"", "/tmp/jskeys", "password", 22}, false, false},
		{"TestLoadJetStreamEncryptionKeyFromTPM-BadPass", args{"", "/tmp/jskeys", "badpass", 22}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.clear {
				os.RemoveAll(tt.args.jsKeydir)
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
	os.RemoveAll("/tmp/jskeys")
	key, err := LoadJetStreamEncryptionKeyFromTPM("", "/tmp/jskeys", "password", 22)
	if err != nil {
		t.Errorf("LoadJetStreamEncryptionKeyFromTPM() failed: %v", err)
	}

	key2, err := LoadJetStreamEncryptionKeyFromTPM("", "/tmp/jskeys", "password", 22)
	if err != nil {
		t.Errorf("LoadJetStreamEncryptionKeyFromTPM() failed: %v", err)
	}
	if key != key2 {
		t.Errorf("Keys should match")
	}
}
