package jos_test

import (
	"strings"
	"testing"

	"josfox.cloud/jos"
)

func TestSealAndVerify(t *testing.T) {
	doc := map[string]any{
		"jos":  map[string]any{"version": "2.0.0", "kind": "atom"},
		"meta": map[string]any{"name": "hello-go", "version": "0.1.0"},
		"intention": map[string]any{
			"objective":        "Verify .jos sealing in Go",
			"success_criteria": []any{"integrity.hash matches"},
		},
	}
	sealed, art, err := jos.Seal(doc)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	if !strings.HasPrefix(art, "art_") || len(art) != 68 {
		t.Fatalf("unexpected artID: %s", art)
	}
	gotArt, err := jos.Verify(sealed)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if gotArt != art {
		t.Fatalf("artID mismatch: %s != %s", gotArt, art)
	}
	tampered := strings.Replace(string(sealed), "hello-go", "tampered", 1)
	if _, err := jos.Verify([]byte(tampered)); err == nil {
		t.Fatal("expected tamper error, got nil")
	}
}
