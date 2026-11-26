// Package jos implements the official Go SDK and reference primitives for .jos
// (JSON Operating System): RFC 8785 JCS canonicalization, SHA-256 content-addressed
// sealing (art_<hex>), structural 2.0 validation, and hash-chained ledger verification.
package jos

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Version is the semantic version of the josfox.cloud/jos Go SDK.
const Version = "0.1.0"

var validKinds = map[string]bool{
	"atom": true, "flow": true, "service": true, "persona": true,
	"template": true, "crystal": true, "directory": true, "engine": true,
}

// CanonicalizeJCS serializes an arbitrary JSON-compatible value according to RFC 8785 (JCS).
func CanonicalizeJCS(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeJCS(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeJCS(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		f, err := x.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return errors.New("jos: non-finite number in JCS")
		}
		if f == 0 {
			buf.WriteString("0")
			return nil
		}
		buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return errors.New("jos: non-finite float in JCS")
		}
		if x == 0 {
			buf.WriteString("0")
			return nil
		}
		buf.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
	case int:
		buf.WriteString(strconv.Itoa(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case string:
		b, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, elem := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJCS(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeJCS(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		raw, err := json.Marshal(x)
		if err != nil {
			return err
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var generic any
		if err := dec.Decode(&generic); err != nil {
			return err
		}
		return writeJCS(buf, generic)
	}
	return nil
}

// ComputeIntegrityHash computes the canonical .jos 2.0 SHA-256 digest ("sha256:<hex>") and artifact ID ("art_<hex>").
func ComputeIntegrityHash(doc map[string]any) (hash string, artID string, err error) {
	clone := make(map[string]any, len(doc)+1)
	for k, v := range doc {
		clone[k] = v
	}
	integ := map[string]any{"hash": "", "signature": ""}
	if orig, ok := doc["integrity"].(map[string]any); ok {
		for k, v := range orig {
			integ[k] = v
		}
		integ["hash"] = ""
		integ["signature"] = ""
	}
	clone["integrity"] = integ
	canon, err := CanonicalizeJCS(clone)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(canon)
	hexStr := hex.EncodeToString(sum[:])
	return "sha256:" + hexStr, "art_" + hexStr, nil
}

// Seal sets integrity.hash on a .jos document in-place and returns the sealed JSON bytes and artifact ID.
func Seal(doc map[string]any) ([]byte, string, error) {
	h, art, err := ComputeIntegrityHash(doc)
	if err != nil {
		return nil, "", err
	}
	integ, ok := doc["integrity"].(map[string]any)
	if !ok {
		integ = map[string]any{}
	}
	integ["hash"] = h
	doc["integrity"] = integ
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, "", err
	}
	return append(out, '\n'), art, nil
}

// Verify checks structural .jos 2.0 validity and verifies integrity.hash if declared.
func Verify(raw []byte) (artID string, err error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return "", fmt.Errorf("jos: invalid JSON: %w", err)
	}
	hdr, ok := doc["jos"].(map[string]any)
	if !ok {
		return "", errors.New("jos: missing jos header")
	}
	ver, _ := hdr["version"].(string)
	if strings.Count(ver, ".") != 2 {
		return "", fmt.Errorf("jos: invalid jos.version %q", ver)
	}
	if kind, ok := hdr["kind"].(string); ok && kind != "" && !validKinds[kind] {
		return "", fmt.Errorf("jos: unknown jos.kind %q", kind)
	}
	meta, ok := doc["meta"].(map[string]any)
	if !ok {
		return "", errors.New("jos: missing meta object")
	}
	if name, _ := meta["name"].(string); strings.TrimSpace(name) == "" {
		return "", errors.New("jos: missing meta.name")
	}
	expectedHash, art, err := ComputeIntegrityHash(doc)
	if err != nil {
		return "", err
	}
	if integ, ok := doc["integrity"].(map[string]any); ok {
		if declared, _ := integ["hash"].(string); declared != "" && declared != expectedHash {
			return "", fmt.Errorf("jos: integrity mismatch: declared %s != computed %s", declared, expectedHash)
		}
	}
	return art, nil
}
