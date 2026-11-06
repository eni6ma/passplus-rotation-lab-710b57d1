package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFullE6ArchiveRawReadbackAboveContentsBase64Limit(t *testing.T) {
	c, key, a := fixture(t)
	data := bytes.Repeat([]byte{7}, maxEncryptedArchive)
	a.Files[1].Content = base64.StdEncoding.EncodeToString(data)
	a.Files[1].SHA256 = sum(data)
	a.PayloadDigest = sum(data)
	for i := 1; i < 5; i++ {
		a.Proofs[i].PayloadDigest = a.PayloadDigest
	}
	pairs := [][]string{}
	for _, f := range a.Files {
		pairs = append(pairs, []string{f.Path, f.SHA256})
	}
	encoded, _ := json.Marshal(pairs)
	a.FileSetDigest = sum(encoded)
	p := &provider{tip: a.PredecessorCommit, old: a.PredecessorCommit}
	server := httptest.NewServer(http.HandlerFunc(p.serve))
	defer server.Close()
	c.api = server.URL
	verified, err := authorize(c, envelope(t, a, key))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := publish(c, verified, "runtime-test-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.PayloadDigest != sum(data) || p.commits != 1 {
		t.Fatal("full archive was changed or published twice")
	}
}

func TestCanonicalEncryptedArchiveAndMetadataBounds(t *testing.T) {
	for _, file := range []struct{ index, limit int }{{0, 16384}, {1, 8*1024*1024 + 65536}, {2, 512}} {
		for _, extra := range []int{0, 1} {
			c, key, a := fixture(t)
			data := bytes.Repeat([]byte{7}, file.limit+extra)
			a.Files[file.index].Content = base64.StdEncoding.EncodeToString(data)
			a.Files[file.index].SHA256 = sum(data)
			a.PayloadDigest = a.Files[1].SHA256
			for i := 1; i < 5; i++ {
				a.Proofs[i].PayloadDigest = a.PayloadDigest
			}
			pairs := [][]string{}
			for _, item := range a.Files {
				pairs = append(pairs, []string{item.Path, item.SHA256})
			}
			encoded, _ := json.Marshal(pairs)
			a.FileSetDigest = sum(encoded)
			_, err := authorize(c, envelope(t, a, key))
			if (err != nil) != (extra == 1) {
				t.Fatalf("canonical bound mismatch for %s", a.Files[file.index].Path)
			}
		}
	}
}
