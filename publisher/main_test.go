package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func identifier(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012x", n) }
func fixture(t *testing.T) (config, ed25519.PrivateKey, Authorization) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := config{repository: "eni6ma/passplus-rotation-lab-tests", repositoryID: 123, publicKey: public, api: "https://api.github.com", now: func() time.Time { return time.Unix(2000000000, 0) }}
	a := Authorization{Schema: "passplus.rotation-publication.v1", Environment: "synthetic-test", Audience: "passplus-compiled-github-publisher", Scope: "commit-circuit-family",
		OperationID: identifier(1), AccountID: identifier(2), Handle: "synthetic-test", Repository: c.repository, RepositoryID: c.repositoryID, Branch: "synthetic-test",
		PredecessorCommit: strings.Repeat("a", 40), PredecessorDigest: strings.Repeat("a", 64), OldRegistration: identifier(3), NewRegistration: identifier(4), OldVersion: 1, NewVersion: 2, OldEpoch: 1, NewEpoch: 2,
		IssuedAt: 2000000000, ExpiresAt: 2000000060, AcceptedAt: 1999999990, BuildID: "test-build", OldCircuits: map[string]string{}, NewCircuits: map[string]string{}}
	for i, grade := range []string{"ID1", "ID2", "ID3", "ID4"} {
		a.OldCircuits[grade] = sum([]byte("old" + grade))
		a.NewCircuits[grade] = sum([]byte("new" + grade))
		_ = i
	}
	for _, name := range []string{"manifest.json", "archive.e6.e6ps", "SHA256SUMS"} {
		data := []byte("synthetic " + name)
		a.Files = append(a.Files, File{Path: name, Content: base64.StdEncoding.EncodeToString(data), SHA256: sum(data)})
	}
	a.PayloadDigest = a.Files[1].SHA256
	pairs := [][]string{}
	for _, file := range a.Files {
		pairs = append(pairs, []string{file.Path, file.SHA256})
	}
	raw, _ := json.Marshal(pairs)
	a.FileSetDigest = sum(raw)
	for i := 0; i < 5; i++ {
		role, grade, digest := "candidate", fmt.Sprintf("ID%d", i), a.PayloadDigest
		if i == 0 {
			role, grade, digest = "existing", "ID4", a.PredecessorDigest
		}
		a.Proofs = append(a.Proofs, Proof{DecisionID: identifier(10 + i), Nonce: identifier(20 + i), OperationID: a.OperationID, Grade: grade, Role: role, Purpose: "circuit-family-replacement", PayloadDigest: digest, Accepted: true})
	}
	return c, key, a
}
func envelope(t *testing.T, a Authorization, key ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(Envelope{Authorization: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
func TestSignedAuthorizationBindsFiveProofsAndExactPayload(t *testing.T) {
	c, key, a := fixture(t)
	if _, err := authorize(c, envelope(t, a, key)); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Authorization){
		"login cannot replace":            func(a *Authorization) { a.Proofs[0].Purpose = "website-sign-in" },
		"missing candidate proof":         func(a *Authorization) { a.Proofs = a.Proofs[:4] },
		"wrong grade order":               func(a *Authorization) { a.Proofs[2].Grade = "ID4" },
		"wrong proof":                     func(a *Authorization) { a.Proofs[0].Accepted = false },
		"another operation":               func(a *Authorization) { a.Proofs[3].OperationID = identifier(99) },
		"proof replay":                    func(a *Authorization) { a.Proofs[3].Nonce = a.Proofs[2].Nonce },
		"different payload":               func(a *Authorization) { a.Files[1].Content = base64.StdEncoding.EncodeToString([]byte("changed")) },
		"different branch":                func(a *Authorization) { a.Branch = "someone-else" },
		"different repository":            func(a *Authorization) { a.RepositoryID++ },
		"unchanged circuit identity":      func(a *Authorization) { a.NewCircuits["ID1"] = a.OldCircuits["ID1"] },
		"expired":                         func(a *Authorization) { a.ExpiresAt = 1999999999 },
		"production cannot use simulator": func(a *Authorization) { a.Environment = "production" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, copy := fixture(t)
			change(&copy)
			if _, err := authorize(c, envelope(t, copy, key)); err == nil {
				t.Fatal("accepted invalid authorization")
			}
		})
	}
	_, stranger, _ := fixture(t)
	if _, err := authorize(c, envelope(t, a, stranger)); err == nil {
		t.Fatal("accepted wrong signer")
	}
	raw := envelope(t, a, key)
	if _, err := authorize(c, append(raw, []byte(" {}")...)); err == nil {
		t.Fatal("accepted trailing payload")
	}
}

type provider struct {
	sync.Mutex
	tip, old        string
	files           map[string]File
	commits         int
	lost            bool
	wrongReadback   bool
	wrongRepository bool
}

func (p *provider) serve(w http.ResponseWriter, r *http.Request) {
	p.Lock()
	defer p.Unlock()
	if r.Header.Get("Authorization") != "Bearer runtime-test-token" {
		http.Error(w, "missing credential", 401)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	respond := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	if r.URL.Path == "/repos/eni6ma/passplus-rotation-lab-tests" {
		id := 123
		if p.wrongRepository {
			id++
		}
		respond(map[string]any{"id": id, "full_name": "eni6ma/passplus-rotation-lab-tests", "permissions": map[string]bool{"push": true}})
		return
	}
	if strings.Contains(r.URL.Path, "/git/ref/heads/") {
		respond(map[string]any{"object": map[string]string{"sha": p.tip, "type": "commit"}})
		return
	}
	if r.URL.Path == "/graphql" {
		var input struct {
			Query     string `json:"query"`
			Variables struct {
				Input struct {
					Expected string `json:"expectedHeadOid"`
					Branch   struct {
						Name string `json:"branchName"`
					} `json:"branch"`
					FileChanges struct {
						Additions []struct {
							Path    string `json:"path"`
							Content string `json:"contents"`
						} `json:"additions"`
					} `json:"fileChanges"`
				} `json:"input"`
			} `json:"variables"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil || !strings.Contains(input.Query, "createCommitOnBranch") || input.Variables.Input.Branch.Name != "synthetic-test" {
			http.Error(w, "invalid commit", 400)
			return
		}
		if input.Variables.Input.Expected != p.tip {
			respond(map[string]any{"errors": []string{"head changed"}})
			return
		}
		p.tip = strings.Repeat("b", 40)
		p.commits++
		p.files = map[string]File{}
		for _, f := range input.Variables.Input.FileChanges.Additions {
			p.files[f.Path] = File{Path: f.Path, Content: f.Content}
		}
		if p.lost {
			http.Error(w, "response lost after commit", 503)
			return
		}
		respond(map[string]any{"data": map[string]any{"createCommitOnBranch": map[string]any{"commit": map[string]string{"oid": p.tip}}}})
		return
	}
	if strings.Contains(r.URL.Path, "/git/commits/") {
		respond(map[string]any{"sha": p.tip, "parents": []map[string]string{{"sha": p.old}}})
		return
	}
	if strings.Contains(r.URL.Path, "/contents/") {
		name := strings.Split(r.URL.Path, "/contents/")[1]
		f, ok := p.files[name]
		if !ok {
			http.Error(w, "missing", 404)
			return
		}
		if p.wrongReadback {
			f.Content = base64.StdEncoding.EncodeToString([]byte("changed"))
		}
		if r.Header.Get("Accept") == "application/vnd.github.raw+json" {
			data, _ := base64.StdEncoding.DecodeString(f.Content)
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(data)
			return
		}
		respond(map[string]string{"path": name, "encoding": "base64", "content": f.Content})
		return
	}
	http.Error(w, "unexpected endpoint", 400)
}
func TestOrdinarySameBranchCommitPreservesParentAndIsIdempotent(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(fmt.Sprint("lost-response-", lost), func(t *testing.T) {
			c, key, a := fixture(t)
			p := &provider{tip: a.PredecessorCommit, old: a.PredecessorCommit, lost: lost}
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
			if receipt.Commit != strings.Repeat("b", 40) || receipt.Parent != a.PredecessorCommit || receipt.Branch != a.Handle || receipt.Reconciled != lost {
				t.Fatalf("bad receipt: %+v", receipt)
			}
			repeat, err := publish(c, verified, "runtime-test-token", server.Client())
			if err != nil || !repeat.Reconciled || p.commits != 1 {
				t.Fatalf("duplicate commit: %v %d", err, p.commits)
			}
		})
	}
}
func TestReadbackAndRepositoryIdentityRefuseSubstitution(t *testing.T) {
	for _, variant := range []string{"wrong repository", "wrong bytes", "unrelated tip"} {
		t.Run(variant, func(t *testing.T) {
			c, _, a := fixture(t)
			p := &provider{tip: a.PredecessorCommit, old: a.PredecessorCommit}
			if variant == "wrong repository" {
				p.wrongRepository = true
			}
			if variant == "wrong bytes" {
				p.wrongReadback = true
			}
			if variant == "unrelated tip" {
				p.tip = strings.Repeat("c", 40)
				p.files = map[string]File{}
			}
			server := httptest.NewServer(http.HandlerFunc(p.serve))
			defer server.Close()
			c.api = server.URL
			if _, err := publish(c, a, "runtime-test-token", server.Client()); err == nil {
				t.Fatal("accepted substituted provider state")
			}
			if variant != "wrong bytes" && p.commits != 0 {
				t.Fatal("published before validating repository and predecessor")
			}
		})
	}
}
