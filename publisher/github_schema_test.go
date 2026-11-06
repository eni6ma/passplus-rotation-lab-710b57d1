package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// This snapshot comes from GitHub's authenticated live schema, independently
// of the local provider model and the publisher's request implementation.
func TestCommitUsesRecordedLiveGitHubBranchContract(t *testing.T) {
	raw, err := os.ReadFile("github-committable-branch.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Type   string   `json:"type"`
		Fields []string `json:"inputFields"`
	}
	if json.Unmarshal(raw, &schema) != nil || schema.Type != "CommittableBranch" {
		t.Fatal("live schema snapshot required")
	}
	allowed := map[string]bool{}
	for _, field := range schema.Fields {
		allowed[field] = true
	}
	c, _, a := fixture(t)
	provider := &provider{tip: a.PredecessorCommit, old: a.PredecessorCommit}
	validated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			raw, _ := io.ReadAll(r.Body)
			var input struct {
				Variables struct {
					Input struct {
						Branch map[string]any `json:"branch"`
					} `json:"input"`
				} `json:"variables"`
			}
			if json.Unmarshal(raw, &input) != nil {
				http.Error(w, "invalid request", 400)
				return
			}
			for name := range input.Variables.Input.Branch {
				if !allowed[name] {
					http.Error(w, "field absent from live schema", 400)
					return
				}
			}
			if input.Variables.Input.Branch["branchName"] != a.Branch || input.Variables.Input.Branch["repositoryNameWithOwner"] != a.Repository {
				http.Error(w, "branch identity required", 400)
				return
			}
			validated = true
			r.Body = io.NopCloser(bytes.NewReader(raw))
		}
		provider.serve(w, r)
	}))
	defer server.Close()
	c.api = server.URL
	if _, err = publish(c, a, "runtime-test-token", server.Client()); err != nil {
		t.Fatal(err)
	}
	if !validated || provider.commits != 1 {
		t.Fatal("commit did not pass the independent live branch schema")
	}
}
