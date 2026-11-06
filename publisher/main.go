// A restricted synthetic-pilot publisher. Credentials are runtime input, never
// compiled data. Only a signed five-proof authorization can select a payload.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var buildID = "development"
var oid = regexp.MustCompile(`^[a-f0-9]{40}$`)
var hash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
var handle = regexp.MustCompile(`^synthetic-[a-z0-9-]{1,22}$`)

const maximum = 20 * 1024 * 1024
const maxEncryptedArchive = 8*1024*1024 + 65536

func fileLimit(name string) int {
	switch name {
	case "manifest.json":
		return 16384
	case "archive.e6.e6ps":
		return maxEncryptedArchive
	case "SHA256SUMS":
		return 512
	default:
		return 0
	}
}

type Envelope struct {
	Authorization string `json:"authorization"`
	Signature     string `json:"signature"`
}
type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	SHA256  string `json:"sha256"`
}
type Proof struct {
	DecisionID    string `json:"decisionId"`
	Nonce         string `json:"nonce"`
	OperationID   string `json:"operationId"`
	Grade         string `json:"grade"`
	Role          string `json:"role"`
	Purpose       string `json:"purpose"`
	PayloadDigest string `json:"payloadDigest"`
	Accepted      bool   `json:"accepted"`
}
type Authorization struct {
	Schema            string            `json:"schema"`
	Environment       string            `json:"environment"`
	Audience          string            `json:"audience"`
	Scope             string            `json:"scope"`
	OperationID       string            `json:"operationId"`
	AccountID         string            `json:"accountId"`
	Handle            string            `json:"handle"`
	Repository        string            `json:"repository"`
	RepositoryID      int64             `json:"repositoryId"`
	Branch            string            `json:"branch"`
	PredecessorCommit string            `json:"predecessorCommit"`
	PredecessorDigest string            `json:"predecessorDigest"`
	OldRegistration   string            `json:"oldRegistration"`
	NewRegistration   string            `json:"newRegistration"`
	OldVersion        int               `json:"oldVersion"`
	NewVersion        int               `json:"newVersion"`
	OldEpoch          int               `json:"oldEpoch"`
	NewEpoch          int               `json:"newEpoch"`
	IssuedAt          int64             `json:"issuedAt"`
	ExpiresAt         int64             `json:"expiresAt"`
	AcceptedAt        int64             `json:"acceptedAt"`
	PayloadDigest     string            `json:"payloadDigest"`
	FileSetDigest     string            `json:"fileSetDigest"`
	BuildID           string            `json:"buildId"`
	OldCircuits       map[string]string `json:"oldCircuits"`
	NewCircuits       map[string]string `json:"newCircuits"`
	Proofs            []Proof           `json:"proofs"`
	Files             []File            `json:"files"`
}
type Receipt struct {
	Schema         string `json:"schema"`
	Environment    string `json:"environment"`
	OperationID    string `json:"operationId"`
	Repository     string `json:"repository"`
	RepositoryID   int64  `json:"repositoryId"`
	Branch         string `json:"branch"`
	Parent         string `json:"parent"`
	Commit         string `json:"commit"`
	PayloadDigest  string `json:"payloadDigest"`
	FileSetDigest  string `json:"fileSetDigest"`
	BuildID        string `json:"buildId"`
	PublisherBuild string `json:"publisherBuild"`
	Reconciled     bool   `json:"reconciled"`
}
type config struct {
	repository   string
	repositoryID int64
	publicKey    ed25519.PublicKey
	api          string
	now          func() time.Time
}

func rejected() error { return errors.New("PUBLICATION_AUTHORIZATION_REJECTED") }
func strict(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return rejected()
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return rejected()
	}
	return nil
}

func authorize(c config, input []byte) (Authorization, error) {
	var a Authorization
	var e Envelope
	if len(input) > maximum || strict(input, &e) != nil {
		return a, rejected()
	}
	message, err := base64.RawURLEncoding.DecodeString(e.Authorization)
	if err != nil {
		return a, rejected()
	}
	signature, err := base64.RawURLEncoding.DecodeString(e.Signature)
	if err != nil || len(c.publicKey) != ed25519.PublicKeySize || !ed25519.Verify(c.publicKey, message, signature) || strict(message, &a) != nil {
		return a, rejected()
	}
	now := c.now().Unix()
	if a.Schema != "passplus.rotation-publication.v1" || a.Environment != "synthetic-test" || a.Audience != "passplus-compiled-github-publisher" || a.Scope != "commit-circuit-family" ||
		!uuid.MatchString(a.OperationID) || !uuid.MatchString(a.AccountID) || !handle.MatchString(a.Handle) || a.Branch != a.Handle ||
		a.Repository != c.repository || a.RepositoryID != c.repositoryID || !strings.HasPrefix(c.repository, "eni6ma/passplus-rotation-lab-") ||
		!oid.MatchString(a.PredecessorCommit) || !hash.MatchString(a.PredecessorDigest) || !hash.MatchString(a.PayloadDigest) || !hash.MatchString(a.FileSetDigest) ||
		!uuid.MatchString(a.OldRegistration) || !uuid.MatchString(a.NewRegistration) || a.OldRegistration == a.NewRegistration ||
		a.OldVersion < 1 || a.NewVersion != a.OldVersion+1 || a.OldEpoch < 1 || a.NewEpoch != a.OldEpoch+1 ||
		a.IssuedAt > now+5 || a.ExpiresAt <= now || a.ExpiresAt-a.IssuedAt > 120 || a.AcceptedAt > a.IssuedAt || a.AcceptedAt < 1 ||
		a.BuildID == "" || len(a.BuildID) > 128 || len(a.Files) != 3 || len(a.Proofs) != 5 || len(a.OldCircuits) != 4 || len(a.NewCircuits) != 4 {
		return a, rejected()
	}
	seen := map[string]bool{}
	for _, grade := range []string{"ID1", "ID2", "ID3", "ID4"} {
		if !hash.MatchString(a.OldCircuits[grade]) || !hash.MatchString(a.NewCircuits[grade]) {
			return a, rejected()
		}
		seen[a.OldCircuits[grade]] = true
	}
	for _, grade := range []string{"ID1", "ID2", "ID3", "ID4"} {
		if seen[a.NewCircuits[grade]] {
			return a, rejected()
		}
		seen[a.NewCircuits[grade]] = true
	}
	proofs := map[string]bool{}
	for i, p := range a.Proofs {
		role, grade, digest := "candidate", fmt.Sprintf("ID%d", i), a.PayloadDigest
		if i == 0 {
			role, grade, digest = "existing", "ID4", a.PredecessorDigest
		}
		if !p.Accepted || p.OperationID != a.OperationID || p.Role != role || p.Grade != grade || p.Purpose != "circuit-family-replacement" ||
			p.PayloadDigest != digest || !uuid.MatchString(p.DecisionID) || !uuid.MatchString(p.Nonce) || proofs[p.DecisionID] || proofs[p.Nonce] {
			return a, rejected()
		}
		proofs[p.DecisionID] = true
		proofs[p.Nonce] = true
	}
	pairs := [][]string{}
	for i, name := range []string{"manifest.json", "archive.e6.e6ps", "SHA256SUMS"} {
		file := a.Files[i]
		content, err := base64.StdEncoding.DecodeString(file.Content)
		limit := fileLimit(name)
		if err != nil || file.Path != name || len(content) == 0 || len(content) > limit || !hash.MatchString(file.SHA256) || sum(content) != file.SHA256 {
			return a, rejected()
		}
		if name == "archive.e6.e6ps" && file.SHA256 != a.PayloadDigest {
			return a, rejected()
		}
		pairs = append(pairs, []string{file.Path, file.SHA256})
	}
	encoded, _ := json.Marshal(pairs)
	if sum(encoded) != a.FileSetDigest {
		return a, rejected()
	}
	return a, nil
}
func sum(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

type github struct {
	client                  *http.Client
	base, token, repository string
}

func (g github) request(method, path string, body any, out any) error {
	var input io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return errors.New("PUBLICATION_ENCODING")
		}
		input = bytes.NewReader(encoded)
	}
	endpoint := g.base + "/repos/" + g.repository + path
	if path == "graphql" {
		endpoint = g.base + "/graphql"
	}
	req, err := http.NewRequest(method, endpoint, input)
	if err != nil {
		return errors.New("PUBLICATION_TRANSPORT")
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "PassPlus-compiled-publisher")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := g.client.Do(req)
	if err != nil {
		return errors.New("PUBLICATION_TRANSPORT")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || len(raw) > maximum || response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("PUBLICATION_PROVIDER_UNAVAILABLE")
	}
	if json.Unmarshal(raw, out) != nil {
		return errors.New("PUBLICATION_PROVIDER_FORMAT")
	}
	return nil
}
func (g github) head(branch string) (string, error) {
	var ref struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	if err := g.request("GET", "/git/ref/heads/"+url.PathEscape(branch), nil, &ref); err != nil {
		return "", err
	}
	if !oid.MatchString(ref.Object.SHA) || ref.Object.Type != "commit" {
		return "", errors.New("PUBLICATION_REF_IDENTITY")
	}
	return ref.Object.SHA, nil
}
func (g github) readback(a Authorization, commit string) error {
	var info struct {
		SHA     string `json:"sha"`
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
	}
	if err := g.request("GET", "/git/commits/"+commit, nil, &info); err != nil {
		return err
	}
	if info.SHA != commit || len(info.Parents) != 1 || info.Parents[0].SHA != a.PredecessorCommit {
		return errors.New("PUBLICATION_PARENT_MISMATCH")
	}
	for _, file := range a.Files {
		// GitHub's JSON contents endpoint omits base64 for larger files. Raw
		// immutable readback supports the real multi-megabyte E6PS archive.
		request, err := http.NewRequest("GET", g.base+"/repos/"+g.repository+"/contents/"+file.Path+"?ref="+commit, nil)
		if err != nil {
			return errors.New("PUBLICATION_READBACK_REQUEST")
		}
		request.Header.Set("Authorization", "Bearer "+g.token)
		request.Header.Set("Accept", "application/vnd.github.raw+json")
		request.Header.Set("User-Agent", "PassPlus-compiled-publisher")
		response, err := g.client.Do(request)
		if err != nil {
			return errors.New("PUBLICATION_READBACK_UNAVAILABLE")
		}
		limit := fileLimit(file.Path)
		data, readErr := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
		response.Body.Close()
		if readErr != nil || response.StatusCode != 200 || limit == 0 || len(data) > limit || sum(data) != file.SHA256 {
			return errors.New("PUBLICATION_READBACK_MISMATCH")
		}
	}
	return nil
}

func publish(c config, a Authorization, token string, client *http.Client) (Receipt, error) {
	var receipt Receipt
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return receipt, errors.New("PUBLICATION_CREDENTIAL_UNAVAILABLE")
	}
	g := github{client: client, base: c.api, token: token, repository: c.repository}
	var repo struct {
		ID          int64  `json:"id"`
		FullName    string `json:"full_name"`
		Archived    bool   `json:"archived"`
		Disabled    bool   `json:"disabled"`
		Permissions struct {
			Push bool `json:"push"`
		} `json:"permissions"`
	}
	if err := g.request("GET", "", nil, &repo); err != nil {
		return receipt, err
	}
	if repo.ID != c.repositoryID || repo.FullName != c.repository || repo.Archived || repo.Disabled || !repo.Permissions.Push {
		return receipt, errors.New("PUBLICATION_REPOSITORY_IDENTITY")
	}
	tip, err := g.head(a.Branch)
	if err != nil {
		return receipt, err
	}
	reconciled := tip != a.PredecessorCommit
	if !reconciled {
		additions := []map[string]string{}
		for _, file := range a.Files {
			additions = append(additions, map[string]string{"path": file.Path, "contents": file.Content})
		}
		input := map[string]any{"branch": map[string]string{"repositoryNameWithOwner": a.Repository, "branchName": a.Branch}, "expectedHeadOid": a.PredecessorCommit, "clientMutationId": a.OperationID,
			"message": map[string]string{"headline": "Pass+ circuit replacement " + a.OperationID, "body": "Synthetic account replacement. Build " + a.BuildID}, "fileChanges": map[string]any{"additions": additions}}
		var result struct {
			Data struct {
				Create *struct {
					Commit struct {
						OID string `json:"oid"`
					} `json:"commit"`
				} `json:"createCommitOnBranch"`
			} `json:"data"`
			Errors []json.RawMessage `json:"errors"`
		}
		// This is one ordinary commit on the existing branch, not a force-push or
		// separate ref-update operation. expectedHeadOid prevents a lost update.
		err = g.request("POST", "graphql", map[string]any{"query": "mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid} clientMutationId}}", "variables": map[string]any{"input": input}}, &result)
		if err == nil && len(result.Errors) == 0 && result.Data.Create != nil && oid.MatchString(result.Data.Create.Commit.OID) {
			tip = result.Data.Create.Commit.OID
		} else {
			// A missing response does not prove failure. Compare immutable file bytes
			// and parent at the observed tip before accepting an identical operation.
			tip, err = g.head(a.Branch)
			if err != nil {
				return receipt, err
			}
			if tip == a.PredecessorCommit {
				return receipt, errors.New("PUBLICATION_RETRY_IDENTICAL")
			}
			reconciled = true
		}
	}
	if err = g.readback(a, tip); err != nil {
		return receipt, err
	}
	finalTip, err := g.head(a.Branch)
	if err != nil {
		return receipt, err
	}
	if finalTip != tip {
		return receipt, errors.New("PUBLICATION_RECONCILIATION_HOLD")
	}
	receipt = Receipt{Schema: "passplus.rotation-publication-receipt.v1", Environment: "synthetic-test", OperationID: a.OperationID, Repository: a.Repository, RepositoryID: a.RepositoryID, Branch: a.Branch, Parent: a.PredecessorCommit, Commit: tip, PayloadDigest: a.PayloadDigest, FileSetDigest: a.FileSetDigest, BuildID: a.BuildID, PublisherBuild: buildID, Reconciled: reconciled}
	return receipt, nil
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--worker" {
		if err := runWorker(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"buildId": buildID, "scope": "synthetic-test-only"})
		return
	}
	fail := func(err error) { fmt.Fprintln(os.Stderr, err.Error()); os.Exit(1) }
	var repositoryID int64
	if _, err := fmt.Sscan(os.Getenv("PASSPLUS_REPOSITORY_ID"), &repositoryID); err != nil {
		fail(rejected())
	}
	public, err := hex.DecodeString(os.Getenv("PASSPLUS_AUTHORITY_PUBLIC_HEX"))
	if err != nil {
		fail(rejected())
	}
	c := config{repository: os.Getenv("PASSPLUS_REPOSITORY"), repositoryID: repositoryID, publicKey: public, api: "https://api.github.com", now: time.Now}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, maximum+1))
	if err != nil {
		fail(rejected())
	}
	a, err := authorize(c, input)
	if err != nil {
		fail(err)
	}
	// Read the runtime credential only after the authorization was verified.
	token := os.Getenv("GITHUB_TOKEN")
	client := &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("PUBLICATION_REDIRECT_REFUSED") }}
	receipt, err := publish(c, a, token, client)
	if err != nil {
		fail(err)
	}
	if err = json.NewEncoder(os.Stdout).Encode(receipt); err != nil {
		fail(errors.New("PUBLICATION_RECEIPT_WRITE"))
	}
}
