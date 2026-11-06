package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func workerFixture(t *testing.T, mode string) (workerAgent, *provider, *int, *int, func()) {
	t.Helper()
	c, key, a := fixture(t)
	raw := envelope(t, a, key)
	if mode == "bad-authorization" {
		var outer Envelope
		_ = json.Unmarshal(raw, &outer)
		outer.Signature = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 64))
		raw, _ = json.Marshal(outer)
	}
	caller, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	service, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	github := &provider{tip: a.PredecessorCommit, old: a.PredecessorCommit}
	api := httptest.NewServer(http.HandlerFunc(github.serve))
	c.api = api.URL
	tokenReads, reports := 0, 0
	seen := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
		if len(parts) != 3 {
			t.Error("unsigned worker request")
			http.Error(w, "denied", 401)
			return
		}
		wire, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]any
		_ = json.Unmarshal(wire, &claims)
		signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
		hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		input, _ := io.ReadAll(io.LimitReader(r.Body, 4097))
		var value any
		_ = json.Unmarshal(input, &value)
		canonical, _ := canonicalPayload(value)
		jti, _ := claims["jti"].(string)
		if len(signature) != 64 || !ecdsa.Verify(&caller.PublicKey, hash[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) || claims["iss"] != "passplus-publisher-test" || claims["aud"] != "passplus-verifier-test" || claims["method"] != "POST" || claims["path"] != r.URL.Path || claims["body_hash"] != sum(canonical) || seen[jti] {
			t.Error("worker request authentication failed")
			http.Error(w, "denied", 401)
			return
		}
		seen[jti] = true
		respond := func(result any) {
			now := time.Now().Unix()
			body := map[string]any{"iss": "passplus-verifier-test", "aud": "passplus-publisher-test", "iat": now, "exp": now + 30, "request_jti": jti, "request_hash": sum(canonical), "path": r.URL.Path, "result": result}
			if mode == "wrong-binding" {
				body["request_jti"] = "another-request"
			}
			if mode == "expired" {
				body["iat"] = now - 100
				body["exp"] = now - 70
			}
			token, _ := signedES256(map[string]string{"alg": "ES256", "typ": "passplus-service-result+jwt"}, body, service)
			if mode == "wrong-signature" {
				token = token[:len(token)-10] + strings.Repeat("a", 10)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"decision": token})
		}
		switch r.URL.Path {
		case workerPrefix + "claim":
			if mode == "idle" {
				respond(workerClaim{Phase: "IDLE"})
				return
			}
			if mode == "published" {
				respond(workerClaim{Phase: "PUBLISHED", OperationID: a.OperationID, LeaseID: a.NewRegistration})
				return
			}
			hash := sum(raw)
			if mode == "changed-download" {
				hash = strings.Repeat("f", 64)
			}
			respond(workerClaim{Phase: "COMMITTING", OperationID: a.OperationID, LeaseID: a.NewRegistration, EnvelopeSHA256: hash, EnvelopeBytes: len(raw)})
		case workerPrefix + "envelope":
			var lease struct {
				OperationID string `json:"operationId"`
				LeaseID     string `json:"leaseId"`
				Hash        string `json:"envelopeSha256"`
			}
			_ = json.Unmarshal(input, &lease)
			if lease.OperationID != a.OperationID || lease.LeaseID != a.NewRegistration {
				t.Error("download lost its lease binding")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(raw)
		case workerPrefix + "published":
			reports++
			var input struct {
				Receipt Receipt `json:"receipt"`
			}
			_ = json.Unmarshal(canonical, &input)
			if input.Receipt.Commit != strings.Repeat("b", 40) || input.Receipt.OperationID != a.OperationID {
				t.Error("receipt lost publication identity")
			}
			if mode == "lost-report" && reports == 1 {
				http.Error(w, "response lost", 503)
				return
			}
			respond(map[string]string{"schema": "passplus.rotation-status.v1", "environment": "synthetic-test", "id": a.OperationID, "state": "ACTIVE"})
		case workerPrefix + "finish":
			reports++
			respond(map[string]string{"schema": "passplus.rotation-status.v1", "environment": "synthetic-test", "id": a.OperationID, "state": "ACTIVE"})
		default:
			http.Error(w, "denied", 404)
		}
	}))
	client := server.Client()
	client.Timeout = 5 * time.Second
	agent := workerAgent{service: workerClient{origin: server.URL, private: caller, public: &service.PublicKey, client: client, now: time.Now}, publication: c, token: func() string { tokenReads++; return "runtime-test-token" }}
	return agent, github, &tokenReads, &reports, func() { server.Close(); api.Close() }
}

func TestWorkerAuthenticatesJobAndPublishesOnlyOnce(t *testing.T) {
	for _, mode := range []string{"success", "lost-report", "published", "idle"} {
		t.Run(mode, func(t *testing.T) {
			agent, provider, tokenReads, reports, close := workerFixture(t, mode)
			defer close()
			out, err := agent.step()
			if err != nil {
				t.Fatal(err)
			}
			expectedCommits := 1
			if mode == "published" || mode == "idle" {
				expectedCommits = 0
			}
			if provider.commits != expectedCommits || *tokenReads != expectedCommits {
				t.Fatal("credential read or publication occurred outside authenticated authorization")
			}
			if mode == "lost-report" && *reports != 2 {
				t.Fatal("lost result did not retry the same completion")
			}
			if mode == "idle" {
				if out.State != "IDLE" {
					t.Fatal(out)
				}
			} else if out.State != "ACTIVE" {
				t.Fatal(out)
			}
		})
	}
}

func TestWorkerRefusesSubstitutedDeliveryAndAuthorizationBeforeReadingToken(t *testing.T) {
	for _, mode := range []string{"wrong-binding", "wrong-signature", "expired", "changed-download", "bad-authorization"} {
		t.Run(mode, func(t *testing.T) {
			agent, provider, tokenReads, reports, close := workerFixture(t, mode)
			defer close()
			if _, err := agent.step(); err == nil {
				t.Fatal("substituted worker input accepted")
			}
			if provider.commits != 0 || *tokenReads != 0 || *reports != 0 {
				t.Fatal("unverified job reached a credential or commit")
			}
		})
	}
}

func TestWorkerJWKRejectsChangedOrPrivateVerificationIdentity(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	encode := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, 32))) }
	j := ecJWK{Kty: "EC", Crv: "P-256", X: encode(key.X), Y: encode(key.Y), D: encode(key.D)}
	raw, _ := json.Marshal(j)
	if _, _, err := ecKey(string(raw), true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ecKey(string(raw), false); err == nil {
		t.Fatal("private verification key accepted")
	}
	j.D = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	raw, _ = json.Marshal(j)
	if _, _, err := ecKey(string(raw), true); err == nil {
		t.Fatal("inconsistent key accepted")
	}
}

func TestWorkerEnvironmentCannotForwardCredentialsToAnUnapprovedOrigin(t *testing.T) {
	for _, origin := range []string{"http://passplus-e6-12345678-verifier.wasmer.app", "https://other.invalid", "https://passplus-e6-12345678-verifier.wasmer.app@other.invalid", "https://passplus-e6-12345678-verifier.wasmer.app/path"} {
		t.Setenv("PASSPLUS_VERIFIER_ORIGIN", origin)
		if runWorker() == nil {
			t.Fatal("unapproved worker destination accepted")
		}
	}
}
