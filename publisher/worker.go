package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const workerPrefix = "/internal/passplus/v1/rotation-worker/"

type ecJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d,omitempty"`
}
type workerClaim struct {
	OperationID    string `json:"operationId"`
	LeaseID        string `json:"leaseId"`
	Phase          string `json:"phase"`
	EnvelopeSHA256 string `json:"envelopeSha256"`
	EnvelopeBytes  int    `json:"envelopeBytes"`
}
type workerClient struct {
	origin   string
	private  *ecdsa.PrivateKey
	public   *ecdsa.PublicKey
	client   *http.Client
	now      func() time.Time
	cooldown time.Duration
}
type workerAgent struct {
	service     workerClient
	publication config
	token       func() string
}
type workerOutcome struct {
	State          string `json:"state"`
	OperationID    string `json:"operationId,omitempty"`
	PublisherBuild string `json:"publisherBuild"`
}

func workerError() error { return errors.New("PUBLISHER_WORKER_UNAVAILABLE") }
func hexPublic(text string) (ed25519.PublicKey, error) {
	value, e := hex.DecodeString(text)
	if e != nil || len(value) != ed25519.PublicKeySize {
		return nil, workerError()
	}
	return ed25519.PublicKey(value), nil
}
func ecKey(raw string, private bool) (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	var j ecJWK
	if strict([]byte(raw), &j) != nil || j.Kty != "EC" || j.Crv != "P-256" || (private != (j.D != "")) {
		return nil, nil, workerError()
	}
	decode := func(s string) ([]byte, error) {
		v, e := base64.RawURLEncoding.DecodeString(s)
		if e != nil || len(v) != 32 || base64.RawURLEncoding.EncodeToString(v) != s {
			return nil, workerError()
		}
		return v, nil
	}
	x, e := decode(j.X)
	if e != nil {
		return nil, nil, e
	}
	y, e := decode(j.Y)
	if e != nil {
		return nil, nil, e
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, nil, workerError()
	}
	if !private {
		return pub, nil, nil
	}
	d, e := decode(j.D)
	if e != nil {
		return nil, nil, e
	}
	scalar := new(big.Int).SetBytes(d)
	if scalar.Sign() <= 0 || scalar.Cmp(pub.Curve.Params().N) >= 0 {
		return nil, nil, workerError()
	}
	dx, dy := pub.Curve.ScalarBaseMult(d)
	if dx.Cmp(pub.X) != 0 || dy.Cmp(pub.Y) != 0 {
		return nil, nil, workerError()
	}
	return pub, &ecdsa.PrivateKey{PublicKey: *pub, D: scalar}, nil
}
func canonicalPayload(value any) ([]byte, error) {
	raw, e := json.Marshal(value)
	if e != nil {
		return nil, workerError()
	}
	var sorted any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&sorted) != nil {
		return nil, workerError()
	}
	return json.Marshal(sorted)
}
func signedES256(header, claims any, key *ecdsa.PrivateKey) (string, error) {
	h, e := json.Marshal(header)
	if e != nil {
		return "", workerError()
	}
	p, e := json.Marshal(claims)
	if e != nil {
		return "", workerError()
	}
	wire := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	hash := sha256.Sum256([]byte(wire))
	r, s, e := ecdsa.Sign(rand.Reader, key, hash[:])
	if e != nil {
		return "", workerError()
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return wire + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
func (w workerClient) request(action string, input any, limit int) ([]byte, string, string, error) {
	payload, e := canonicalPayload(input)
	if e != nil {
		return nil, "", "", e
	}
	nonce := make([]byte, 32)
	if _, e = rand.Read(nonce); e != nil {
		return nil, "", "", workerError()
	}
	jti := base64.RawURLEncoding.EncodeToString(nonce)
	path := workerPrefix + action
	now := w.now().Unix()
	token, e := signedES256(map[string]string{"alg": "ES256", "typ": "passplus-service-request+jwt"}, map[string]any{
		"iss": "passplus-publisher-test", "aud": "passplus-verifier-test", "jti": jti, "iat": now, "exp": now + 30, "method": "POST", "path": path, "body_hash": sum(payload)}, w.private)
	if e != nil {
		return nil, "", "", e
	}
	req, e := http.NewRequest("POST", w.origin+path, bytes.NewReader(payload))
	if e != nil {
		return nil, "", "", workerError()
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if w.cooldown > 0 {
		defer time.Sleep(w.cooldown)
	}
	response, e := w.client.Do(req)
	if e != nil {
		return nil, "", "", workerError()
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, "", "", workerError()
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if e != nil || len(raw) > limit {
		return nil, "", "", workerError()
	}
	return raw, jti, sum(payload), nil
}
func (w workerClient) rpc(action string, input any, out any) error {
	raw, jti, requestHash, e := w.request(action, input, 131072)
	if e != nil {
		return e
	}
	var envelope struct {
		Decision string `json:"decision"`
	}
	if strict(raw, &envelope) != nil {
		return workerError()
	}
	parts := strings.Split(envelope.Decision, ".")
	if len(parts) != 3 {
		return workerError()
	}
	h, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return workerError()
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if strict(h, &header) != nil || header.Alg != "ES256" || header.Typ != "passplus-service-result+jwt" {
		return workerError()
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil || len(sig) != 64 {
		return workerError()
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(w.public, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return workerError()
	}
	data, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return workerError()
	}
	var claims struct {
		Issuer   string          `json:"iss"`
		Audience string          `json:"aud"`
		Issued   int64           `json:"iat"`
		Expires  int64           `json:"exp"`
		JTI      string          `json:"request_jti"`
		Hash     string          `json:"request_hash"`
		Path     string          `json:"path"`
		Result   json.RawMessage `json:"result"`
	}
	if strict(data, &claims) != nil || claims.Issuer != "passplus-verifier-test" || claims.Audience != "passplus-publisher-test" || claims.JTI != jti || claims.Hash != requestHash || claims.Path != workerPrefix+action || claims.Issued > w.now().Unix()+5 || claims.Expires <= w.now().Unix() || claims.Expires <= claims.Issued || claims.Expires-claims.Issued > 30 {
		return workerError()
	}
	if json.Unmarshal(claims.Result, out) != nil {
		return workerError()
	}
	return nil
}
func (w workerClient) download(claim workerClaim) ([]byte, error) {
	if !hash.MatchString(claim.EnvelopeSHA256) || claim.EnvelopeBytes <= 0 || claim.EnvelopeBytes > maximum {
		return nil, workerError()
	}
	raw, _, _, e := w.request("envelope", map[string]string{"operationId": claim.OperationID, "leaseId": claim.LeaseID, "envelopeSha256": claim.EnvelopeSHA256}, claim.EnvelopeBytes)
	if e != nil || len(raw) != claim.EnvelopeBytes || sum(raw) != claim.EnvelopeSHA256 {
		return nil, workerError()
	}
	return raw, nil
}
func (a workerAgent) step() (workerOutcome, error) {
	outcome := workerOutcome{State: "IDLE", PublisherBuild: buildID}
	var claim workerClaim
	if e := a.service.rpc("claim", map[string]any{}, &claim); e != nil {
		return outcome, e
	}
	if claim.Phase == "IDLE" {
		return outcome, nil
	}
	if !uuid.MatchString(claim.OperationID) || !uuid.MatchString(claim.LeaseID) {
		return outcome, workerError()
	}
	outcome.OperationID = claim.OperationID
	action := "finish"
	var input any = map[string]string{"operationId": claim.OperationID, "leaseId": claim.LeaseID}
	if claim.Phase == "COMMITTING" {
		raw, e := a.service.download(claim)
		if e != nil {
			return outcome, e
		}
		authorization, e := authorize(a.publication, raw)
		clear(raw)
		if e != nil || authorization.OperationID != claim.OperationID {
			return outcome, workerError()
		}
		// The GitHub credential is read only after both service delivery and the
		// independent five-proof authorization have been authenticated.
		receipt, e := publish(a.publication, authorization, a.token(), a.service.client)
		if e != nil {
			return outcome, e
		}
		action = "published"
		input = map[string]any{"operationId": claim.OperationID, "leaseId": claim.LeaseID, "receipt": receipt}
	} else if claim.Phase != "PUBLISHED" {
		return outcome, workerError()
	}
	var result struct {
		Schema      string `json:"schema"`
		Environment string `json:"environment"`
		ID          string `json:"id"`
		State       string `json:"state"`
	}
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		err = a.service.rpc(action, input, &result)
		if err == nil {
			break
		}
	}
	if err != nil || result.Schema != "passplus.rotation-status.v1" || result.Environment != "synthetic-test" || result.ID != claim.OperationID || result.State != "ACTIVE" {
		return outcome, workerError()
	}
	outcome.State = "ACTIVE"
	return outcome, nil
}
func runWorker() error {
	origin, e := url.Parse(os.Getenv("PASSPLUS_VERIFIER_ORIGIN"))
	if e != nil || origin.Scheme != "https" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" || origin.Port() != "" || !regexp.MustCompile(`^passplus-e6-[a-f0-9]{8}-verifier\.wasmer\.app$`).MatchString(origin.Hostname()) {
		return workerError()
	}
	_, private, e := ecKey(os.Getenv("PASSPLUS_WORKER_PRIVATE_JWK"), true)
	if e != nil {
		return e
	}
	public, _, e := ecKey(os.Getenv("PASSPLUS_VERIFIER_PUBLIC_JWK"), false)
	if e != nil {
		return e
	}
	repositoryID, e := strconv.ParseInt(os.Getenv("PASSPLUS_REPOSITORY_ID"), 10, 64)
	if e != nil || repositoryID <= 0 || !regexp.MustCompile(`^eni6ma/passplus-rotation-lab-[a-z0-9-]+$`).MatchString(os.Getenv("PASSPLUS_REPOSITORY")) {
		return workerError()
	}
	publicAuthority, e := hexPublic(os.Getenv("PASSPLUS_AUTHORITY_PUBLIC_HEX"))
	if e != nil {
		return e
	}
	wait := 0
	if text := os.Getenv("PASSPLUS_WORKER_WAIT_SECONDS"); text != "" {
		wait, e = strconv.Atoi(text)
		if e != nil || wait < 0 || wait > 300 {
			return workerError()
		}
	}
	client := &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return workerError() }}
	agent := workerAgent{service: workerClient{origin: origin.String(), private: private, public: public, client: client, now: time.Now, cooldown: 1500 * time.Millisecond},
		publication: config{repository: os.Getenv("PASSPLUS_REPOSITORY"), repositoryID: repositoryID, publicKey: publicAuthority, api: "https://api.github.com", now: time.Now}, token: func() string { return os.Getenv("GITHUB_TOKEN") }}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		outcome, e := agent.step()
		if e != nil {
			return e
		}
		if outcome.State == "ACTIVE" || wait == 0 || !time.Now().Add(5*time.Second).Before(deadline) {
			return json.NewEncoder(os.Stdout).Encode(outcome)
		}
		time.Sleep(5 * time.Second)
	}
}
