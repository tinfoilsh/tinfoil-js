//go:build ignore

// Generates rfc3161-tokens.json, the RFC 3161 fixtures for sigstore-keyed.test.ts.
//
// It mints synthetic timestamp authorities (a root CA and a timestamping leaf
// per key type) and a set of timestamp responses over one fixed input, so the
// verifier's parsing, imprint, policy, chain and window checks can be
// exercised against real CMS signatures without minting anything at test time.
//
// Run it from inside any module that provides github.com/digitorus/timestamp:
//
//	go run rfc3161-tokens.gen.go > rfc3161-tokens.json
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/digitorus/timestamp"
)

const (
	domain = "https://tinfoil.sh/timestamp-input/test"
	policy = "1.3.6.1.4.1.57264.2"
)

var (
	sigstorePolicy  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}
	otherPolicy     = asn1.ObjectIdentifier{1, 2, 3, 4}
	ekuOID          = asn1.ObjectIdentifier{2, 5, 29, 37}
	timestampingOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}

	rootNotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rootNotAfter  = time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
	leafNotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leafNotAfter  = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	genTime       = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	lateGenTime   = time.Date(2027, 6, 15, 12, 0, 0, 0, time.UTC)
)

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	out  authorityJSON
}

type authorityJSON struct {
	Note         string   `json:"note"`
	Curve        string   `json:"curve"`
	Certificates []string `json:"certificates"`
	NotBefore    string   `json:"notBefore"`
	NotAfter     string   `json:"notAfter"`
}

type tokenJSON struct {
	Note          string `json:"note"`
	Authority     string `json:"authority"`
	Status        int    `json:"status"`
	Policy        string `json:"policy,omitempty"`
	HashAlgorithm string `json:"hashAlgorithm,omitempty"`
	GenTime       string `json:"genTime,omitempty"`
	Response      string `json:"response"`
}

type fixtureJSON struct {
	Note        string                   `json:"note"`
	Domain      string                   `json:"domain"`
	Core        json.RawMessage          `json:"core"`
	Input       string                   `json:"input"`
	Authorities map[string]authorityJSON `json:"authorities"`
	Tokens      map[string]tokenJSON     `json:"tokens"`
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

type ekuMode int

const (
	ekuCritical ekuMode = iota
	ekuNonCritical
	ekuNone
)

func newAuthority(name string, curve elliptic.Curve, mode ekuMode, note string) *authority {
	rootKey := must(ecdsa.GenerateKey(curve, rand.Reader))
	leafKey := must(ecdsa.GenerateKey(curve, rand.Reader))
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test timestamp root " + name},
		NotBefore: rootNotBefore, NotAfter: rootNotAfter,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	rootDER := must(x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey))
	rootCert := must(x509.ParseCertificate(rootDER))
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test timestamp signer " + name},
		NotBefore: leafNotBefore, NotAfter: leafNotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	switch mode {
	case ekuCritical:
		eku := must(asn1.Marshal([]asn1.ObjectIdentifier{timestampingOID}))
		leafTemplate.ExtraExtensions = []pkix.Extension{{Id: ekuOID, Critical: true, Value: eku}}
	case ekuNonCritical:
		leafTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	case ekuNone:
	}
	leafDER := must(x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey))
	leafCert := must(x509.ParseCertificate(leafDER))
	return &authority{cert: leafCert, key: leafKey, out: authorityJSON{
		Note: note, Curve: curve.Params().Name,
		Certificates: []string{b64(leafDER), b64(rootDER)},
		NotBefore:    leafNotBefore.Format(time.RFC3339), NotAfter: leafNotAfter.Format(time.RFC3339),
	}}
}

func mint(a *authority, input []byte, at time.Time, pol asn1.ObjectIdentifier, imprint crypto.Hash, signer crypto.Hash, embedCert bool) []byte {
	var digest []byte
	switch imprint {
	case crypto.SHA256:
		d := sha256.Sum256(input)
		digest = d[:]
	case crypto.SHA384:
		d := sha512.Sum384(input)
		digest = d[:]
	default:
		panic("unsupported imprint")
	}
	ts := timestamp.Timestamp{HashAlgorithm: imprint, HashedMessage: digest, Time: at, Policy: pol, AddTSACertificate: embedCert}
	return must(ts.CreateResponseWithOpts(a.cert, a.key, signer))
}

func main() {
	core := json.RawMessage(`{"b": 2, "a": "x", "n": [1, 2.5, "ü"], "z": {"y": true, "x": null}}`)
	canonical := jsontext.Value(append([]byte(nil), core...))
	if err := canonical.Canonicalize(); err != nil {
		panic(err)
	}
	input := append([]byte(domain), canonical...)

	p256 := newAuthority("p256", elliptic.P256(), ekuCritical, "P-256 root and timestamping leaf; the leaf's extended key usage is critical and names only timestamping.")
	p384 := newAuthority("p384", elliptic.P384(), ekuCritical, "P-384 root and timestamping leaf, the key type of the production authority.")
	lax := newAuthority("lax-eku", elliptic.P256(), ekuNonCritical, "P-256 leaf whose timestamping extended key usage is not marked critical.")
	noEku := newAuthority("no-eku", elliptic.P256(), ekuNone, "P-256 leaf with no extended key usage extension.")

	f := fixtureJSON{
		Note:   "Generated by rfc3161-tokens.gen.go (see that file for how). `input` is `domain` followed by the RFC 8785 canonical form of `core`; every token's message imprint is a hash of `input`. Authorities list their certificates leaf first, as a trusted root does.",
		Domain: domain, Core: core, Input: b64(input),
		Authorities: map[string]authorityJSON{"p256": p256.out, "p384": p384.out, "lax-eku": lax.out, "no-eku": noEku.out},
		Tokens: map[string]tokenJSON{
			"granted-p256": {Note: "granted, Sigstore policy, SHA-256 imprint, signer certificate embedded", Authority: "p256", Status: 0, Policy: policy, HashAlgorithm: "sha256", GenTime: genTime.Format(time.RFC3339),
				Response: b64(mint(p256, input, genTime, sigstorePolicy, crypto.SHA256, crypto.SHA256, true))},
			"granted-p256-no-cert": {Note: "as granted-p256 but with no certificate embedded in the token", Authority: "p256", Status: 0, Policy: policy, HashAlgorithm: "sha256", GenTime: genTime.Format(time.RFC3339),
				Response: b64(mint(p256, input, genTime, sigstorePolicy, crypto.SHA256, crypto.SHA256, false))},
			"granted-p384": {Note: "P-384 signer with a SHA-256 signature digest, as the production authority signs", Authority: "p384", Status: 0, Policy: policy, HashAlgorithm: "sha256", GenTime: genTime.Format(time.RFC3339),
				Response: b64(mint(p384, input, genTime, sigstorePolicy, crypto.SHA256, crypto.SHA256, true))},
			"granted-p384-sha384": {Note: "P-384 signer with a SHA-384 signature digest", Authority: "p384", Status: 0, Policy: policy, HashAlgorithm: "sha256", GenTime: genTime.Format(time.RFC3339),
				Response: b64(mint(p384, input, genTime, sigstorePolicy, crypto.SHA256, crypto.SHA384, true))},
			"other-policy": {Note: "granted under policy 1.2.3.4 instead of the Sigstore policy", Authority: "p256", Status: 0, Policy: "1.2.3.4", HashAlgorithm: "sha256", GenTime: genTime.Format(time.RFC3339),
				Response: b64(mint(p256, input, genTime, otherPolicy, crypto.SHA256, crypto.SHA256, true))},
			"sha384-imprint": {Note: "message imprint is SHA-384 of the input", Authority: "p256", Status: 0, Policy: policy, HashAlgorithm: "sha384", GenTime: genTime.Format(time.RFC3339),
				Response: b64(mint(p256, input, genTime, sigstorePolicy, crypto.SHA384, crypto.SHA256, true))},
			"after-signer-expiry": {Note: "genTime falls after the signer certificate's notAfter", Authority: "p256", Status: 0, Policy: policy, HashAlgorithm: "sha256", GenTime: lateGenTime.Format(time.RFC3339),
				Response: b64(mint(p256, input, lateGenTime, sigstorePolicy, crypto.SHA256, crypto.SHA256, true))},
			"lax-eku": {Note: "signed by the leaf whose extended key usage is not critical", Authority: "lax-eku", Status: 0, Policy: policy, HashAlgorithm: "sha256", GenTime: genTime.Format(time.RFC3339),
				Response: b64(mint(lax, input, genTime, sigstorePolicy, crypto.SHA256, crypto.SHA256, true))},
			"no-eku": {Note: "signed by the leaf with no extended key usage", Authority: "no-eku", Status: 0, Policy: policy, HashAlgorithm: "sha256", GenTime: genTime.Format(time.RFC3339),
				Response: b64(mint(noEku, input, genTime, sigstorePolicy, crypto.SHA256, crypto.SHA256, true))},
			"rejected": {Note: "status rejection with failure info badRequest and no token", Authority: "", Status: 2,
				Response: b64(must(timestamp.CreateErrorResponse(timestamp.Rejection, timestamp.BadRequest)))},
		},
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		panic(err)
	}
	fmt.Fprintln(os.Stderr, "ok")
}
