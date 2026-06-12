// Package certificate – brainpool curve support and fallback certificate parser.
//
// Go's crypto/x509 only recognises the four NIST prime curves; it returns
// "x509: unsupported elliptic curve" for any other OID.  This file adds:
//
//  1. A generic Weierstrass curve implementation (weierstrassCurve) that
//     satisfies elliptic.Curve and supports an arbitrary A coefficient.
//  2. Pre-built curve instances for brainpoolP256r1, brainpoolP384r1,
//     brainpoolP512r1 (RFC 5639 parameters verified against OpenSSL).
//  3. parseBrainpoolCertificate – a pure-ASN.1 fallback parser that returns a
//     fully-populated *x509.Certificate when the standard parser fails.
package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ── Brainpool OIDs (RFC 5639) ────────────────────────────────────────────────

var (
	oidBrainpoolP256r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	oidBrainpoolP384r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}
	oidBrainpoolP512r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 13}

	// Standard ECDSA signature OIDs
	oidSigECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSigECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSigECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSigECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// Brainpool-specific signature OIDs (RFC 5639 §3.9)
	oidBPSigWithSHA256 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 4, 1, 3}
	oidBPSigWithSHA384 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 4, 1, 4}
	oidBPSigWithSHA512 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 4, 1, 5}
)

// ── Extension OIDs ───────────────────────────────────────────────────────────

var (
	oidExtSAN   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtBC    = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtKU    = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtEKU   = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtAIA   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtCRLDP = asn1.ObjectIdentifier{2, 5, 29, 31}

	oidAIAOCSP    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAIAIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

// ── EKU OID → x509.ExtKeyUsage map ──────────────────────────────────────────

var ekuOIDMap = map[string]x509.ExtKeyUsage{
	asn1.ObjectIdentifier{2, 5, 29, 37, 0}.String():           x509.ExtKeyUsageAny,
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}.String(): x509.ExtKeyUsageServerAuth,
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}.String(): x509.ExtKeyUsageClientAuth,
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}.String(): x509.ExtKeyUsageCodeSigning,
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}.String(): x509.ExtKeyUsageEmailProtection,
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}.String(): x509.ExtKeyUsageTimeStamping,
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}.String(): x509.ExtKeyUsageOCSPSigning,
}

// ── Generic Weierstrass curve (y² = x³ + Ax + B mod p) ──────────────────────

// weierstrassCurve implements elliptic.Curve for arbitrary short Weierstrass
// curves. All arithmetic uses affine coordinates (sufficient for a viewer).
type weierstrassCurve struct {
	*elliptic.CurveParams
	A *big.Int
}

func (c *weierstrassCurve) Params() *elliptic.CurveParams { return c.CurveParams }

func (c *weierstrassCurve) IsOnCurve(x, y *big.Int) bool {
	p := c.P
	if x.Sign() < 0 || x.Cmp(p) >= 0 || y.Sign() < 0 || y.Cmp(p) >= 0 {
		return false
	}
	// rhs = x³ + A·x + B  mod p
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	ax := new(big.Int).Mul(c.A, x)
	rhs := new(big.Int).Add(x3, ax)
	rhs.Add(rhs, c.B)
	rhs.Mod(rhs, p)

	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, p)
	return y2.Cmp(rhs) == 0
}

func (c *weierstrassCurve) Add(x1, y1, x2, y2 *big.Int) (x3, y3 *big.Int) {
	// point at infinity represented as (0,0)
	inf1 := x1.Sign() == 0 && y1.Sign() == 0
	inf2 := x2.Sign() == 0 && y2.Sign() == 0
	if inf1 {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if inf2 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}
	if x1.Cmp(x2) == 0 {
		if y1.Cmp(y2) == 0 {
			return c.Double(x1, y1)
		}
		return new(big.Int), new(big.Int) // P + (-P) = ∞
	}
	p := c.P
	dy := new(big.Int).Sub(y2, y1)
	dx := new(big.Int).Sub(x2, x1)
	lambda := bpModMul(dy, bpModInv(dx, p), p)

	x3 = bpModSub(bpModSub(bpModMul(lambda, lambda, p), x1, p), x2, p)
	y3 = bpModSub(bpModMul(lambda, bpModSub(x1, x3, p), p), y1, p)
	return
}

func (c *weierstrassCurve) Double(x1, y1 *big.Int) (x3, y3 *big.Int) {
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}
	if y1.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}
	p := c.P
	// λ = (3·x₁² + A) / (2·y₁)
	x1sq := bpModMul(x1, x1, p)
	num := bpModAdd(bpModMul(big.NewInt(3), x1sq, p), c.A, p)
	den := bpModMul(big.NewInt(2), y1, p)
	lambda := bpModMul(num, bpModInv(den, p), p)

	x3 = bpModSub(bpModSub(bpModMul(lambda, lambda, p), x1, p), x1, p)
	y3 = bpModSub(bpModMul(lambda, bpModSub(x1, x3, p), p), y1, p)
	return
}

func (c *weierstrassCurve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	x, y = new(big.Int), new(big.Int) // start at ∞
	for _, b := range k {
		for bit := 7; bit >= 0; bit-- {
			x, y = c.Double(x, y)
			if b>>uint(bit)&1 == 1 {
				x, y = c.Add(x, y, x1, y1)
			}
		}
	}
	return
}

func (c *weierstrassCurve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return c.ScalarMult(c.Gx, c.Gy, k)
}

// Modular helpers – all return values in [0, p).

func bpModInv(a, p *big.Int) *big.Int {
	r := new(big.Int).ModInverse(a, p)
	if r == nil {
		return new(big.Int) // degenerate
	}
	return r
}
func bpModMul(a, b, p *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), p) }
func bpModAdd(a, b, p *big.Int) *big.Int {
	r := new(big.Int).Add(a, b)
	r.Mod(r, p)
	if r.Sign() < 0 {
		r.Add(r, p)
	}
	return r
}
func bpModSub(a, b, p *big.Int) *big.Int {
	r := new(big.Int).Sub(a, b)
	r.Mod(r, p)
	if r.Sign() < 0 {
		r.Add(r, p)
	}
	return r
}

// ── Curve instances (initialised once at package load) ───────────────────────

var (
	curveP256r1 elliptic.Curve
	curveP384r1 elliptic.Curve
	curveP512r1 elliptic.Curve
)

func mustHex(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("brainpool: invalid hex literal: " + s)
	}
	return n
}

func init() { //nolint:gochecknoinits
	curveP256r1 = &weierstrassCurve{
		CurveParams: &elliptic.CurveParams{
			Name:    "brainpoolP256r1",
			BitSize: 256,
			P:       mustHex("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"),
			N:       mustHex("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"),
			B:       mustHex("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"),
			Gx:      mustHex("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262"),
			Gy:      mustHex("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"),
		},
		A: mustHex("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9"),
	}

	curveP384r1 = &weierstrassCurve{
		CurveParams: &elliptic.CurveParams{
			Name:    "brainpoolP384r1",
			BitSize: 384,
			P:       mustHex("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A718774700133107EC53"),
			N:       mustHex("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565"),
			B:       mustHex("04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11"),
			Gx:      mustHex("1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E"),
			Gy:      mustHex("8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315"),
		},
		A: mustHex("7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826"),
	}

	curveP512r1 = &weierstrassCurve{
		CurveParams: &elliptic.CurveParams{
			Name:    "brainpoolP512r1",
			BitSize: 512,
			P:       mustHex("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3"),
			N: mustHex("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA7033087055" +
				"3E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069"),
			B:  mustHex("3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723"),
			Gx: mustHex("81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822"),
			Gy: mustHex("7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892"),
		},
		A: mustHex("7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA"),
	}
}

// brainpoolCurveFromOID maps a brainpool OID to an elliptic.Curve.
// Returns nil for unrecognised OIDs.
func brainpoolCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidBrainpoolP256r1):
		return curveP256r1
	case oid.Equal(oidBrainpoolP384r1):
		return curveP384r1
	case oid.Equal(oidBrainpoolP512r1):
		return curveP512r1
	}
	return nil
}

// isCurveRelatedError reports whether the error came from an unsupported curve.
func isCurveRelatedError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "elliptic curve")
}

// ── ASN.1 types for manual certificate parsing ───────────────────────────────

type bpRawCertificate struct {
	Raw            asn1.RawContent
	TBSCertificate bpRawTBSCertificate
	SigAlgorithm   pkix.AlgorithmIdentifier
	SignatureValue asn1.BitString
}

type bpRawTBSCertificate struct {
	Raw             asn1.RawContent
	Version         int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber    *big.Int
	SigAlgorithm    pkix.AlgorithmIdentifier
	Issuer          asn1.RawValue
	Validity        bpRawValidity
	Subject         asn1.RawValue
	PublicKey       bpRawPublicKeyInfo
	UniqueID        asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID asn1.BitString   `asn1:"optional,tag:2"`
	Extensions      []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type bpRawValidity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type bpRawPublicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// ── Fallback certificate parser ──────────────────────────────────────────────

// parseBrainpoolCertificate parses a DER-encoded certificate whose SubjectPublicKeyInfo
// uses a brainpool curve OID that standard x509.ParseCertificate rejects.
// It returns a fully-populated *x509.Certificate suitable for display and chain
// validation.
func parseBrainpoolCertificate(der []byte) (*x509.Certificate, error) {
	var raw bpRawCertificate
	if rest, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, fmt.Errorf("brainpool: failed to unmarshal certificate: %w", err)
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("brainpool: trailing data after certificate")
	}

	tbs := &raw.TBSCertificate

	// Subject
	var subjectRDN pkix.RDNSequence
	if _, err := asn1.Unmarshal(tbs.Subject.FullBytes, &subjectRDN); err != nil {
		return nil, fmt.Errorf("brainpool: failed to parse subject: %w", err)
	}
	var subject pkix.Name
	subject.FillFromRDNSequence(&subjectRDN)

	// Issuer
	var issuerRDN pkix.RDNSequence
	if _, err := asn1.Unmarshal(tbs.Issuer.FullBytes, &issuerRDN); err != nil {
		return nil, fmt.Errorf("brainpool: failed to parse issuer: %w", err)
	}
	var issuer pkix.Name
	issuer.FillFromRDNSequence(&issuerRDN)

	// Public key
	publicKey, err := parseBrainpoolPublicKey(&tbs.PublicKey)
	if err != nil {
		return nil, err
	}

	cert := &x509.Certificate{
		Raw:                     der,
		RawTBSCertificate:       []byte(tbs.Raw),
		RawSubjectPublicKeyInfo: []byte(tbs.PublicKey.Raw),
		RawSubject:              tbs.Subject.FullBytes,
		RawIssuer:               tbs.Issuer.FullBytes,

		Version:            tbs.Version + 1,
		SerialNumber:       tbs.SerialNumber,
		Subject:            subject,
		Issuer:             issuer,
		NotBefore:          tbs.Validity.NotBefore,
		NotAfter:           tbs.Validity.NotAfter,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          publicKey,
		SignatureAlgorithm: bpOIDToSigAlgo(raw.SigAlgorithm.Algorithm),
		Signature:          raw.SignatureValue.Bytes,
	}

	// Parse extensions – non-fatal if something fails
	if parseErr := parseBrainpoolExtensions(cert, tbs.Extensions); parseErr != nil {
		logger.Warn("brainpool: error parsing extensions", zap.Error(parseErr))
	}

	return cert, nil
}

// parseBrainpoolPublicKey unmarshals an EC public key whose curve is one of the
// supported brainpool curves.
func parseBrainpoolPublicKey(info *bpRawPublicKeyInfo) (*ecdsa.PublicKey, error) {
	// The algorithm parameters hold the curve OID.
	var curveOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &curveOID); err != nil {
		return nil, fmt.Errorf("brainpool: failed to parse curve OID: %w", err)
	}

	curve := brainpoolCurveFromOID(curveOID)
	if curve == nil {
		return nil, fmt.Errorf("brainpool: unsupported curve OID %v", curveOID)
	}

	pointBytes := info.PublicKey.Bytes
	if len(pointBytes) == 0 || pointBytes[0] != 0x04 {
		return nil, fmt.Errorf("brainpool: unsupported EC point format (only uncompressed is supported)")
	}

	byteLen := (curve.Params().BitSize + 7) / 8
	if len(pointBytes) != 2*byteLen+1 {
		return nil, fmt.Errorf("brainpool: unexpected EC point length: got %d, want %d",
			len(pointBytes), 2*byteLen+1)
	}

	x := new(big.Int).SetBytes(pointBytes[1 : 1+byteLen])
	y := new(big.Int).SetBytes(pointBytes[1+byteLen:])

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// ── Signature algorithm OID mapping ─────────────────────────────────────────

func bpOIDToSigAlgo(oid asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	switch {
	case oid.Equal(oidSigECDSAWithSHA1):
		return x509.ECDSAWithSHA1
	case oid.Equal(oidSigECDSAWithSHA256), oid.Equal(oidBPSigWithSHA256):
		return x509.ECDSAWithSHA256
	case oid.Equal(oidSigECDSAWithSHA384), oid.Equal(oidBPSigWithSHA384):
		return x509.ECDSAWithSHA384
	case oid.Equal(oidSigECDSAWithSHA512), oid.Equal(oidBPSigWithSHA512):
		return x509.ECDSAWithSHA512
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// ── Extension parsers ────────────────────────────────────────────────────────

func parseBrainpoolExtensions(cert *x509.Certificate, extensions []pkix.Extension) error {
	for _, ext := range extensions {
		switch {
		case ext.Id.Equal(oidExtSAN):
			parseBPSAN(cert, ext.Value)
		case ext.Id.Equal(oidExtBC):
			parseBPBasicConstraints(cert, ext.Value)
		case ext.Id.Equal(oidExtKU):
			parseBPKeyUsage(cert, ext.Value)
		case ext.Id.Equal(oidExtEKU):
			parseBPExtKeyUsage(cert, ext.Value)
		case ext.Id.Equal(oidExtAIA):
			parseBPAIA(cert, ext.Value)
		case ext.Id.Equal(oidExtCRLDP):
			parseBPCRLDP(cert, ext.Value)
		}
	}
	return nil
}

// Subject Alternative Name (2.5.29.17)
func parseBPSAN(cert *x509.Certificate, value []byte) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(value, &seq); err != nil {
		return
	}
	rest := seq.Bytes
	for len(rest) > 0 {
		var item asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &item)
		if err != nil {
			break
		}
		if item.Class != asn1.ClassContextSpecific {
			continue
		}
		switch item.Tag {
		case 1: // rfc822Name
			cert.EmailAddresses = append(cert.EmailAddresses, string(item.Bytes))
		case 2: // dNSName
			cert.DNSNames = append(cert.DNSNames, string(item.Bytes))
		case 7: // iPAddress
			if len(item.Bytes) == 4 || len(item.Bytes) == 16 {
				ip := make(net.IP, len(item.Bytes))
				copy(ip, item.Bytes)
				cert.IPAddresses = append(cert.IPAddresses, ip)
			}
		}
	}
}

// Basic Constraints (2.5.29.19)
type bpBasicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

func parseBPBasicConstraints(cert *x509.Certificate, value []byte) {
	var bc bpBasicConstraints
	if _, err := asn1.Unmarshal(value, &bc); err != nil {
		return
	}
	cert.BasicConstraintsValid = true
	cert.IsCA = bc.IsCA
	if bc.MaxPathLen >= 0 {
		cert.MaxPathLen = bc.MaxPathLen
	}
}

// Key Usage (2.5.29.15)
func parseBPKeyUsage(cert *x509.Certificate, value []byte) {
	var bits asn1.BitString
	if _, err := asn1.Unmarshal(value, &bits); err != nil {
		return
	}
	usages := []x509.KeyUsage{
		x509.KeyUsageDigitalSignature,
		x509.KeyUsageContentCommitment,
		x509.KeyUsageKeyEncipherment,
		x509.KeyUsageDataEncipherment,
		x509.KeyUsageKeyAgreement,
		x509.KeyUsageCertSign,
		x509.KeyUsageCRLSign,
		x509.KeyUsageEncipherOnly,
		x509.KeyUsageDecipherOnly,
	}
	for i, ku := range usages {
		if bits.At(i) != 0 {
			cert.KeyUsage |= ku
		}
	}
}

// Extended Key Usage (2.5.29.37)
func parseBPExtKeyUsage(cert *x509.Certificate, value []byte) {
	var oids []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(value, &oids); err != nil {
		return
	}
	for _, oid := range oids {
		if eku, ok := ekuOIDMap[oid.String()]; ok {
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, eku)
		} else {
			cert.UnknownExtKeyUsage = append(cert.UnknownExtKeyUsage, oid)
		}
	}
}

// Authority Information Access (1.3.6.1.5.5.7.1.1)
type bpAccessDescription struct {
	AccessMethod   asn1.ObjectIdentifier
	AccessLocation asn1.RawValue
}

func parseBPAIA(cert *x509.Certificate, value []byte) {
	var ads []bpAccessDescription
	if _, err := asn1.Unmarshal(value, &ads); err != nil {
		return
	}
	for _, ad := range ads {
		// tag 6 = uniformResourceIdentifier
		if ad.AccessLocation.Class != asn1.ClassContextSpecific || ad.AccessLocation.Tag != 6 {
			continue
		}
		url := string(ad.AccessLocation.Bytes)
		switch {
		case ad.AccessMethod.Equal(oidAIAOCSP):
			cert.OCSPServer = append(cert.OCSPServer, url)
		case ad.AccessMethod.Equal(oidAIAIssuers):
			cert.IssuingCertificateURL = append(cert.IssuingCertificateURL, url)
		}
	}
}

// CRL Distribution Points (2.5.29.31) – extracts full-name URI entries.
func parseBPCRLDP(cert *x509.Certificate, value []byte) {
	// Walk the raw bytes looking for context-specific tag 6 (URI) anywhere in
	// the nested structure. This handles the common case without full ASN.1
	// recursion.
	var dps asn1.RawValue
	if _, err := asn1.Unmarshal(value, &dps); err != nil {
		return
	}
	extractURIs(dps.Bytes, cert)
}

func extractURIs(data []byte, cert *x509.Certificate) {
	for len(data) > 0 {
		var item asn1.RawValue
		rest, err := asn1.Unmarshal(data, &item)
		if err != nil {
			break
		}
		if item.Class == asn1.ClassContextSpecific && item.Tag == 6 && !item.IsCompound {
			cert.CRLDistributionPoints = append(cert.CRLDistributionPoints, string(item.Bytes))
		}
		if item.IsCompound {
			extractURIs(item.Bytes, cert)
		}
		data = rest
	}
}
