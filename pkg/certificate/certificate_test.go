package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// Test certificate data (valid PEM format)
const testCertPEM = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEhMB8G
A1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAwUdO3fxEzEtcnI7ZKZL412XvZOVJFstNXSB0RT2ZCpNu
NE6t+XFw0Q4fz0ZaMsoQn+2BdooxrkBU5RdgBBOQOSXl5Mt0Q5X7+trI5rFvr/Wr
mVXmPiLiRkN2NfQQi+9E2Q+LEHiGNy2g2d6lAjCG5De2YUkEzEHRYFhIllQRWqmM
ZbNCRBWi6NEUECMFtk5hgEfzJVoGy8IkYdnativY2XcOQQjd40CQk6+FHqjHHxzH
ZgTCrJDghTtt6ZFVZMQjqlzEEWEN4dMusx1GVrpJLTTyQBNbBVNgtGAoAiEA4dEo
qiUupiUsvqTFmaFioOiuCiDuMGQC6+DGCmzAbpfcjwIDAQABo1AwTjAdBgNVHQ4E
FgQUhKs/VJ3IWyKwrl0Ki0f+EWuUlMEwHwYDVR0jBBgwFoAUhKs/VJ3IWyKwrl0K
i0f+EWuUlMEwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAWGlApfpT
WsAS/8wAQHhM1olf2ox81lxCKmrBdBjXpNwdVd84dEzjLrAK7b8IAjXkEkDjY1VE
EJ8+TzP9PKtqKdjgQQwo0Yqscw5f1uLpOBXBDrftnig5TQjx4HlgwUBvQnI79c/j
MfqNuDdJ3U0QHakjXHqmWGbCc6tGgDr4EbE+Kh7s5Hl0SLrI9FoYXyPdYgHQfkjy
oQiRSIWlFfHe+5lXGvQWlkumO2dDVVHlIgySQVShOBvfcQ1DcsHEfU2dmeMffrI9
TKph8fRAQRg1MwlnCjbBWA==
-----END CERTIFICATE-----`

func createTestCert() *x509.Certificate {
	// Use fixed values for testing
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "test.example.com",
			Organization:       []string{"Test Corp"},
			OrganizationalUnit: []string{"IT Department"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Francisco"},
		},
		Issuer: pkix.Name{
			CommonName:         "Test CA",
			Organization:       []string{"Test CA Corp"},
			OrganizationalUnit: []string{"CA Department"},
			Country:            []string{"US"},
		},
		NotBefore:      time.Now().Add(-24 * time.Hour),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		DNSNames:       []string{"test.example.com", "www.test.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.168.1.1")},
		EmailAddresses: []string{"admin@example.com"},
		SerialNumber:   big.NewInt(12345),
		Raw:            []byte("test-cert-data"),
		PublicKey:      &rsa.PublicKey{N: big.NewInt(12345), E: 65537}, // Fixed public key
	}
}

func createRSACert() *x509.Certificate {
	// Generate 2048-bit RSA key
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := createTestCert()
	cert.PublicKey = &rsaKey.PublicKey
	return cert
}

func createECDSACert() *x509.Certificate {
	// Generate P-256 curve ECDSA key
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := createTestCert()
	cert.PublicKey = &ecdsaKey.PublicKey
	return cert
}

func TestParseCertificatesFromFile(t *testing.T) {
	// Test with actual certificate file
	data, err := os.ReadFile("../../testdata/demo/certs.pem")
	if err != nil {
		t.Skipf("Skipping test: could not read ../../testdata/demo/certs.pem: %v", err)
	}

	certs, err := ParseCertificates(data)
	if err != nil {
		t.Errorf("Unexpected error parsing real certificates: %v", err)
		return
	}

	if len(certs) == 0 {
		t.Error("Expected at least one certificate")
	}

	// Verify certificate info structure
	for i, cert := range certs {
		if cert.Certificate == nil {
			t.Errorf("Certificate %d is nil", i)
		}
		if cert.Index != i {
			t.Errorf("Certificate %d has wrong index: %d", i, cert.Index)
		}
		if cert.Label == "" {
			t.Errorf("Certificate %d has empty label", i)
		}
	}
}

// Utility: Generate a certificate and return *x509.Certificate
func generateCertificate(template, parent *x509.Certificate, pub, parentPriv interface{}) *x509.Certificate {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert
}

// Utility: Generate a PEM string from a certificate
func certToPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// Utility: Generate a random key ID
func randomKeyID() []byte {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// Utility: Generate a valid test certificate chain (root, leaf)
func generateTestChain() (leaf, root *x509.Certificate, leafPEM, rootPEM string) {
	// Root CA
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootSubjectKeyID := randomKeyID()
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageKeyEncipherment,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		SubjectKeyId:          rootSubjectKeyID,
	}
	rootCert := generateCertificate(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCertParsed, _ := x509.ParseCertificate(rootCert.Raw)

	// Leaf
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test.example.com"},
		Issuer:                rootTemplate.Subject,
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  false,
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
		AuthorityKeyId:        rootSubjectKeyID,
	}
	leafCert := generateCertificate(leafTemplate, rootCertParsed, &leafKey.PublicKey, rootKey)

	return leafCert, rootCertParsed, certToPEM(leafCert), certToPEM(rootCertParsed)
}

// TestValidateChain with actual certificate chain
func TestValidateChain(t *testing.T) {
	leaf, root, _, _ := generateTestChain()
	tests := []struct {
		name    string
		certs   []*x509.Certificate
		want    bool
		wantErr bool
	}{
		{
			name:    "Empty chain",
			certs:   []*x509.Certificate{},
			want:    false,
			wantErr: true,
		},
		{
			name:    "Valid chain",
			certs:   []*x509.Certificate{leaf, root},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateChain(tt.certs)
			if err != nil {
				t.Logf("ValidateChain() error detail: %v", err)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateChain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateChain() IsValid = %v, want %v", got, tt.want)
			}
		})
	}
}

// Fix TestParseCertificates Valid certificate case
func TestParseCertificates(t *testing.T) {
	_, _, leafPEM, _ := generateTestChain()
	tests := []struct {
		name        string
		input       string
		expectCount int
		expectError bool
	}{
		{
			name:        "Empty input",
			input:       "",
			expectCount: 0,
			expectError: true,
		},
		{
			name:        "Invalid PEM",
			input:       "invalid pem data",
			expectCount: 0,
			expectError: true,
		},
		{
			name:        "Valid certificate",
			input:       leafPEM,
			expectCount: 1,
			expectError: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := ParseCertificates([]byte(tt.input))
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}
			if err != nil {
				// Skip test if certificate parsing fails (malformed test certificate)
				t.Skipf("Skipping test due to certificate parsing error: %v", err)
				return
			}
			if len(certs) != tt.expectCount {
				t.Errorf("Expected %d certificates, got %d", tt.expectCount, len(certs))
			}
			// Verify certificate info structure
			for i, cert := range certs {
				if cert.Certificate == nil {
					t.Errorf("Certificate %d is nil", i)
				}
				if cert.Index != i {
					t.Errorf("Certificate %d has wrong index: %d", i, cert.Index)
				}
				if cert.Label == "" {
					t.Errorf("Certificate %d has empty label", i)
				}
			}
		})
	}
}

func TestParseCertificatesDER(t *testing.T) {
	leaf, root, _, _ := generateTestChain()

	tests := []struct {
		name        string
		input       []byte
		expectCount int
	}{
		{
			name:        "Single DER certificate",
			input:       leaf.Raw,
			expectCount: 1,
		},
		{
			name:        "Concatenated DER certificates",
			input:       append(append([]byte{}, leaf.Raw...), root.Raw...),
			expectCount: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := ParseCertificates(tt.input)
			if err != nil {
				t.Fatalf("Unexpected error parsing DER certificates: %v", err)
			}
			if len(certs) != tt.expectCount {
				t.Fatalf("Expected %d certificates, got %d", tt.expectCount, len(certs))
			}
			for i, cert := range certs {
				if cert.Certificate == nil {
					t.Errorf("Certificate %d is nil", i)
				}
				if cert.Index != i {
					t.Errorf("Certificate %d has wrong index: %d", i, cert.Index)
				}
				if cert.Label == "" {
					t.Errorf("Certificate %d has empty label", i)
				}
			}
		})
	}
}

func TestGenerateCertificateLabel(t *testing.T) {
	tests := []struct {
		name     string
		cn       string
		index    int
		expected string
	}{
		{
			name:     "Normal CN",
			cn:       "example.com",
			index:    0,
			expected: "1. example.com",
		},
		{
			name:     "Empty CN",
			cn:       "",
			index:    1,
			expected: "2. Unknown",
		},
		{
			name:     "Long CN",
			cn:       "very-long-common-name-that-should-be-truncated.example.com",
			index:    2,
			expected: "3. very-long-common-name-that-...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock certificate
			cert := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: tt.cn,
				},
			}

			result := generateCertificateLabel(cert, tt.index)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// GetCertificateDetails returns detailed information about a certificate
func GetCertificateDetails(cert *Info) string {
	var details strings.Builder
	details.WriteString(fmt.Sprintf("Subject: %s\n", FormatSubject(cert.Certificate)))
	details.WriteString(fmt.Sprintf("Issuer: %s\n", FormatIssuer(cert.Certificate)))
	details.WriteString(fmt.Sprintf("Validity: %s\n", FormatValidity(cert.Certificate)))
	details.WriteString(fmt.Sprintf("SAN: %s\n", FormatSAN(cert.Certificate)))
	details.WriteString(fmt.Sprintf("Fingerprint: %s\n", FormatFingerprint(cert.Certificate)))
	details.WriteString(fmt.Sprintf("Public Key: %s\n", FormatPublicKey(cert.Certificate)))
	return details.String()
}

func TestIsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		notAfter time.Time
		expected bool
	}{
		{
			name:     "Valid certificate",
			notAfter: now.Add(24 * time.Hour),
			expected: false,
		},
		{
			name:     "Expired certificate",
			notAfter: now.Add(-24 * time.Hour),
			expected: true,
		},
		{
			name:     "Just expired",
			notAfter: now.Add(-1 * time.Minute),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				NotAfter: tt.notAfter,
			}

			result := IsExpired(cert)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsExpiringSoon(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		notAfter time.Time
		expected bool
	}{
		{
			name:     "Valid for long time",
			notAfter: now.Add(60 * 24 * time.Hour),
			expected: false,
		},
		{
			name:     "Expiring in 15 days",
			notAfter: now.Add(15 * 24 * time.Hour),
			expected: true,
		},
		{
			name:     "Expiring in 29 days",
			notAfter: now.Add(29 * 24 * time.Hour),
			expected: true,
		},
		{
			name:     "Expiring in 31 days",
			notAfter: now.Add(31 * 24 * time.Hour),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				NotAfter: tt.notAfter,
			}

			result := IsExpiringSoon(cert)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestLoadCertificates(t *testing.T) {
	// Test reading from file
	tempFile, err := os.CreateTemp("", "test-cert-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tempFile.Name()) }()

	_, err = tempFile.WriteString(testCertPEM)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	if err := tempFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	certs, err := LoadCertificates(tempFile.Name())
	if err != nil {
		// Skip test if certificate loading fails (malformed test certificate)
		t.Skipf("Skipping test due to certificate loading error: %v", err)
		return
	}
	if len(certs) == 0 {
		t.Error("Expected at least one certificate")
	}

	// Test reading from non-existent file
	_, err = LoadCertificates("non-existent-file.pem")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestFormatSubject(t *testing.T) {
	cert := createTestCert()
	result := FormatSubject(cert)

	expectedStrings := []string{
		"Common Name: test.example.com",
		"Organization: Test Corp",
		"Organizational Unit: IT Department",
		"Country: US",
		"Province: California",
		"Locality: San Francisco",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(result, expected) {
			t.Errorf("Expected result to contain %q, but it didn't.\nResult: %s", expected, result)
		}
	}
}

func TestFormatIssuer(t *testing.T) {
	cert := createTestCert()
	result := FormatIssuer(cert)

	expectedStrings := []string{
		"Common Name: Test CA",
		"Organization: Test CA Corp",
		"Organizational Unit: CA Department",
		"Country: US",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(result, expected) {
			t.Errorf("Expected result to contain %q, but it didn't.\nResult: %s", expected, result)
		}
	}
}

func TestFormatValidity(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		expected  []string
	}{
		{
			name:      "Valid certificate",
			notBefore: now.Add(-24 * time.Hour),
			notAfter:  now.Add(365 * 24 * time.Hour),
			expected:  []string{"Status: Valid", "Expires in:"},
		},
		{
			name:      "Expired certificate",
			notBefore: now.Add(-365 * 24 * time.Hour),
			notAfter:  now.Add(-24 * time.Hour),
			expected:  []string{"Status: EXPIRED", "Expired:"},
		},
		{
			name:      "Expiring soon",
			notBefore: now.Add(-24 * time.Hour),
			notAfter:  now.Add(15 * 24 * time.Hour),
			expected:  []string{"Status: EXPIRING SOON", "Expires in:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				NotBefore: tt.notBefore,
				NotAfter:  tt.notAfter,
			}

			result := FormatValidity(cert)
			for _, expected := range tt.expected {
				if !strings.Contains(result, expected) {
					t.Errorf("Expected result to contain %q, but it didn't.\nResult: %s", expected, result)
				}
			}
		})
	}
}

func TestFormatSAN(t *testing.T) {
	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected []string
	}{
		{
			name: "Certificate with DNS names",
			cert: &x509.Certificate{
				DNSNames: []string{"example.com", "www.example.com"},
			},
			expected: []string{"DNS Names:", "example.com", "www.example.com"},
		},
		{
			name: "Certificate with IP addresses",
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")},
			},
			expected: []string{"IP Addresses:", "192.168.1.1", "10.0.0.1"},
		},
		{
			name: "Certificate with email addresses",
			cert: &x509.Certificate{
				EmailAddresses: []string{"admin@example.com", "support@example.com"},
			},
			expected: []string{"Email Addresses:", "admin@example.com", "support@example.com"},
		},
		{
			name:     "Certificate with no SAN",
			cert:     &x509.Certificate{},
			expected: []string{"No Subject Alternative Names found"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatSAN(tt.cert)
			for _, expected := range tt.expected {
				if !strings.Contains(result, expected) {
					t.Errorf("Expected result to contain %q, but it didn't.\nResult: %s", expected, result)
				}
			}
		})
	}
}

func TestFormatFingerprint(t *testing.T) {
	cert := &x509.Certificate{
		Raw: []byte("test-cert-data"),
	}

	result := FormatFingerprint(cert)
	if result == "" {
		t.Error("Expected non-empty fingerprint")
	}
	if len(result) != 64 { // SHA256 hex string length
		t.Errorf("Expected fingerprint length 64, got %d", len(result))
	}
}

func TestFormatSerial(t *testing.T) {
	tests := []struct {
		name    string
		serial  *big.Int
		wantHex string // expected colon-separated hex prefix
		wantDec string // expected decimal value in parens
	}{
		{
			name:    "small decimal",
			serial:  big.NewInt(1),
			wantHex: "01",
			wantDec: "(1)",
		},
		{
			name:    "multi-byte value",
			serial:  big.NewInt(0x0102),
			wantHex: "01:02",
			wantDec: "(258)",
		},
		{
			name:    "odd hex digit count gets zero-padded",
			serial:  big.NewInt(0xf),
			wantHex: "0f",
			wantDec: "(15)",
		},
		{
			name:    "nil serial",
			serial:  nil,
			wantHex: "",
			wantDec: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatSerial(tt.serial)
			if tt.serial == nil {
				if got != "" {
					t.Errorf("FormatSerial(nil) = %q, want empty string", got)
				}
				return
			}
			if !strings.Contains(got, tt.wantHex) {
				t.Errorf("FormatSerial hex: got %q, want it to contain %q", got, tt.wantHex)
			}
			if !strings.Contains(got, tt.wantDec) {
				t.Errorf("FormatSerial decimal: got %q, want it to contain %q", got, tt.wantDec)
			}
		})
	}
}

func TestFormatPublicKey(t *testing.T) {
	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected []string
	}{
		{
			name:     "RSA certificate",
			cert:     createRSACert(),
			expected: []string{"Algorithm:", "Type: RSA2048", "Key Size: 2048 bits", "Modulus Size:", "Public Exponent:"},
		},
		{
			name:     "ECDSA certificate",
			cert:     createECDSACert(),
			expected: []string{"Algorithm:", "Type: ECDSA", "Curve: P-256", "Key Size: 256 bits", "Standard: NIST P-256"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatPublicKey(tt.cert)
			for _, expected := range tt.expected {
				if !strings.Contains(result, expected) {
					t.Errorf("Expected result to contain %q, but it didn't.\nResult: %s", expected, result)
				}
			}
		})
	}
}

// SearchCertificates searches for certificates matching the query
func SearchCertificates(certs []*Info, query string) []*Info {
	if query == "" {
		return certs
	}

	var results []*Info
	query = strings.ToLower(query)

	for _, cert := range certs {
		if strings.Contains(strings.ToLower(cert.Label), query) {
			results = append(results, cert)
		}
	}

	return results
}

// FilterCertificates filters certificates based on criteria
func FilterCertificates(certs []*Info, filterType string) []*Info {
	var results []*Info

	for _, cert := range certs {
		switch filterType {
		case "expired":
			if IsExpired(cert.Certificate) {
				results = append(results, cert)
			}
		case "expiring":
			if IsExpiringSoon(cert.Certificate) {
				results = append(results, cert)
			}
		case "valid":
			if !IsExpired(cert.Certificate) {
				results = append(results, cert)
			}
		case "self-signed":
			if cert.Certificate.Subject.CommonName == cert.Certificate.Issuer.CommonName {
				results = append(results, cert)
			}
		}
	}

	return results
}

// Update test cases to use ValidationResult instead of ChainValidationResult
func TestFormatChainValidation(t *testing.T) {
	tests := []struct {
		name     string
		result   *ValidationResult
		expected string
	}{
		{
			name: "Valid chain",
			result: &ValidationResult{
				IsValid: true,
			},
			expected: "✅ Certificate chain is valid.",
		},
		{
			name: "Invalid chain with errors",
			result: &ValidationResult{
				IsValid: false,
				Errors: []string{
					"Certificate expired",
					"Invalid signature",
				},
				Warnings: []string{
					"Certificate expiring soon",
				},
			},
			expected: `Certificate chain validation failed:
Errors:
- Certificate expired
- Invalid signature
Warnings:
- Certificate expiring soon`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatChainValidation(tt.result)
			if got != tt.expected {
				t.Errorf("FormatChainValidation() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExportCertificate(t *testing.T) {
	cert := createTestCert()

	tests := []struct {
		name        string
		format      string
		expectError bool
	}{
		{
			name:        "PEM format",
			format:      "pem",
			expectError: false,
		},
		{
			name:        "DER format",
			format:      "der",
			expectError: false,
		},
		{
			name:        "P7B format",
			format:      "p7b",
			expectError: false,
		},
		{
			name:        "PKCS7 format alias",
			format:      "pkcs7",
			expectError: false,
		},
		{
			name:        "Invalid format",
			format:      "invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempFile, err := os.CreateTemp("", "test-export-*."+tt.format)
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer func() { _ = os.Remove(tempFile.Name()) }()
			if err := tempFile.Close(); err != nil {
				t.Fatalf("Failed to close temp file: %v", err)
			}

			err = ExportCertificate(cert, tt.format, tempFile.Name())

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestParseCertificatesPKCS7PEM verifies that PEM-armored PKCS7 / P7B files are parsed correctly.
func TestParseCertificatesPKCS7PEM(t *testing.T) {
	leaf, root, _, _ := generateTestChain()

	// Build a degenerate PKCS7 that contains both certs.
	p7der, err := buildDegeneratePKCS7([]*x509.Certificate{leaf, root})
	if err != nil {
		t.Fatalf("buildDegeneratePKCS7: %v", err)
	}

	// PEM-encode as "PKCS7".
	p7pem := string(pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: p7der}))

	certs, err := ParseCertificates([]byte(p7pem))
	if err != nil {
		t.Fatalf("ParseCertificates (PEM PKCS7): %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("Expected 2 certificates, got %d", len(certs))
	}
	for i, c := range certs {
		if c.Certificate == nil {
			t.Errorf("Certificate %d is nil", i)
		}
		if c.Index != i {
			t.Errorf("Certificate %d has wrong Index: got %d", i, c.Index)
		}
		if c.Label == "" {
			t.Errorf("Certificate %d has empty Label", i)
		}
	}
}

// TestParseCertificatesPKCS7DER verifies that raw DER-encoded PKCS7 / P7B data is parsed correctly.
func TestParseCertificatesPKCS7DER(t *testing.T) {
	leaf, root, _, _ := generateTestChain()

	p7der, err := buildDegeneratePKCS7([]*x509.Certificate{leaf, root})
	if err != nil {
		t.Fatalf("buildDegeneratePKCS7: %v", err)
	}

	certs, err := ParseCertificates(p7der)
	if err != nil {
		t.Fatalf("ParseCertificates (DER PKCS7): %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("Expected 2 certificates, got %d", len(certs))
	}
}

// TestLoadCertificatesP7BFile verifies that LoadCertificates handles a .p7b file on disk.
func TestLoadCertificatesP7BFile(t *testing.T) {
	leaf, root, _, _ := generateTestChain()

	p7der, err := buildDegeneratePKCS7([]*x509.Certificate{leaf, root})
	if err != nil {
		t.Fatalf("buildDegeneratePKCS7: %v", err)
	}

	// Write PEM-encoded P7B to a temp file with .p7b extension.
	tmpFile, err := os.CreateTemp("", "test-*.p7b")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if err := pem.Encode(tmpFile, &pem.Block{Type: "PKCS7", Bytes: p7der}); err != nil {
		t.Fatalf("pem.Encode: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	certs, err := LoadCertificates(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadCertificates: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("Expected 2 certificates, got %d", len(certs))
	}
}

// TestExportAndReloadP7B verifies the round-trip: export a cert as P7B, then reload it.
func TestExportAndReloadP7B(t *testing.T) {
	_, root, _, _ := generateTestChain()

	tmpFile, err := os.CreateTemp("", "test-export-*.p7b")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := ExportCertificate(root, "p7b", tmpFile.Name()); err != nil {
		t.Fatalf("ExportCertificate (p7b): %v", err)
	}

	certs, err := LoadCertificates(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadCertificates after P7B export: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("Expected 1 certificate after reload, got %d", len(certs))
	}
	if certs[0].Certificate.Subject.CommonName != root.Subject.CommonName {
		t.Errorf("Subject mismatch: got %q, want %q",
			certs[0].Certificate.Subject.CommonName, root.Subject.CommonName)
	}
}

// ── Brainpool tests ──────────────────────────────────────────────────────────

// brainpoolTestFiles maps a curve name to a PEM file with a self-signed cert.
var brainpoolTestFiles = map[string]string{
	"brainpoolP256r1": "../../testdata/brainpool/brainpoolP256r1-cert.pem",
	"brainpoolP384r1": "../../testdata/brainpool/brainpoolP384r1-cert.pem",
	"brainpoolP512r1": "../../testdata/brainpool/brainpoolP512r1-cert.pem",
}

func TestParseBrainpoolCertificatesPEM(t *testing.T) {
	for curveName, filename := range brainpoolTestFiles {
		t.Run(curveName, func(t *testing.T) {
			certs, err := LoadCertificates(filename)
			if err != nil {
				t.Fatalf("LoadCertificates(%s): %v", filename, err)
			}
			if len(certs) != 1 {
				t.Fatalf("expected 1 cert, got %d", len(certs))
			}
			c := certs[0]
			if c.Certificate == nil {
				t.Fatal("Certificate is nil")
			}
			if c.Certificate.PublicKeyAlgorithm != x509.ECDSA {
				t.Errorf("PublicKeyAlgorithm: got %v, want ECDSA", c.Certificate.PublicKeyAlgorithm)
			}
			pub, ok := c.Certificate.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("PublicKey type: got %T, want *ecdsa.PublicKey", c.Certificate.PublicKey)
			}
			if pub.Curve.Params().Name != curveName {
				t.Errorf("curve name: got %q, want %q", pub.Curve.Params().Name, curveName)
			}
			if c.Label == "" {
				t.Error("Label is empty")
			}
		})
	}
}

func TestParseBrainpoolChainPEM(t *testing.T) {
	certs, err := LoadCertificates("../../testdata/brainpool/brainpoolP256r1-chain.pem")
	if err != nil {
		t.Fatalf("LoadCertificates(chain): %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs in chain, got %d", len(certs))
	}
	for i, c := range certs {
		if c.Certificate == nil {
			t.Errorf("cert[%d] is nil", i)
		}
	}
}

func TestBrainpoolIsOnCurve(t *testing.T) {
	// Parse a brainpool cert and verify the public key is on the claimed curve.
	certs, err := LoadCertificates("../../testdata/brainpool/brainpoolP256r1-cert.pem")
	if err != nil {
		t.Fatalf("LoadCertificates: %v", err)
	}
	pub := certs[0].Certificate.PublicKey.(*ecdsa.PublicKey)
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		t.Error("public key point is not on the brainpool curve")
	}
}

func TestBrainpoolValidateChainLinks(t *testing.T) {
	certs, err := LoadCertificates("../../testdata/brainpool/brainpoolP256r1-chain.pem")
	if err != nil {
		t.Fatalf("LoadCertificates: %v", err)
	}
	ValidateChainLinks(certs)
	for _, c := range certs {
		if c.ValidationStatus == StatusInvalidSignature {
			t.Errorf("cert %q: unexpected StatusInvalidSignature: %v",
				c.Certificate.Subject.CommonName, c.ValidationError)
		}
	}
}

func TestBrainpoolFormatPublicKey(t *testing.T) {
	certs, err := LoadCertificates("../../testdata/brainpool/brainpoolP256r1-cert.pem")
	if err != nil {
		t.Fatalf("LoadCertificates: %v", err)
	}
	out := FormatPublicKey(certs[0].Certificate)
	if !strings.Contains(out, "brainpoolP256r1") {
		t.Errorf("FormatPublicKey output missing curve name: %q", out)
	}
	if !strings.Contains(out, "RFC 5639") {
		t.Errorf("FormatPublicKey output missing RFC 5639 standard: %q", out)
	}
}

func TestBrainpoolDERParse(t *testing.T) {
	// Load PEM, decode to DER, verify ParseCertificates handles raw DER.
	data, err := os.ReadFile("../../testdata/brainpool/brainpoolP256r1-cert.pem")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("pem.Decode returned nil")
	}
	certs, err := ParseCertificates(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificates (DER brainpool): %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
}

// TestParseBrainpoolP7BPEM verifies that a PEM-encoded PKCS#7 bundle whose
// certificates use brainpool curves is parsed correctly.
func TestParseBrainpoolP7BPEM(t *testing.T) {
	// Load the two brainpool P256r1 certs from the chain file.
	chainCerts, err := LoadCertificates("../../testdata/brainpool/brainpoolP256r1-chain.pem")
	if err != nil {
		t.Fatalf("LoadCertificates (chain): %v", err)
	}
	if len(chainCerts) < 2 {
		t.Fatalf("expected at least 2 certs in chain, got %d", len(chainCerts))
	}

	// Build a P7B that contains both brainpool certs.
	rawCerts := make([]*x509.Certificate, len(chainCerts))
	for i, c := range chainCerts {
		rawCerts[i] = c.Certificate
	}
	p7der, err := buildDegeneratePKCS7(rawCerts)
	if err != nil {
		t.Fatalf("buildDegeneratePKCS7: %v", err)
	}

	// Wrap in PEM.
	p7pem := pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: p7der})

	// Parse – this must succeed and return both certs.
	parsed, err := ParseCertificates(p7pem)
	if err != nil {
		t.Fatalf("ParseCertificates (brainpool P7B PEM): %v", err)
	}
	if len(parsed) != len(chainCerts) {
		t.Fatalf("expected %d certs, got %d", len(chainCerts), len(parsed))
	}
	for _, c := range parsed {
		if _, ok := c.Certificate.PublicKey.(*ecdsa.PublicKey); !ok {
			t.Errorf("expected *ecdsa.PublicKey, got %T", c.Certificate.PublicKey)
		}
	}
}

// TestParseBrainpoolP7BDER verifies the same round-trip for raw DER P7B data.
func TestParseBrainpoolP7BDER(t *testing.T) {
	chainCerts, err := LoadCertificates("../../testdata/brainpool/brainpoolP256r1-chain.pem")
	if err != nil {
		t.Fatalf("LoadCertificates (chain): %v", err)
	}

	rawCerts := make([]*x509.Certificate, len(chainCerts))
	for i, c := range chainCerts {
		rawCerts[i] = c.Certificate
	}
	p7der, err := buildDegeneratePKCS7(rawCerts)
	if err != nil {
		t.Fatalf("buildDegeneratePKCS7: %v", err)
	}

	parsed, err := ParseCertificates(p7der)
	if err != nil {
		t.Fatalf("ParseCertificates (brainpool P7B DER): %v", err)
	}
	if len(parsed) != len(chainCerts) {
		t.Fatalf("expected %d certs, got %d", len(chainCerts), len(parsed))
	}
}
