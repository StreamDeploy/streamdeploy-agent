package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// Manager implements the CertificateManager interface
type Manager struct {
	pkiDir     string
	deviceID   string
	httpClient types.HTTPClient
	logger     types.Logger
}

// NewManager creates a new certificate manager
func NewManager(pkiDir, deviceID string, httpClient types.HTTPClient, logger types.Logger) *Manager {
	return &Manager{
		pkiDir:     pkiDir,
		deviceID:   deviceID,
		httpClient: httpClient,
		logger:     logger,
	}
}

// GetCertificateInfo returns information about the current certificate
func (m *Manager) GetCertificateInfo() (*types.CertificateInfo, error) {
	certPath := m.GetCertificatePath()
	keyPath := m.GetPrivateKeyPath()
	caCertPath := m.GetCACertificatePath()

	// Check if certificate file exists
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("certificate file not found: %s", certPath)
	}

	// Get certificate expiration using openssl
	cmd := exec.Command("openssl", "x509", "-in", certPath, "-noout", "-dates")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate dates: %w", err)
	}

	// Parse the output to get expiration date
	lines := strings.Split(string(output), "\n")
	var expiresAt time.Time
	for _, line := range lines {
		if strings.HasPrefix(line, "notAfter=") {
			dateStr := strings.TrimPrefix(line, "notAfter=")
			// Parse the date format: "Jan  2 15:04:05 2006 GMT"
			expiresAt, err = time.Parse("Jan  2 15:04:05 2006 MST", dateStr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse expiration date: %w", err)
			}
			break
		}
	}

	return &types.CertificateInfo{
		CertPath:   certPath,
		KeyPath:    keyPath,
		CACertPath: caCertPath,
		ExpiresAt:  expiresAt,
	}, nil
}

// IsCertificateExpiringSoon checks if the certificate expires within the specified number of days
func (m *Manager) IsCertificateExpiringSoon(days int) bool {
	certInfo, err := m.GetCertificateInfo()
	if err != nil {
		m.logger.Errorf("Failed to get certificate info: %v", err)
		return true // Assume expiring if we can't check
	}

	threshold := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	return certInfo.ExpiresAt.Before(threshold)
}

// RenewCertificate renews the certificate using the enrollment endpoint
func (m *Manager) RenewCertificate(deviceID, enrollEndpoint string) error {
	m.logger.Info("Starting certificate renewal process")

	// Generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create a certificate signing request
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: deviceID,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	// Encode CSR to PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	// Base64 encode the CSR
	csrBase64 := base64.StdEncoding.EncodeToString(csrPEM)

	// Prepare the request payload
	requestPayload := map[string]string{
		"csr_base64": csrBase64,
	}

	requestData, err := json.Marshal(requestPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal request payload: %w", err)
	}

	// Send the renewal request
	renewalURL := fmt.Sprintf("%s/v1-device/enroll/renew", enrollEndpoint)
	headers := map[string]string{
		"Content-Type": "application/json",
		"x-device-id":  deviceID,
		"User-Agent":   "StreamDeploy-Agent/1.0",
	}

	response, err := m.httpClient.Post(renewalURL, requestData, headers)
	if err != nil {
		return fmt.Errorf("failed to send renewal request: %w", err)
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// Parse error response
		var errorResponse struct {
			Detail []struct {
				Loc  []interface{} `json:"loc"`
				Msg  string        `json:"msg"`
				Type string        `json:"type"`
			} `json:"detail"`
		}

		if err := json.Unmarshal(response.Body, &errorResponse); err == nil && len(errorResponse.Detail) > 0 {
			return fmt.Errorf("certificate renewal failed: %s", errorResponse.Detail[0].Msg)
		}
		return fmt.Errorf("certificate renewal failed with status %d: %s", response.StatusCode, string(response.Body))
	}

	// Parse successful response
	var renewalResponse struct {
		CertPEM  string    `json:"cert_pem"`
		Chain    []string  `json:"chain"`
		NotAfter time.Time `json:"not_after"`
	}

	if err := json.Unmarshal(response.Body, &renewalResponse); err != nil {
		return fmt.Errorf("failed to parse renewal response: %w", err)
	}

	// Save the new private key
	if err := m.savePrivateKey(privateKey); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Save the new certificate
	if err := m.saveCertificate(renewalResponse.CertPEM); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	// Save the certificate chain
	if err := m.saveCertificateChain(renewalResponse.Chain); err != nil {
		return fmt.Errorf("failed to save certificate chain: %w", err)
	}

	m.logger.Infof("Certificate renewed successfully, expires at: %v", renewalResponse.NotAfter)
	return nil
}

// GetCACertificatePath returns the path to the CA certificate
func (m *Manager) GetCACertificatePath() string {
	return filepath.Join(m.pkiDir, "ca.pem")
}

// GetCertificatePath returns the path to the client certificate
func (m *Manager) GetCertificatePath() string {
	return filepath.Join(m.pkiDir, "client.pem")
}

// GetPrivateKeyPath returns the path to the private key
func (m *Manager) GetPrivateKeyPath() string {
	return filepath.Join(m.pkiDir, "client-key.pem")
}

// savePrivateKey saves the private key to disk
func (m *Manager) savePrivateKey(key *rsa.PrivateKey) error {
	keyPath := m.GetPrivateKeyPath()

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return fmt.Errorf("failed to create PKI directory: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// saveCertificate saves the certificate to disk
func (m *Manager) saveCertificate(certPEM string) error {
	certPath := m.GetCertificatePath()

	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	return nil
}

// saveCertificateChain saves the certificate chain to disk
func (m *Manager) saveCertificateChain(chain []string) error {
	if len(chain) == 0 {
		return nil // No chain to save
	}

	// Save the chain as ca.pem (assuming the chain contains the CA certificates)
	caCertPath := m.GetCACertificatePath()

	var chainPEM strings.Builder
	for _, cert := range chain {
		chainPEM.WriteString(cert)
		if !strings.HasSuffix(cert, "\n") {
			chainPEM.WriteString("\n")
		}
	}

	if err := os.WriteFile(caCertPath, []byte(chainPEM.String()), 0644); err != nil {
		return fmt.Errorf("failed to write certificate chain: %w", err)
	}

	return nil
}
