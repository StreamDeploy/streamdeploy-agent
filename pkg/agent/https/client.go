package https

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// Client implements the HTTPClient interface with full TLS support
type Client struct {
	baseURL    string
	httpClient *http.Client
	caCertPath string
	certPath   string
	keyPath    string
}

// NewClient creates a new HTTPS client with mTLS support
func NewClient(baseURL, caCertPath, certPath, keyPath string) (types.HTTPClient, error) {
	client := &Client{
		baseURL:    baseURL,
		caCertPath: caCertPath,
		certPath:   certPath,
		keyPath:    keyPath,
	}

	if err := client.setupTLSConfig(); err != nil {
		return nil, fmt.Errorf("failed to setup TLS config: %w", err)
	}

	return client, nil
}

// setupTLSConfig configures the TLS settings for mTLS
func (c *Client) setupTLSConfig() error {
	// Load client certificate and key
	cert, err := tls.LoadX509KeyPair(c.certPath, c.keyPath)
	if err != nil {
		return fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Load CA certificate
	caCert, err := os.ReadFile(c.caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	// Create HTTP client with custom transport
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	c.httpClient = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return nil
}

// UpdateCertificates updates the client certificates
func (c *Client) UpdateCertificates(caCertPath, certPath, keyPath string) error {
	c.caCertPath = caCertPath
	c.certPath = certPath
	c.keyPath = keyPath
	return c.setupTLSConfig()
}

// SendHeartbeat sends a heartbeat message
func (c *Client) SendHeartbeat(payload *types.HeartbeatPayload, deviceID string) (*types.HTTPResponse, error) {
	url := fmt.Sprintf("%s/v1-device/heartbeat", c.baseURL)

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal heartbeat payload: %w", err)
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"x-device-id":  deviceID,
		"User-Agent":   "StreamDeploy-Agent/1.0",
	}

	return c.Post(url, data, headers)
}

// SendStatusUpdate sends a status update message
func (c *Client) SendStatusUpdate(payload *types.StatusUpdatePayload, deviceID string) (*types.HTTPResponse, error) {
	url := fmt.Sprintf("%s/v1-device/status", c.baseURL)

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal status update payload: %w", err)
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"x-device-id":  deviceID,
		"User-Agent":   "StreamDeploy-Agent/1.0",
	}

	return c.Post(url, data, headers)
}

// Post sends a POST request
func (c *Client) Post(url string, data []byte, headers map[string]string) (*types.HTTPResponse, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Convert headers
	responseHeaders := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			responseHeaders[key] = values[0]
		}
	}

	return &types.HTTPResponse{
		StatusCode: resp.StatusCode,
		Body:       body,
		Headers:    responseHeaders,
	}, nil
}

// Get sends a GET request
func (c *Client) Get(url string, headers map[string]string) (*types.HTTPResponse, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Convert headers
	responseHeaders := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			responseHeaders[key] = values[0]
		}
	}

	return &types.HTTPResponse{
		StatusCode: resp.StatusCode,
		Body:       body,
		Headers:    responseHeaders,
	}, nil
}
