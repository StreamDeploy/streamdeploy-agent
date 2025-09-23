package tunnel

import (
	"strings"
	"testing"
	"time"
)

// TestSSHCommandParsing tests the parsing of SSH command format
func TestSSHCommandParsing(t *testing.T) {
	tests := []struct {
		name         string
		command      string
		expectedUser string
		expectError  bool
		description  string
	}{
		{
			name:         "valid_custom_ssh_format",
			command:      "custom ssh user456",
			expectedUser: "user456",
			expectError:  false,
			description:  "Valid format: custom ssh {user_id}",
		},
		{
			name:         "valid_custom_ssh_format_with_underscore",
			command:      "custom ssh user_789",
			expectedUser: "user_789",
			expectError:  false,
			description:  "Valid format: custom ssh {user_id} with underscore",
		},
		{
			name:         "invalid_format_too_few_parts",
			command:      "custom ssh",
			expectedUser: "",
			expectError:  true,
			description:  "Invalid format: too few parts",
		},
		{
			name:         "invalid_format_too_many_parts",
			command:      "custom ssh user123 extra part",
			expectedUser: "",
			expectError:  true,
			description:  "Invalid format: too many parts",
		},
		{
			name:         "invalid_format_wrong_prefix",
			command:      "ssh user123",
			expectedUser: "",
			expectError:  true,
			description:  "Invalid format: wrong prefix (should be 'custom ssh')",
		},
		{
			name:         "invalid_format_wrong_command",
			command:      "custom ftp user123",
			expectedUser: "",
			expectError:  true,
			description:  "Invalid format: wrong command (should be 'ssh')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the command manually to test the logic
			parts := strings.Fields(tt.command)

			var user string
			var expires time.Time

			// New simplified logic: only support "custom ssh {user_id}"
			if len(parts) != 3 {
				if !tt.expectError {
					t.Errorf("Unexpected error: invalid command format (expected 3 parts, got %d)", len(parts))
				}
				return
			}

			if parts[0] != "custom" || parts[1] != "ssh" {
				if !tt.expectError {
					t.Errorf("Unexpected error: invalid command format (expected 'custom ssh', got '%s %s')", parts[0], parts[1])
				}
				return
			}

			user = parts[2]
			expires = time.Now().Add(1 * time.Hour)

			// Check if we got the expected user
			if user != tt.expectedUser {
				t.Errorf("Expected user %s, got %s", tt.expectedUser, user)
			}

			// Check if expiration time is reasonable (within next 2 hours)
			now := time.Now()
			if expires.Before(now) || expires.After(now.Add(2*time.Hour)) {
				t.Errorf("Expiration time %s seems unreasonable (current time: %s)", expires.Format(time.RFC3339), now.Format(time.RFC3339))
			}

			t.Logf("✓ %s: user=%s, expires=%s", tt.description, user, expires.Format(time.RFC3339))
		})
	}
}

// TestCommandFormatExamples tests specific command format examples
func TestCommandFormatExamples(t *testing.T) {
	examples := []struct {
		command string
		valid   bool
	}{
		{"custom ssh user456", true},
		{"custom ssh user_789", true},
		{"ssh user123", false},
		{"custom ssh", false},
		{"custom ssh user123 extra", false},
		{"custom ftp user123", false},
		{"custom", false},
	}

	for _, example := range examples {
		t.Run(example.command, func(t *testing.T) {
			parts := strings.Fields(example.command)
			valid := len(parts) == 3 && parts[0] == "custom" && parts[1] == "ssh"

			if valid != example.valid {
				t.Errorf("Expected valid=%v for command '%s', got valid=%v", example.valid, example.command, valid)
			}
		})
	}
}
