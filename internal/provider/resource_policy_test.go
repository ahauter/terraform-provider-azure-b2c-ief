package provider

import (
	"testing"
)

func TestInjectAppSettings(t *testing.T) {
	tests := []struct {
		name        string
		xml         string
		appSettings map[string]string
		expected    string
	}{
		{
			name: "single replacement",
			xml:  "<Config>{settings:API_KEY}</Config>",
			appSettings: map[string]string{
				"API_KEY": "12345",
			},
			expected: "<Config>12345</Config>",
		},
		{
			name: "multiple replacements",
			xml:  "<Config>{settings:API_KEY},{settings:SECRET}</Config>",
			appSettings: map[string]string{
				"API_KEY": "12345",
				"SECRET":  "abcd",
			},
			expected: "<Config>12345,abcd</Config>",
		},
		{
			name: "case insensitive key",
			xml:  "<Config>{Settings:Api_Key}</Config>",
			appSettings: map[string]string{
				"API_KEY": "12345",
			},
			expected: "<Config>12345</Config>",
		},
		{
			name: "key not present in map",
			xml:  "<Config>{settings:NOT_IN_MAP}</Config>",
			appSettings: map[string]string{
				"API_KEY": "12345",
			},
			expected: "<Config>{settings:NOT_IN_MAP}</Config>",
		},
		{
			name: "no placeholders",
			xml:  "<Config>No placeholders here</Config>",
			appSettings: map[string]string{
				"API_KEY": "12345",
			},
			expected: "<Config>No placeholders here</Config>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := injectAppSettings(tt.xml, tt.appSettings)
			if got != tt.expected {
				t.Errorf("injectAppSettings() = %q, want %q", got, tt.expected)
			}
		})
	}
}
