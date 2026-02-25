package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    bool
		errMessage string
	}{
		{
			name:    "Valid API Key",
			headers: http.Header{"Authorization": []string{"ApiKey abc123def456"}},
			wantKey: "abc123def456",
			wantErr: false,
		},
		{
			name:       "Missing Authorization Header",
			headers:    http.Header{},
			wantKey:    "",
			wantErr:    true,
			errMessage: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:       "Malformed - Missing ApiKey Prefix",
			headers:    http.Header{"Authorization": []string{"Bearer token123"}},
			wantKey:    "",
			wantErr:    true,
			errMessage: "malformed authorization header",
		},
		{
			name:       "Malformed - Only One Part",
			headers:    http.Header{"Authorization": []string{"ApiKey"}},
			wantKey:    "",
			wantErr:    true,
			errMessage: "malformed authorization header",
		},
		{
			name:       "Malformed - Empty After Prefix",
			headers:    http.Header{"Authorization": []string{"ApiKey "}},
			wantKey:    "",
			wantErr:    true,
			errMessage: "malformed authorization header",
		},
		{
			name:    "Valid API Key with Extra Spaces",
			headers: http.Header{"Authorization": []string{"ApiKey  key-with-dashes"}},
			wantKey: "key-with-dashes",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			// Check error cases
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetAPIKey() error = nil, wantErr %v", tt.wantErr)
				} else if tt.errMessage != "" && err.Error() != tt.errMessage {
					t.Errorf("GetAPIKey() error = %v, want %v", err.Error(), tt.errMessage)
				}
				return
			}

			// Check success cases
			if err != nil {
				t.Errorf("GetAPIKey() unexpected error = %v", err)
				return
			}
			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() = %q, want %q", gotKey, tt.wantKey)
			}
		})
	}
}
