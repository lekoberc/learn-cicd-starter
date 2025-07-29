package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	testCases := []struct {
		name           string
		headers        http.Header
		expectedAPIKey string
		expectedError  error
	}{
		{
			name: "Valid API Key",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey test-api-key")
				return h
			}(),
			expectedAPIKey: "test-api-key",
			expectedError:  nil,
		},
		{
			name: "No Authorization Header",
			headers: func() http.Header {
				return http.Header{}
			}(),
			expectedAPIKey: "",
			expectedError:  ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header - Missing Prefix",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "Bearer test-api-key")
				return h
			}(),
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header - Incomplete",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey")
				return h
			}(),
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tc.headers)

			// Check error
			if tc.expectedError == nil && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tc.expectedError != nil && err == nil {
				t.Errorf("expected error %v, got nil", tc.expectedError)
			}
			if tc.expectedError != nil && err != nil && tc.expectedError.Error() != err.Error() {
				t.Errorf("expected error %v, got %v", tc.expectedError, err)
			}

			// Check API key
			if apiKey != tc.expectedAPIKey {
				t.Errorf("expected API key %q, got %q", tc.expectedAPIKey, apiKey)
			}
		})
	}
}
