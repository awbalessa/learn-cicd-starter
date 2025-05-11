package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Prepare test cases
	testCases := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid ApiKey",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-test-api-key"},
			},
			expectedKey:   "my-test-api-key",
			expectedError: nil,
		},
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Auth Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Bearer token",
			headers: http.Header{
				"Authorization": []string{"Bearer my-token"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tc.headers)

			if apiKey != tc.expectedKey {
				t.Errorf("Expected key: %q, Got: %q", tc.expectedKey, apiKey)
			}

			if tc.expectedError != nil {
				// An error was expected
				if err == nil {
					t.Errorf("Expected error: %v, Got no error", tc.expectedError)
				} else if err.Error() != tc.expectedError.Error() {
					t.Errorf("Expected error message: %q, Got: %q", tc.expectedError.Error(), err.Error())
				}
			} else {
				// No error was expected
				if err != nil {
					t.Errorf("Expected no error, Got: %v", err)
				}
			}
		})
	}
}
