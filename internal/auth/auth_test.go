package auth

import (
	"errors"
	"log"
	"net/http"
	"testing"
)

func TestGetApiKey(t *testing.T) {

	type ExpectedResult struct {
		value         string
		expectedError error
	}
	type Cases struct {
		input    http.Header
		expected ExpectedResult
	}

	testSuit := []Cases{
		{
			input: http.Header{},
			expected: ExpectedResult{
				value:         "",
				expectedError: ErrNoAuthHeaderIncluded,
			},
		},
		{
			input: http.Header{
				"Authorization": {},
			},
			expected: ExpectedResult{
				value:         "",
				expectedError: errors.New("malformed authorization header"),
			},
		},
		{
			input: http.Header{
				"Authorization": {"ApiKey my-api-key"},
			},
			expected: ExpectedResult{
				value:         "my-api-key",
				expectedError: nil,
			},
		},
		{
			input: http.Header{
				"Authorization": {"ApiKey my-api-key another-random-thing"},
			},
			expected: ExpectedResult{
				value:         "my-api-key",
				expectedError: nil,
			},
		},
		{
			input: http.Header{
				"Authorization": {"NotApiKey my-api-key another-random-thing"},
			},
			expected: ExpectedResult{
				value:         "",
				expectedError: errors.New("malformed authorization header"),
			},
		},
	}

	for i, testCase := range testSuit {
		results, err := GetAPIKey(testCase.input)
		expectedValue := testCase.expected.value
		expectedError := testCase.expected.expectedError

		if results != expectedValue && err != expectedError {
			log.Fatalf("Test %d: Expected value: %s, got: %s. Expected error: %s, got: %s", i+1, expectedValue, results, expectedError, err)
		}
	}
}
