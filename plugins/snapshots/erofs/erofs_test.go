/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package erofs

import "testing"

func TestIsExtractKey(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "namespaced extract key",
			key:      "default/1/extract-12345",
			expected: true,
		},
		{
			name:     "extract key with digest",
			key:      "default/1/extract-sha256:abc123",
			expected: true,
		},
		{
			name:     "non-extract key",
			key:      "default/1/other-12345",
			expected: false,
		},
		{
			name:     "empty string",
			key:      "",
			expected: false,
		},
		{
			name:     "just extract prefix",
			key:      "extract-",
			expected: true,
		},
		{
			name:     "extract without hyphen",
			key:      "default/1/extract",
			expected: true, // HasPrefix matches "extract" prefix
		},
		{
			name:     "key without namespace",
			key:      "extract-12345",
			expected: true,
		},
		{
			name:     "deeply nested extract key",
			key:      "ns/a/b/c/extract-12345",
			expected: true,
		},
		{
			name:     "extract in middle of path",
			key:      "default/extract-123/snapshot",
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isExtractKey(tc.key)
			if got != tc.expected {
				t.Errorf("isExtractKey(%q) = %v, want %v", tc.key, got, tc.expected)
			}
		})
	}
}
