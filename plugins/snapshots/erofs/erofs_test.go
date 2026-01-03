package erofs

import "testing"

func TestIsExtractKey(t *testing.T) {
	if !isExtractKey("default/1/extract-12345") {
		t.Fatal("expected namespaced extract key to be recognized")
	}
	if isExtractKey("default/1/other-12345") {
		t.Fatal("did not expect non-extract key to match")
	}
}
