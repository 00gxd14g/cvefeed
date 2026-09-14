package httpx

import (
	"strings"
	"testing"
)

func TestErrorBodyStripsHTMLAndBounds(t *testing.T) {
	html := `<html><body><h1>503 Service Unavailable</h1>
No server is available to handle this request.
<script>(function(){var x="window.__CF$cv$params={r:'a3b0'}";})()</script></body></html>`
	got := errorBody("text/html; charset=utf-8", []byte(html))
	want := "503 Service Unavailable No server is available to handle this request."
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	long := strings.Repeat("é", 500)
	got = errorBody("text/plain", []byte(long))
	if len(got) > errorBodyLimit+len("…") || !strings.HasSuffix(got, "…") {
		t.Fatalf("not bounded: %d bytes", len(got))
	}
	if got := errorBody("application/json", []byte(`{"message":"rate limited"}`)); got != `{"message":"rate limited"}` {
		t.Fatalf("plain body altered: %q", got)
	}
}
