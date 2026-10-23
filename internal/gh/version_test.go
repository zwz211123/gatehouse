package gh

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebUsesBuildVersion(t *testing.T) {
	f := setup(t)
	response := httptest.NewRecorder()
	f.c.WebHandler().ServeHTTP(response, httptest.NewRequest("GET", "https://localhost/", nil))
	body := response.Body.String()
	for _, expected := range []string{"?v=" + Version, "Gatehouse " + Version} {
		if !strings.Contains(body, expected) {
			t.Fatalf("web page lacks build version %q", expected)
		}
	}
	if strings.Contains(body, "{{GATEHOUSE_VERSION}}") {
		t.Fatal("unexpanded build version")
	}
}
