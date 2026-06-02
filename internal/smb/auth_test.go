package smb

import (
	"strings"
	"testing"
)

func TestNormalizeAuthMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value string
		want  string
	}{
		{value: "", want: AuthNTLM},
		{value: "ntlm", want: AuthNTLM},
		{value: "kerberos", want: AuthKerberos},
		{value: "krb5", want: AuthKerberos},
		{value: "gssapi", want: AuthKerberos},
		{value: "bad", want: ""},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.value, func(t *testing.T) {
			t.Parallel()
			if got := normalizeAuthMethod(tt.value); got != tt.want {
				t.Fatalf("normalizeAuthMethod(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestKerberosCCachePathSupportsExplicitPathAndFileCache(t *testing.T) {
	if got, err := kerberosCCachePath("/tmp/custom.ccache"); err != nil || got != "/tmp/custom.ccache" {
		t.Fatalf("explicit kerberosCCachePath = %q, %v; want /tmp/custom.ccache, nil", got, err)
	}

	t.Setenv("KRB5CCNAME", "FILE:/tmp/krb5cc_test")
	got, err := kerberosCCachePath("")
	if err != nil {
		t.Fatalf("kerberosCCachePath returned error: %v", err)
	}
	if got != "/tmp/krb5cc_test" {
		t.Fatalf("kerberosCCachePath = %q, want /tmp/krb5cc_test", got)
	}
}

func TestKerberosCCachePathRejectsUnsupportedCacheTypes(t *testing.T) {
	t.Setenv("KRB5CCNAME", "KEYRING:persistent:1000")
	_, err := kerberosCCachePath("")
	if err == nil || !strings.Contains(err.Error(), "only FILE credential caches are supported") {
		t.Fatalf("expected unsupported cache error, got %v", err)
	}
}
