//go:build !windows

package discovery

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"

	krbgssapi "github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestKerberosBindIdentity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		username  string
		domain    string
		wantUser  string
		wantRealm string
	}{
		{
			name:      "user principal name",
			username:  "alice@example.local",
			wantUser:  "alice",
			wantRealm: "EXAMPLE.LOCAL",
		},
		{
			name:      "down-level with fqdn domain",
			username:  `EXAMPLE\alice`,
			domain:    "example.local",
			wantUser:  "alice",
			wantRealm: "EXAMPLE.LOCAL",
		},
		{
			name:      "down-level without fqdn domain",
			username:  `EXAMPLE\alice`,
			wantUser:  "alice",
			wantRealm: "EXAMPLE",
		},
		{
			name:      "bare username",
			username:  "alice",
			domain:    "example.local",
			wantUser:  "alice",
			wantRealm: "EXAMPLE.LOCAL",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotUser, gotRealm, err := kerberosBindIdentity(tc.username, tc.domain)
			if err != nil {
				t.Fatalf("kerberosBindIdentity returned error: %v", err)
			}
			if gotUser != tc.wantUser || gotRealm != tc.wantRealm {
				t.Fatalf("kerberosBindIdentity(%q, %q) = (%q, %q), want (%q, %q)", tc.username, tc.domain, gotUser, gotRealm, tc.wantUser, tc.wantRealm)
			}
		})
	}
}

func TestKerberosBindIdentityRequiresRealmForBareUsername(t *testing.T) {
	t.Parallel()

	_, _, err := kerberosBindIdentity("alice", "")
	if err == nil {
		t.Fatal("expected bare username without domain to fail")
	}
}

func TestKerberosAuthenticatorChecksumIncludesChannelBindingHashAndFlags(t *testing.T) {
	t.Parallel()

	channelBindingHash := []byte{
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
	}
	flags := []int{krbgssapi.ContextFlagInteg, krbgssapi.ContextFlagConf, krbgssapi.ContextFlagMutual}

	got := kerberosAuthenticatorChecksum(flags, channelBindingHash)
	if len(got) != 24 {
		t.Fatalf("checksum length = %d, want 24", len(got))
	}
	if gotLen := binary.LittleEndian.Uint32(got[:4]); gotLen != 16 {
		t.Fatalf("checksum channel-binding length = %d, want 16", gotLen)
	}
	if !bytes.Equal(got[4:20], channelBindingHash) {
		t.Fatalf("checksum channel-binding hash = %x, want %x", got[4:20], channelBindingHash)
	}

	wantFlags := uint32(krbgssapi.ContextFlagInteg | krbgssapi.ContextFlagConf | krbgssapi.ContextFlagMutual)
	if gotFlags := binary.LittleEndian.Uint32(got[20:24]); gotFlags != wantFlags {
		t.Fatalf("checksum flags = %#x, want %#x", gotFlags, wantFlags)
	}
}

func TestKerberosChannelBindingHashUsesTLSServerEndpointData(t *testing.T) {
	t.Parallel()

	cert := &x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Raw:                []byte("certificate-bytes"),
	}

	certHash := sha256.Sum256(cert.Raw)
	applicationData := append([]byte("tls-server-end-point:"), certHash[:]...)
	buf := bytes.NewBuffer(nil)
	for _, field := range []uint32{0, 0, 0, 0, uint32(len(applicationData))} {
		if err := binary.Write(buf, binary.LittleEndian, field); err != nil {
			t.Fatalf("write expected channel-binding field: %v", err)
		}
	}
	buf.Write(applicationData)
	want := md5.Sum(buf.Bytes())

	got, err := kerberosChannelBindingHash(cert)
	if err != nil {
		t.Fatalf("kerberosChannelBindingHash returned error: %v", err)
	}
	if !reflect.DeepEqual(got, want[:]) {
		t.Fatalf("kerberosChannelBindingHash = %x, want %x", got, want)
	}
}

func TestKerberosCCachePathSupportsFileCacheOnly(t *testing.T) {
	t.Setenv("KRB5CCNAME", "file:/tmp/krb5cc_test")
	got, err := kerberosCCachePath()
	if err != nil {
		t.Fatalf("kerberosCCachePath returned error: %v", err)
	}
	if got != "/tmp/krb5cc_test" {
		t.Fatalf("kerberosCCachePath = %q, want /tmp/krb5cc_test", got)
	}

	t.Setenv("KRB5CCNAME", "KEYRING:persistent:1000")
	_, err = kerberosCCachePath()
	if err == nil || !strings.Contains(err.Error(), "only FILE credential caches are supported") {
		t.Fatalf("expected unsupported cache error, got %v", err)
	}
}

func TestNormalizeLDAPServiceTicketNameUsesServiceInstanceType(t *testing.T) {
	t.Parallel()

	tkt := messages.Ticket{
		SName: types.PrincipalName{
			NameType:   nametype.KRB_NT_PRINCIPAL,
			NameString: []string{"ldap", "dc01.example.local"},
		},
	}

	normalizeLDAPServiceTicketName(&tkt)

	if tkt.SName.NameType != nametype.KRB_NT_SRV_INST {
		t.Fatalf("LDAP ticket name type = %d, want %d", tkt.SName.NameType, nametype.KRB_NT_SRV_INST)
	}
}

func TestNormalizeLDAPServiceTicketNameLeavesNonLDAPTicketsAlone(t *testing.T) {
	t.Parallel()

	tkt := messages.Ticket{
		SName: types.PrincipalName{
			NameType:   nametype.KRB_NT_PRINCIPAL,
			NameString: []string{"HTTP", "app.example.local"},
		},
	}

	normalizeLDAPServiceTicketName(&tkt)

	if tkt.SName.NameType != nametype.KRB_NT_PRINCIPAL {
		t.Fatalf("non-LDAP ticket name type = %d, want %d", tkt.SName.NameType, nametype.KRB_NT_PRINCIPAL)
	}
}
