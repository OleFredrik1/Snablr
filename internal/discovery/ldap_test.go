package discovery

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestBindCandidatesBareUsername(t *testing.T) {
	t.Parallel()

	got := bindCandidates("snaffleuser", "evilhaxxor.local")
	want := []bindCandidate{
		{Label: "username", Value: "snaffleuser"},
		{Label: "UPN", Value: "snaffleuser@evilhaxxor.local"},
		{Label: "DOMAIN\\USER", Value: `EVILHAXXOR\snaffleuser`},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected bind candidates:\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestBindCandidatesExplicitFormatsRemainSingleAttempt(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		username string
		want     []bindCandidate
	}{
		{
			name:     "explicit upn",
			username: "snaffleuser@evilhaxxor.local",
			want: []bindCandidate{{
				Label: "explicit UPN",
				Value: "snaffleuser@evilhaxxor.local",
			}},
		},
		{
			name:     "explicit down-level",
			username: `EVILHAXXOR\snaffleuser`,
			want: []bindCandidate{{
				Label: "explicit DOMAIN\\USER",
				Value: `EVILHAXXOR\snaffleuser`,
			}},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := bindCandidates(tc.username, "evilhaxxor.local"); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("unexpected bind candidates:\nwant: %#v\ngot:  %#v", tc.want, got)
			}
		})
	}
}

func TestBindCandidatesWithoutDomain(t *testing.T) {
	t.Parallel()

	got := bindCandidates("snaffleuser", "")
	want := []bindCandidate{{
		Label: "username",
		Value: "snaffleuser",
	}}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected bind candidates:\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestDownLevelBindDomain(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"evilhaxxor.local": "EVILHAXXOR",
		"EXAMPLE":          "EXAMPLE",
		"":                 "",
	}

	for input, want := range cases {
		if got := downLevelBindDomain(input); got != want {
			t.Fatalf("downLevelBindDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestDomainFromNamingContext(t *testing.T) {
	t.Parallel()

	got := domainFromNamingContext("DC=evilhaxxor,DC=local")
	if got != "evilhaxxor.local" {
		t.Fatalf("domainFromNamingContext returned %q", got)
	}
}

func TestNormalizeDetectedDomainRejectsPlaceholderValues(t *testing.T) {
	t.Parallel()

	cases := []string{"(none)", "none", "(invalid)"}
	for _, input := range cases {
		if got := normalizeDetectedDomain(input); got != "" {
			t.Fatalf("normalizeDetectedDomain(%q) = %q, want empty", input, got)
		}
	}
}

func TestRequiresLDAPSigning(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "ldap strong auth required",
			err: &ldap.Error{
				ResultCode: ldap.LDAPResultStrongAuthRequired,
				Err:        fmt.Errorf("bind rejected"),
			},
			want: true,
		},
		{
			name: "ldap confidentiality required",
			err: &ldap.Error{
				ResultCode: ldap.LDAPResultConfidentialityRequired,
				Err:        fmt.Errorf("bind rejected"),
			},
			want: true,
		},
		{
			name: "string stronger auth required",
			err:  fmt.Errorf("00002028: LdapErr: DSID-0C090274, comment: The server requires binds to turn on integrity checking if SSL/TLS are not already active on the connection, data 0, v4563 strongerAuthRequired"),
			want: true,
		},
		{
			name: "invalid credentials",
			err: &ldap.Error{
				ResultCode: ldap.LDAPResultInvalidCredentials,
				Err:        fmt.Errorf("bad password"),
			},
			want: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := requiresLDAPSigning(tc.err); got != tc.want {
				t.Fatalf("requiresLDAPSigning(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestLDAPAddressUsesCorrectDefaultPorts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		input       string
		defaultPort int
		wantAddr    string
		wantHost    string
	}{
		{
			name:        "ldap default port",
			input:       "10.100.11.31",
			defaultPort: defaultLDAPPort,
			wantAddr:    "10.100.11.31:389",
			wantHost:    "10.100.11.31",
		},
		{
			name:        "ldaps default port",
			input:       "10.100.11.31",
			defaultPort: defaultLDAPSPort,
			wantAddr:    "10.100.11.31:636",
			wantHost:    "10.100.11.31",
		},
		{
			name:        "preserve explicit port",
			input:       "10.100.11.31:1636",
			defaultPort: defaultLDAPSPort,
			wantAddr:    "10.100.11.31:1636",
			wantHost:    "10.100.11.31",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotAddr, gotHost := ldapAddress(tc.input, tc.defaultPort)
			if gotAddr != tc.wantAddr || gotHost != tc.wantHost {
				t.Fatalf("ldapAddress(%q, %d) = (%q, %q), want (%q, %q)", tc.input, tc.defaultPort, gotAddr, gotHost, tc.wantAddr, tc.wantHost)
			}
		})
	}
}

func TestLDAPEndpointForControllerHonorsTransportHints(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		dc        string
		transport string
		want      ldapEndpoint
	}{
		{
			name:      "ldaps url",
			dc:        "ldaps://dc01.example.local",
			transport: ldapTransportAuto,
			want: ldapEndpoint{
				Transport:         ldapTransportLDAPS,
				Address:           "dc01.example.local:636",
				Host:              "dc01.example.local",
				ExplicitTransport: true,
			},
		},
		{
			name:      "ldap url with port",
			dc:        "ldap://dc01.example.local:1389",
			transport: ldapTransportAuto,
			want: ldapEndpoint{
				Transport:         ldapTransportLDAP,
				Address:           "dc01.example.local:1389",
				Host:              "dc01.example.local",
				ExplicitTransport: true,
			},
		},
		{
			name:      "auto treats port 636 as ldaps",
			dc:        "dc01.example.local:636",
			transport: ldapTransportAuto,
			want: ldapEndpoint{
				Transport: ldapTransportLDAPS,
				Address:   "dc01.example.local:636",
				Host:      "dc01.example.local",
			},
		},
		{
			name:      "forced ldaps",
			dc:        "dc01.example.local",
			transport: ldapTransportLDAPS,
			want: ldapEndpoint{
				Transport: ldapTransportLDAPS,
				Address:   "dc01.example.local:636",
				Host:      "dc01.example.local",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ldapEndpointForController(tc.dc, tc.transport)
			if err != nil {
				t.Fatalf("ldapEndpointForController returned error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("unexpected endpoint:\nwant: %#v\ngot:  %#v", tc.want, got)
			}
		})
	}
}

func TestLDAPEndpointForControllerRejectsTransportConflict(t *testing.T) {
	t.Parallel()

	_, err := ldapEndpointForController("ldap://dc01.example.local", ldapTransportLDAPS)
	if err == nil {
		t.Fatal("expected conflicting scheme and ldap_transport to fail")
	}
}

func TestNormalizeLDAPAuthMethod(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"":          ldapAuthAuto,
		"auto":      ldapAuthAuto,
		"simple":    ldapAuthSimple,
		"ntlm":      ldapAuthNTLM,
		"gssapi":    ldapAuthGSSAPI,
		"kerberos":  ldapAuthGSSAPI,
		"negotiate": ldapAuthGSSAPI,
		"sspi":      ldapAuthGSSAPI,
	}

	for input, want := range cases {
		got, err := normalizeLDAPAuthMethod(input)
		if err != nil {
			t.Fatalf("normalizeLDAPAuthMethod(%q) returned error: %v", input, err)
		}
		if got != want {
			t.Fatalf("normalizeLDAPAuthMethod(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNTLMBindIdentity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		username   string
		domain     string
		wantDomain string
		wantUser   string
	}{
		{username: `EXAMPLE\alice`, domain: "example.local", wantDomain: "EXAMPLE", wantUser: "alice"},
		{username: "alice@example.local", domain: "", wantDomain: "example.local", wantUser: "alice@example.local"},
		{username: "alice", domain: "example.local", wantDomain: "EXAMPLE", wantUser: "alice"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.username, func(t *testing.T) {
			t.Parallel()

			gotDomain, gotUser := ntlmBindIdentity(tc.username, tc.domain)
			if gotDomain != tc.wantDomain || gotUser != tc.wantUser {
				t.Fatalf("ntlmBindIdentity(%q, %q) = (%q, %q), want (%q, %q)", tc.username, tc.domain, gotDomain, gotUser, tc.wantDomain, tc.wantUser)
			}
		})
	}
}
