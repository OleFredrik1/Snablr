package smb

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
	krbclient "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

const (
	AuthNTLM     = "ntlm"
	AuthKerberos = "kerberos"
)

func normalizeAuthMethod(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", AuthNTLM:
		return AuthNTLM
	case "kerberos", "krb5", "gssapi":
		return AuthKerberos
	default:
		return ""
	}
}

func newInitiator(method, serverName, username, password, domain string, opts AuthOptions) (smb2.Initiator, func(), error) {
	switch method {
	case AuthNTLM:
		if strings.TrimSpace(username) == "" {
			return nil, func() {}, fmt.Errorf("username cannot be empty")
		}
		return &smb2.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
		}, func() {}, nil
	case AuthKerberos:
		spn := "cifs/" + strings.ToLower(serverName)
		initiator, cleanup, err := newKerberosInitiator(spn, opts)
		if err != nil {
			return nil, func() {}, err
		}
		return initiator, cleanup, nil
	default:
		return nil, func() {}, fmt.Errorf("unsupported SMB auth method %q", method)
	}
}

func newKerberosInitiator(spn string, opts AuthOptions) (*smb2.KerberosInitiator, func(), error) {
	ccachePath, err := kerberosCCachePath(opts.CCachePath)
	if err != nil {
		return nil, func() {}, err
	}
	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, func() {}, fmt.Errorf("load Kerberos credential cache %s: %w", ccachePath, err)
	}

	if cred, ok := ccacheServiceCredential(ccache, spn); ok {
		var ticket messages.Ticket
		if err := ticket.Unmarshal(cred.Ticket); err != nil {
			return nil, func() {}, fmt.Errorf("service ticket %s in credential cache %s is not valid: %w", cachedSPN(cred), ccachePath, err)
		}
		return &smb2.KerberosInitiator{
			Credentials: ccache.GetClientCredentials(),
			Ticket:      ticket,
			SessionKey:  cred.Key,
		}, func() {}, nil
	}

	krb5conf, err := config.Load(kerberosConfigPath(opts.Krb5ConfPath))
	if err != nil {
		return nil, func() {}, fmt.Errorf("load krb5 config: %w", err)
	}
	client, err := krbclient.NewFromCCache(ccache, krb5conf)
	if err != nil {
		return nil, func() {}, fmt.Errorf("credential cache %s does not contain a usable %s service ticket or TGT: %w", ccachePath, spn, err)
	}
	cleanup := func() { client.Destroy() }
	return &smb2.KerberosInitiator{
		Client: client,
		SPN:    spn,
	}, cleanup, nil
}

func ccacheServiceCredential(ccache *credentials.CCache, spn string) (*credentials.Credential, bool) {
	want := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, spn)
	for _, cred := range ccache.GetEntries() {
		if !ccacheCredentialValid(cred) {
			continue
		}
		if cred.Server.PrincipalName.Equal(want) {
			return cred, true
		}
	}

	wantHost := principalHost(want)
	if wantHost == "" {
		return nil, false
	}
	for _, cred := range ccache.GetEntries() {
		if !ccacheCredentialValid(cred) {
			continue
		}
		if principalHost(cred.Server.PrincipalName) == wantHost {
			return cred, true
		}
	}
	return nil, false
}

func ccacheCredentialValid(cred *credentials.Credential) bool {
	now := time.Now().UTC()
	if !cred.StartTime.IsZero() && now.Before(cred.StartTime) {
		return false
	}
	return cred.EndTime.IsZero() || now.Before(cred.EndTime)
}

func principalHost(principal types.PrincipalName) string {
	if len(principal.NameString) < 2 {
		return ""
	}
	host := strings.ToLower(principal.NameString[1])
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host
}

func cachedSPN(cred *credentials.Credential) string {
	spn := cred.Server.PrincipalName.PrincipalNameString()
	if cred.Server.Realm != "" {
		spn += "@" + cred.Server.Realm
	}
	return spn
}

func kerberosConfigPath(path string) string {
	if trimmed := strings.TrimSpace(path); trimmed != "" {
		return trimmed
	}
	if envPath := strings.TrimSpace(os.Getenv("KRB5_CONFIG")); envPath != "" {
		return envPath
	}
	return "/etc/krb5.conf"
}

func kerberosCCachePath(path string) (string, error) {
	if trimmed := strings.TrimSpace(path); trimmed != "" {
		return trimmed, nil
	}

	value := strings.TrimSpace(os.Getenv("KRB5CCNAME"))
	if value == "" {
		return fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid()), nil
	}

	upper := strings.ToUpper(value)
	if strings.HasPrefix(upper, "FILE:") {
		path := strings.TrimSpace(value[5:])
		if path == "" {
			return "", fmt.Errorf("KRB5CCNAME %q does not include a credential cache path", value)
		}
		return path, nil
	}
	if strings.Contains(value, ":") {
		return "", fmt.Errorf("unsupported KRB5CCNAME %q; only FILE credential caches are supported", value)
	}
	return value, nil
}
