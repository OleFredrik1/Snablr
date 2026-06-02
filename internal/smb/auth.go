package smb

import (
	"fmt"
	"os"
	"strings"

	"github.com/hirochachacha/go-smb2"
	krbclient "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
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
		client, err := newKerberosClient(opts)
		if err != nil {
			return nil, func() {}, err
		}
		cleanup := func() { client.Destroy() }
		return &smb2.KerberosInitiator{
			Client: client,
			SPN:    "cifs/" + strings.ToLower(serverName),
		}, cleanup, nil
	default:
		return nil, func() {}, fmt.Errorf("unsupported SMB auth method %q", method)
	}
}

func newKerberosClient(opts AuthOptions) (*krbclient.Client, error) {
	krb5conf, err := config.Load(kerberosConfigPath(opts.Krb5ConfPath))
	if err != nil {
		return nil, fmt.Errorf("load krb5 config: %w", err)
	}

	ccachePath, err := kerberosCCachePath(opts.CCachePath)
	if err != nil {
		return nil, err
	}
	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, fmt.Errorf("load Kerberos credential cache %s: %w", ccachePath, err)
	}
	client, err := krbclient.NewFromCCache(ccache, krb5conf)
	if err != nil {
		return nil, fmt.Errorf("create Kerberos client from credential cache %s: %w", ccachePath, err)
	}
	return client, nil
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
