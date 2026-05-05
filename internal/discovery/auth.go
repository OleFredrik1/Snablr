package discovery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	ldapTransportAuto  = "auto"
	ldapTransportLDAP  = "ldap"
	ldapTransportLDAPS = "ldaps"

	ldapAuthAuto   = "auto"
	ldapAuthSimple = "simple"
	ldapAuthNTLM   = "ntlm"
	ldapAuthGSSAPI = "gssapi"
)

type ldapSession struct {
	Conn       *ldap.Conn
	RootDSE    rootDSEInfo
	AuthMethod string
}

type ldapEndpoint struct {
	Transport         string
	Address           string
	Host              string
	ExplicitTransport bool
}

func ValidateLDAPCredentials(ctx context.Context, opts LDAPOptions, logger Logger) error {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultLDAPTimeout
	}

	domainContext, err := DetectDomainContext(ctx, opts, logger)
	if err != nil {
		return err
	}
	if domainContext.DomainController == "" {
		return fmt.Errorf("ldap discovery: unable to determine a domain controller for credential validation")
	}

	session, err := connectLDAPSession(opts, &domainContext, logger)
	if err != nil {
		return err
	}
	defer session.Conn.Close()

	return nil
}

func connectLDAPSession(opts LDAPOptions, domainContext *DomainContext, logger Logger) (ldapSession, error) {
	if domainContext == nil || strings.TrimSpace(domainContext.DomainController) == "" {
		return ldapSession{}, fmt.Errorf("ldap discovery: missing domain controller for ldap session")
	}

	transport, err := normalizeLDAPTransport(opts.Transport)
	if err != nil {
		return ldapSession{}, err
	}
	endpoint, err := ldapEndpointForController(domainContext.DomainController, transport)
	if err != nil {
		return ldapSession{}, err
	}

	conn, endpoint, err := dialLDAPEndpoint(endpoint, opts.Timeout)
	if err != nil {
		if transport != ldapTransportAuto || endpoint.Transport != ldapTransportLDAP || endpoint.ExplicitTransport {
			return ldapSession{}, err
		}
		if logger != nil {
			logger.Infof("ldap discovery: LDAP connect failed, retrying with LDAPS")
		}
		ldapsEndpoint, endpointErr := ldapEndpointForController(domainContext.DomainController, ldapTransportLDAPS)
		if endpointErr != nil {
			return ldapSession{}, err
		}
		conn, endpoint, err = dialLDAPEndpoint(ldapsEndpoint, opts.Timeout)
		if err != nil {
			return ldapSession{}, err
		}
	}

	rootDSE, err := preBindRootDSE(conn, domainContext, logger)
	if err != nil {
		conn.Close()
		return ldapSession{}, err
	}

	authedConn, method, err := authenticateLDAP(conn, endpoint, opts, domainContext.DomainName, domainContext.DomainController, logger)
	if err != nil {
		conn.Close()
		return ldapSession{}, err
	}

	return ldapSession{
		Conn:       authedConn,
		RootDSE:    rootDSE,
		AuthMethod: method,
	}, nil
}

func authenticateLDAP(conn *ldap.Conn, endpoint ldapEndpoint, opts LDAPOptions, domain, domainController string, logger Logger) (*ldap.Conn, string, error) {
	transport, err := normalizeLDAPTransport(opts.Transport)
	if err != nil {
		return nil, "", err
	}

	if method, err := bindLDAP(conn, endpoint, opts, domain, logger); err == nil {
		return conn, method, nil
	} else if endpoint.Transport != ldapTransportLDAP || transport != ldapTransportAuto || !requiresLDAPSigning(err) {
		return nil, "", err
	}

	if logger != nil {
		logger.Infof("ldap discovery: LDAP bind requires stronger authentication, retrying with LDAPS")
	}

	conn.Close()

	ldapsEndpoint, err := ldapEndpointForController(domainController, ldapTransportLDAPS)
	if err != nil {
		return nil, "", err
	}
	ldapsConn, ldapsEndpoint, err := dialLDAPEndpoint(ldapsEndpoint, opts.Timeout)
	if err != nil {
		return nil, "", fmt.Errorf("ldap discovery: stronger authentication required and LDAPS fallback failed: %w", err)
	}

	method, err := bindLDAP(ldapsConn, ldapsEndpoint, opts, domain, logger)
	if err != nil {
		ldapsConn.Close()
		return nil, "", fmt.Errorf("ldap discovery: stronger authentication required and LDAPS fallback bind failed: %w", err)
	}
	return ldapsConn, method, nil
}

func bindLDAP(conn *ldap.Conn, endpoint ldapEndpoint, opts LDAPOptions, domain string, logger Logger) (string, error) {
	authMethod, err := normalizeLDAPAuthMethod(opts.AuthMethod)
	if err != nil {
		return "", err
	}

	switch authMethod {
	case ldapAuthAuto, ldapAuthSimple:
		return bindLDAPSimple(conn, endpoint.Transport, opts, domain, logger)
	case ldapAuthNTLM:
		return bindLDAPNTLM(conn, endpoint.Transport, opts, domain, logger)
	case ldapAuthGSSAPI:
		return bindLDAPGSSAPI(conn, endpoint, opts, domain, logger)
	default:
		return "", fmt.Errorf("ldap discovery: unsupported ldap_auth %q", opts.AuthMethod)
	}
}

func dialLDAPS(dc string, timeout time.Duration) (*ldap.Conn, error) {
	endpoint, err := ldapEndpointForController(dc, ldapTransportLDAPS)
	if err != nil {
		return nil, err
	}
	conn, _, err := dialLDAPEndpoint(endpoint, timeout)
	return conn, err
}

func dialLDAPEndpoint(endpoint ldapEndpoint, timeout time.Duration) (*ldap.Conn, ldapEndpoint, error) {
	dialer := &net.Dialer{Timeout: timeout}
	dialOpts := []ldap.DialOpt{ldap.DialWithDialer(dialer)}
	if endpoint.Transport == ldapTransportLDAPS {
		dialOpts = append(dialOpts, ldap.DialWithTLSConfig(&tls.Config{
			ServerName:         endpoint.Host,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}))
	}

	conn, err := ldap.DialURL(endpoint.Transport+"://"+endpoint.Address, dialOpts...)
	if err != nil {
		return nil, endpoint, fmt.Errorf("ldap discovery: connect to %s failed: %w", endpoint.Address, err)
	}
	conn.SetTimeout(timeout)
	return conn, endpoint, nil
}

func ldapAddress(dc string, defaultPort int) (string, string) {
	address := dc
	host := dc
	if parsedHost, _, err := net.SplitHostPort(dc); err == nil {
		host = parsedHost
		return dc, host
	}

	host = dc
	address = net.JoinHostPort(dc, fmt.Sprintf("%d", defaultPort))
	return address, host
}

func ldapEndpointForController(dc, requestedTransport string) (ldapEndpoint, error) {
	requestedTransport, err := normalizeLDAPTransport(requestedTransport)
	if err != nil {
		return ldapEndpoint{}, err
	}

	raw := strings.TrimSpace(dc)
	if raw == "" {
		return ldapEndpoint{}, fmt.Errorf("ldap discovery: missing domain controller for ldap endpoint")
	}

	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return ldapEndpoint{}, fmt.Errorf("ldap discovery: parse domain controller URL %q: %w", raw, err)
		}
		transport := strings.ToLower(strings.TrimSpace(parsed.Scheme))
		if transport != ldapTransportLDAP && transport != ldapTransportLDAPS {
			return ldapEndpoint{}, fmt.Errorf("ldap discovery: unsupported LDAP URL scheme %q", parsed.Scheme)
		}
		if requestedTransport != ldapTransportAuto && requestedTransport != transport {
			return ldapEndpoint{}, fmt.Errorf("ldap discovery: dc URL scheme %q conflicts with ldap_transport %q", transport, requestedTransport)
		}
		if parsed.Host == "" {
			return ldapEndpoint{}, fmt.Errorf("ldap discovery: LDAP URL %q is missing host", raw)
		}
		if strings.Trim(parsed.Path, "/") != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return ldapEndpoint{}, fmt.Errorf("ldap discovery: LDAP URL %q must not include path, query, or fragment", raw)
		}
		address, host := ldapAddress(parsed.Host, defaultPortForLDAPTransport(transport))
		return ldapEndpoint{
			Transport:         transport,
			Address:           address,
			Host:              host,
			ExplicitTransport: true,
		}, nil
	}

	transport := requestedTransport
	if transport == ldapTransportAuto {
		transport = ldapTransportLDAP
		if _, port, err := net.SplitHostPort(raw); err == nil && port == fmt.Sprintf("%d", defaultLDAPSPort) {
			transport = ldapTransportLDAPS
		}
	}
	address, host := ldapAddress(raw, defaultPortForLDAPTransport(transport))
	return ldapEndpoint{
		Transport: transport,
		Address:   address,
		Host:      host,
	}, nil
}

func defaultPortForLDAPTransport(transport string) int {
	if transport == ldapTransportLDAPS {
		return defaultLDAPSPort
	}
	return defaultLDAPPort
}

func normalizeLDAPTransport(value string) (string, error) {
	transport := strings.ToLower(strings.TrimSpace(value))
	switch transport {
	case "", ldapTransportAuto:
		return ldapTransportAuto, nil
	case ldapTransportLDAP, ldapTransportLDAPS:
		return transport, nil
	default:
		return "", fmt.Errorf("ldap discovery: unsupported ldap_transport %q (expected auto, ldap, or ldaps)", value)
	}
}

func normalizeLDAPAuthMethod(value string) (string, error) {
	authMethod := strings.ToLower(strings.TrimSpace(value))
	switch authMethod {
	case "", ldapAuthAuto:
		return ldapAuthAuto, nil
	case ldapAuthSimple, ldapAuthNTLM, ldapAuthGSSAPI:
		return authMethod, nil
	case "negotiate", "kerberos", "sspi":
		return ldapAuthGSSAPI, nil
	default:
		return "", fmt.Errorf("ldap discovery: unsupported ldap_auth %q (expected auto, simple, ntlm, or gssapi)", value)
	}
}

func bindLDAPSimple(conn *ldap.Conn, transport string, opts LDAPOptions, domain string, logger Logger) (string, error) {
	username := strings.TrimSpace(opts.Username)
	password := opts.Password
	if username == "" {
		return "anonymous", nil
	}

	attempts := bindCandidates(username, domain)
	var lastErr error
	for _, attempt := range attempts {
		if err := conn.Bind(attempt.Value, password); err != nil {
			lastErr = err
			continue
		}
		method := transport + "-simple"
		if logger != nil {
			logger.Infof("ldap discovery: bind successful using %s format: %s via %s", attempt.Label, attempt.Value, method)
		}
		return method, nil
	}
	if len(attempts) == 1 {
		return "", fmt.Errorf("ldap discovery: bind failed for %s: %w", attempts[0].Value, lastErr)
	}
	return "", fmt.Errorf("ldap discovery: bind failed after trying %d username formats for %s: %w", len(attempts), username, lastErr)
}

func bindLDAPNTLM(conn *ldap.Conn, transport string, opts LDAPOptions, domain string, logger Logger) (string, error) {
	username := strings.TrimSpace(opts.Username)
	if username == "" {
		return "", fmt.Errorf("ldap discovery: ntlm bind requires username")
	}
	if opts.Password == "" {
		return "", fmt.Errorf("ldap discovery: ntlm bind requires password")
	}

	authDomain, authUsername := ntlmBindIdentity(username, domain)
	if err := conn.NTLMBind(authDomain, authUsername, opts.Password); err != nil {
		return "", fmt.Errorf("ldap discovery: ntlm bind failed for %s: %w", displayBindIdentity(authDomain, authUsername), err)
	}

	method := transport + "-ntlm"
	if logger != nil {
		logger.Infof("ldap discovery: bind successful using NTLM format: %s via %s", displayBindIdentity(authDomain, authUsername), method)
	}
	return method, nil
}

func ntlmBindIdentity(username, domain string) (string, string) {
	username = strings.TrimSpace(username)
	if idx := strings.Index(username, `\`); idx > 0 && idx+1 < len(username) {
		return strings.TrimSpace(username[:idx]), strings.TrimSpace(username[idx+1:])
	}
	if idx := strings.Index(username, "@"); idx > 0 && idx+1 < len(username) {
		return strings.TrimSpace(username[idx+1:]), username
	}
	return downLevelBindDomain(domain), username
}

func displayBindIdentity(domain, username string) string {
	domain = strings.TrimSpace(domain)
	username = strings.TrimSpace(username)
	if domain == "" {
		return username
	}
	return domain + `\` + username
}

func requiresLDAPSigning(err error) bool {
	if err == nil {
		return false
	}

	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		switch ldapErr.ResultCode {
		case ldap.LDAPResultStrongAuthRequired, ldap.LDAPResultConfidentialityRequired:
			return true
		}
	}

	message := strings.ToLower(err.Error())
	signingHints := []string{
		"strongerauthrequired",
		"strong auth required",
		"confidentiality required",
		"integrity checking",
	}
	for _, hint := range signingHints {
		if strings.Contains(message, hint) {
			return true
		}
	}
	return false
}
