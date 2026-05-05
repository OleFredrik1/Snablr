//go:build windows

package discovery

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/kerberos"
	"github.com/go-ldap/ldap/v3"
)

type sspiGSSAPIClient struct {
	creds           *sspi.Credentials
	ctx             *kerberos.ClientContext
	channelBindings []byte
}

func bindLDAPGSSAPI(conn *ldap.Conn, endpoint ldapEndpoint, opts LDAPOptions, domain string, logger Logger) (string, error) {
	cert, err := ldapTLSCertificate(conn, endpoint)
	if err != nil {
		return "", err
	}

	client, err := newSSPIGSSAPIClient(opts, domain, cert)
	if err != nil {
		return "", fmt.Errorf("ldap discovery: create SSPI GSSAPI client: %w", err)
	}
	defer client.Close()

	servicePrincipal := "ldap/" + strings.ToLower(endpoint.Host)
	if err := conn.GSSAPIBind(client, servicePrincipal, ""); err != nil {
		return "", fmt.Errorf("ldap discovery: gssapi bind failed for %s: %w", servicePrincipal, err)
	}

	method := endpoint.Transport + "-gssapi-sspi"
	if cert != nil {
		method += "-channel-binding"
	}
	if logger != nil {
		logger.Infof("ldap discovery: bind successful using GSSAPI/SSPI via %s", method)
	}
	return method, nil
}

func ldapTLSCertificate(conn *ldap.Conn, endpoint ldapEndpoint) (*x509.Certificate, error) {
	state, ok := conn.TLSConnectionState()
	if !ok {
		if endpoint.Transport == ldapTransportLDAPS {
			return nil, fmt.Errorf("ldap discovery: LDAPS GSSAPI channel binding requires TLS connection state")
		}
		return nil, nil
	}
	if len(state.PeerCertificates) == 0 {
		if endpoint.Transport == ldapTransportLDAPS {
			return nil, fmt.Errorf("ldap discovery: LDAPS GSSAPI channel binding requires a server TLS certificate")
		}
		return nil, nil
	}
	return state.PeerCertificates[0], nil
}

func newSSPIGSSAPIClient(opts LDAPOptions, domain string, cert *x509.Certificate) (*sspiGSSAPIClient, error) {
	creds, err := acquireSSPICredentials(opts, domain)
	if err != nil {
		return nil, err
	}

	client := &sspiGSSAPIClient{creds: creds}
	if cert != nil {
		certHash := calculateCertificateHash(cert)
		if certHash == nil {
			creds.Release()
			return nil, fmt.Errorf("failed to calculate certificate hash")
		}
		tlsChannelBinding := append([]byte("tls-server-end-point:"), certHash...)
		client.channelBindings = createChannelBindingsStructure(tlsChannelBinding)
	}
	return client, nil
}

func acquireSSPICredentials(opts LDAPOptions, domain string) (*sspi.Credentials, error) {
	username := strings.TrimSpace(opts.Username)
	if username == "" {
		return kerberos.AcquireCurrentUserCredentials()
	}
	if opts.Password == "" {
		return nil, fmt.Errorf("gssapi bind requires password when username is supplied")
	}

	authDomain, authUsername := sspiBindIdentity(username, domain)
	return kerberos.AcquireUserCredentials(authDomain, authUsername, opts.Password)
}

func sspiBindIdentity(username, domain string) (string, string) {
	username = strings.TrimSpace(username)
	if idx := strings.Index(username, `\`); idx > 0 && idx+1 < len(username) {
		return strings.TrimSpace(username[:idx]), strings.TrimSpace(username[idx+1:])
	}
	if idx := strings.Index(username, "@"); idx > 0 && idx+1 < len(username) {
		return strings.TrimSpace(username[idx+1:]), strings.TrimSpace(username[:idx])
	}
	return downLevelBindDomain(domain), username
}

func (c *sspiGSSAPIClient) Close() error {
	err1 := c.DeleteSecContext()
	var err2 error
	if c.creds != nil {
		err2 = c.creds.Release()
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *sspiGSSAPIClient) DeleteSecContext() error {
	if c.ctx == nil {
		return nil
	}
	return c.ctx.Release()
}

func (c *sspiGSSAPIClient) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	return c.InitSecContextWithOptions(target, token, []int{})
}

func (c *sspiGSSAPIClient) InitSecContextWithOptions(target string, token []byte, APOptions []int) ([]byte, bool, error) {
	sspiFlags := uint32(sspi.ISC_REQ_INTEGRITY | sspi.ISC_REQ_CONFIDENTIALITY | sspi.ISC_REQ_MUTUAL_AUTH)

	switch token {
	case nil:
		var ctx *kerberos.ClientContext
		var completed bool
		var output []byte
		var err error
		if len(c.channelBindings) > 0 {
			ctx, completed, output, err = kerberos.NewClientContextWithChannelBindings(c.creds, target, sspiFlags, c.channelBindings)
		} else {
			ctx, completed, output, err = kerberos.NewClientContextWithFlags(c.creds, target, sspiFlags)
		}
		if err != nil {
			return nil, false, err
		}
		c.ctx = ctx
		return output, !completed, nil
	default:
		completed, output, err := c.ctx.Update(token)
		if err != nil {
			return nil, false, err
		}
		if err := c.ctx.VerifyFlags(); err != nil {
			return nil, false, fmt.Errorf("error verifying flags: %v", err)
		}
		return output, !completed, nil
	}
}

func (c *sspiGSSAPIClient) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	const kerberosWrapNoEncrypt = 0x80000001

	flags, inputPayload, err := c.ctx.DecryptMessage(token, 0)
	if err != nil {
		return nil, fmt.Errorf("error decrypting message: %w", err)
	}
	if flags&kerberosWrapNoEncrypt == 0 {
		return nil, fmt.Errorf("message encrypted")
	}
	if len(inputPayload) != 4 {
		return nil, fmt.Errorf("bad server token")
	}
	if inputPayload[0] == 0x0 && !bytes.Equal(inputPayload, []byte{0x0, 0x0, 0x0, 0x0}) {
		return nil, fmt.Errorf("bad server token")
	}

	const selectedSecurity byte = 0
	var maxSecMsgSize uint32
	if selectedSecurity != 0 {
		maxSecMsgSize, _, _, _, err = c.ctx.Sizes()
		if err != nil {
			return nil, fmt.Errorf("error getting security context max message size: %w", err)
		}
	}

	inputPayload, err = c.ctx.EncryptMessage(gssapiHandshakePayload(selectedSecurity, maxSecMsgSize, []byte(authzid)), kerberosWrapNoEncrypt, 0)
	if err != nil {
		return nil, fmt.Errorf("error encrypting message: %w", err)
	}
	return inputPayload, nil
}

func gssapiHandshakePayload(secLayer byte, maxSize uint32, authzid []byte) []byte {
	var truncatedSize uint32
	if secLayer != 0 {
		truncatedSize = 0x00ffffff
		if truncatedSize > maxSize {
			truncatedSize = maxSize
		}
	}

	payload := make([]byte, 4, 4+len(authzid))
	binary.BigEndian.PutUint32(payload, truncatedSize)
	payload[0] = secLayer
	return append(payload, authzid...)
}

func createChannelBindingsStructure(applicationData []byte) []byte {
	const headerSize = 32
	appDataLen := uint32(len(applicationData))
	appDataOffset := uint32(headerSize)

	buf := make([]byte, headerSize+len(applicationData))
	binary.LittleEndian.PutUint32(buf[24:], appDataLen)
	binary.LittleEndian.PutUint32(buf[28:], appDataOffset)
	copy(buf[headerSize:], applicationData)
	return buf
}

func calculateCertificateHash(cert *x509.Certificate) []byte {
	var hashFunc crypto.Hash
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA,
		x509.SHA256WithRSAPSS,
		x509.ECDSAWithSHA256,
		x509.DSAWithSHA256:
		hashFunc = crypto.SHA256
	case x509.SHA384WithRSA,
		x509.SHA384WithRSAPSS,
		x509.ECDSAWithSHA384:
		hashFunc = crypto.SHA384
	case x509.SHA512WithRSA,
		x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA512:
		hashFunc = crypto.SHA512
	case x509.MD5WithRSA,
		x509.SHA1WithRSA,
		x509.ECDSAWithSHA1,
		x509.DSAWithSHA1:
		hashFunc = crypto.SHA256
	default:
		return nil
	}
	if !hashFunc.Available() {
		return nil
	}
	hasher := hashFunc.New()
	hasher.Write(cert.Raw)
	return hasher.Sum(nil)
}
