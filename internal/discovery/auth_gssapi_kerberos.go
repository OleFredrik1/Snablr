//go:build !windows

package discovery

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/md5"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
	ldapgssapi "github.com/go-ldap/ldap/v3/gssapi"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	krbclient "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
	krbgssapi "github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

type kerberosGSSAPIClient struct {
	*krbclient.Client

	ekey               types.EncryptionKey
	Subkey             types.EncryptionKey
	channelBindingHash []byte
}

func bindLDAPGSSAPI(conn *ldap.Conn, endpoint ldapEndpoint, opts LDAPOptions, domain string, logger Logger) (string, error) {
	if endpoint.Transport != ldapTransportLDAPS {
		return "", fmt.Errorf("ldap discovery: gssapi over raw LDAP requires LDAP SASL signing, but go-ldap does not expose the SASL security-layer wrapping needed after bind; use --ldap-transport ldaps")
	}

	cert, err := ldapTLSCertificate(conn, endpoint)
	if err != nil {
		return "", err
	}

	client, err := newKerberosGSSAPIClient(opts, domain, cert)
	if err != nil {
		return "", fmt.Errorf("ldap discovery: create Kerberos GSSAPI client: %w", err)
	}
	defer client.Close()

	servicePrincipal := "ldap/" + strings.ToLower(endpoint.Host)
	if err := conn.GSSAPIBind(client, servicePrincipal, ""); err != nil {
		return "", fmt.Errorf("ldap discovery: gssapi bind failed for %s: %w", servicePrincipal, err)
	}

	method := endpoint.Transport + "-gssapi-kerberos-channel-binding"
	if logger != nil {
		logger.Infof("ldap discovery: bind successful using GSSAPI/Kerberos via %s", method)
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

func newKerberosGSSAPIClient(opts LDAPOptions, domain string, cert *x509.Certificate) (*kerberosGSSAPIClient, error) {
	if cert == nil {
		return nil, fmt.Errorf("LDAPS GSSAPI channel binding requires a server TLS certificate")
	}

	channelBindingHash, err := kerberosChannelBindingHash(cert)
	if err != nil {
		return nil, err
	}

	krb5conf, err := config.Load(kerberosConfigPath())
	if err != nil {
		return nil, fmt.Errorf("load krb5 config: %w", err)
	}

	client, err := newKerberosClient(opts, domain, krb5conf)
	if err != nil {
		return nil, err
	}

	return &kerberosGSSAPIClient{
		Client:             client,
		channelBindingHash: channelBindingHash,
	}, nil
}

func newKerberosClient(opts LDAPOptions, domain string, krb5conf *config.Config) (*krbclient.Client, error) {
	username := strings.TrimSpace(opts.Username)
	if username == "" {
		ccachePath, err := kerberosCCachePath()
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

	if opts.Password == "" {
		return nil, fmt.Errorf("gssapi bind requires password when username is supplied")
	}

	user, realm, err := kerberosBindIdentity(username, domain)
	if err != nil {
		return nil, err
	}
	client := krbclient.NewWithPassword(user, realm, opts.Password, krb5conf)
	if err := client.Login(); err != nil {
		return nil, fmt.Errorf("Kerberos login failed for %s@%s: %w", user, realm, err)
	}
	return client, nil
}

func kerberosConfigPath() string {
	if path := strings.TrimSpace(os.Getenv("KRB5_CONFIG")); path != "" {
		return path
	}
	return "/etc/krb5.conf"
}

func kerberosCCachePath() (string, error) {
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

func kerberosBindIdentity(username, domain string) (string, string, error) {
	username = strings.TrimSpace(username)
	domain = strings.TrimSpace(domain)
	if username == "" {
		return "", "", fmt.Errorf("gssapi bind requires username or a Kerberos credential cache")
	}

	if idx := strings.Index(username, `\`); idx > 0 && idx+1 < len(username) {
		user := strings.TrimSpace(username[idx+1:])
		realm := domain
		if realm == "" {
			realm = strings.TrimSpace(username[:idx])
		}
		return user, strings.ToUpper(realm), nil
	}
	if idx := strings.Index(username, "@"); idx > 0 && idx+1 < len(username) {
		return strings.TrimSpace(username[:idx]), strings.ToUpper(strings.TrimSpace(username[idx+1:])), nil
	}
	if domain == "" {
		return "", "", fmt.Errorf("gssapi bind requires a Kerberos realm; pass --domain or use a user principal name")
	}
	return username, strings.ToUpper(domain), nil
}

func (client *kerberosGSSAPIClient) Close() error {
	err := client.DeleteSecContext()
	if client.Client != nil {
		client.Client.Destroy()
	}
	return err
}

func (client *kerberosGSSAPIClient) DeleteSecContext() error {
	client.ekey = types.EncryptionKey{}
	client.Subkey = types.EncryptionKey{}
	return nil
}

func (client *kerberosGSSAPIClient) InitSecContext(target string, input []byte) ([]byte, bool, error) {
	return client.InitSecContextWithOptions(target, input, []int{})
}

func (client *kerberosGSSAPIClient) InitSecContextWithOptions(target string, input []byte, APOptions []int) ([]byte, bool, error) {
	gssapiFlags := []int{krbgssapi.ContextFlagInteg, krbgssapi.ContextFlagConf, krbgssapi.ContextFlagMutual}

	switch input {
	case nil:
		tkt, ekey, err := client.Client.GetServiceTicket(target)
		if err != nil {
			return nil, false, err
		}
		client.ekey = ekey
		normalizeLDAPServiceTicketName(&tkt)

		output, err := newKRB5TokenAPREQWithChannelBinding(client.Client, tkt, ekey, gssapiFlags, APOptions, client.channelBindingHash)
		if err != nil {
			return nil, false, err
		}

		return output, true, nil

	default:
		var token spnego.KRB5Token
		if err := token.Unmarshal(input); err != nil {
			return nil, false, err
		}

		completed := false
		if token.IsAPRep() {
			completed = true

			encPart, err := krbcrypto.DecryptEncPart(token.APRep.EncPart, client.ekey, keyusage.AP_REP_ENCPART)
			if err != nil {
				return nil, false, err
			}

			part := &messages.EncAPRepPart{}
			if err = part.Unmarshal(encPart); err != nil {
				return nil, false, err
			}
			client.Subkey = part.Subkey
		}

		if token.IsKRBError() {
			return nil, true, token.KRBError
		}

		return make([]byte, 0), !completed, nil
	}
}

func normalizeLDAPServiceTicketName(tkt *messages.Ticket) {
	if tkt == nil || len(tkt.SName.NameString) == 0 {
		return
	}
	if strings.EqualFold(tkt.SName.NameString[0], "ldap") {
		tkt.SName.NameType = nametype.KRB_NT_SRV_INST
	}
}

func (client *kerberosGSSAPIClient) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	token := &krbgssapi.WrapToken{}
	if err := ldapgssapi.UnmarshalWrapToken(token, input, true); err != nil {
		return nil, err
	}

	if (token.Flags & 0b1) == 0 {
		return nil, fmt.Errorf("got a Wrapped token that's not from the server")
	}

	key := client.ekey
	if (token.Flags & 0b100) != 0 {
		key = client.Subkey
	}

	if _, err := token.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		return nil, err
	}

	if len(token.Payload) != 4 {
		return nil, fmt.Errorf("server sent bad final token for SASL GSSAPI handshake")
	}

	// LDAPS provides transport confidentiality and integrity; LDAP signing on
	// raw port 389 would require wrapping subsequent LDAP packets, which
	// go-ldap does not expose.
	payload := gssapiHandshakePayload(0, 0, []byte(authzid))

	encType, err := krbcrypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	token = &krbgssapi.WrapToken{
		Flags:     0b100,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: 1,
		Payload:   payload,
	}

	if err := token.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}

	output, err := token.Marshal()
	if err != nil {
		return nil, err
	}
	return output, nil
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

func newKRB5TokenAPREQWithChannelBinding(cl *krbclient.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, gssapiFlags []int, apOptions []int, channelBindingHash []byte) ([]byte, error) {
	auth, err := types.NewAuthenticator(cl.Credentials.Domain(), cl.Credentials.CName())
	if err != nil {
		return nil, err
	}
	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  kerberosAuthenticatorChecksum(gssapiFlags, channelBindingHash),
	}

	apReq, err := messages.NewAPReq(tkt, sessionKey, auth)
	if err != nil {
		return nil, err
	}
	for _, option := range apOptions {
		types.SetFlag(&apReq.APOptions, option)
	}

	out, err := asn1.Marshal(krbgssapi.OIDKRB5.OID())
	if err != nil {
		return nil, err
	}
	out = append(out, 0x01, 0x00)

	apReqBytes, err := apReq.Marshal()
	if err != nil {
		return nil, err
	}
	out = append(out, apReqBytes...)
	return asn1tools.AddASNAppTag(out, 0), nil
}

func kerberosAuthenticatorChecksum(flags []int, channelBindingHash []byte) []byte {
	checksum := make([]byte, 24)
	binary.LittleEndian.PutUint32(checksum[:4], 16)
	copy(checksum[4:20], channelBindingHash)

	for _, flag := range flags {
		if flag == krbgssapi.ContextFlagDeleg {
			padding := make([]byte, 28-len(checksum))
			checksum = append(checksum, padding...)
		}
		currentFlags := binary.LittleEndian.Uint32(checksum[20:24])
		currentFlags |= uint32(flag)
		binary.LittleEndian.PutUint32(checksum[20:24], currentFlags)
	}
	return checksum
}

func kerberosChannelBindingHash(cert *x509.Certificate) ([]byte, error) {
	certHash := kerberosCertificateHash(cert)
	if certHash == nil {
		return nil, fmt.Errorf("failed to calculate certificate hash for LDAPS channel binding")
	}

	applicationData := append([]byte("tls-server-end-point:"), certHash...)
	buf := bytes.NewBuffer(nil)
	for _, field := range []uint32{0, 0, 0, 0, uint32(len(applicationData))} {
		if err := binary.Write(buf, binary.LittleEndian, field); err != nil {
			return nil, err
		}
	}
	buf.Write(applicationData)

	sum := md5.Sum(buf.Bytes())
	return sum[:], nil
}

func kerberosCertificateHash(cert *x509.Certificate) []byte {
	var hashFunc stdcrypto.Hash
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA,
		x509.SHA256WithRSAPSS,
		x509.ECDSAWithSHA256,
		x509.DSAWithSHA256:
		hashFunc = stdcrypto.SHA256
	case x509.SHA384WithRSA,
		x509.SHA384WithRSAPSS,
		x509.ECDSAWithSHA384:
		hashFunc = stdcrypto.SHA384
	case x509.SHA512WithRSA,
		x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA512:
		hashFunc = stdcrypto.SHA512
	case x509.MD5WithRSA,
		x509.SHA1WithRSA,
		x509.ECDSAWithSHA1,
		x509.DSAWithSHA1:
		hashFunc = stdcrypto.SHA256
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
