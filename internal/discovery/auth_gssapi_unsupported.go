//go:build !windows

package discovery

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

func bindLDAPGSSAPI(conn *ldap.Conn, endpoint ldapEndpoint, opts LDAPOptions, domain string, logger Logger) (string, error) {
	return "", fmt.Errorf("ldap discovery: gssapi ldap_auth requires Windows SSPI support; use ldap_auth=simple or ldap_auth=ntlm on this platform")
}
