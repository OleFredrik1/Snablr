package smb2

import (
	"encoding/asn1"
	"fmt"

	"github.com/hirochachacha/go-smb2/internal/spnego"
	krbclient "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/credentials"
	krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
	krbgssapi "github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	krbspnego "github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

// KerberosInitiator implements SMB session setup with a Kerberos AP-REQ.
type KerberosInitiator struct {
	Client      *krbclient.Client
	Credentials *credentials.Credentials
	Ticket      messages.Ticket
	SessionKey  types.EncryptionKey
	SPN         string

	serviceSessionKey types.EncryptionKey
	acceptorSubkey    types.EncryptionKey
}

func (i *KerberosInitiator) oid() asn1.ObjectIdentifier {
	return spnego.MsKerberosOid
}

func (i *KerberosInitiator) initSecContext() ([]byte, error) {
	tkt, key, creds, err := i.serviceTicket()
	if err != nil {
		return nil, err
	}
	i.serviceSessionKey = key

	tokenClient := &krbclient.Client{Credentials: creds}
	token, err := krbspnego.NewKRB5TokenAPREQ(tokenClient, tkt, key, nil, nil)
	if err != nil {
		return nil, err
	}
	return token.Marshal()
}

func (i *KerberosInitiator) serviceTicket() (messages.Ticket, types.EncryptionKey, *credentials.Credentials, error) {
	if len(i.SessionKey.KeyValue) > 0 {
		creds := i.Credentials
		if creds == nil && i.Client != nil {
			creds = i.Client.Credentials
		}
		if creds == nil {
			return messages.Ticket{}, types.EncryptionKey{}, nil, fmt.Errorf("kerberos credentials are nil")
		}
		return i.Ticket, i.SessionKey, creds, nil
	}

	if i.Client == nil {
		return messages.Ticket{}, types.EncryptionKey{}, nil, fmt.Errorf("kerberos client is nil")
	}
	if i.SPN == "" {
		return messages.Ticket{}, types.EncryptionKey{}, nil, fmt.Errorf("kerberos SPN is empty")
	}
	tkt, key, err := i.Client.GetServiceTicket(i.SPN)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, nil, err
	}
	return tkt, key, i.Client.Credentials, nil
}

func (i *KerberosInitiator) acceptSecContext(sc []byte) ([]byte, error) {
	if len(sc) == 0 {
		return nil, nil
	}

	var token krbspnego.KRB5Token
	if err := token.Unmarshal(sc); err != nil {
		return nil, err
	}
	if token.IsKRBError() {
		return nil, token.KRBError
	}
	if !token.IsAPRep() {
		return nil, fmt.Errorf("expected Kerberos AP-REP token")
	}

	encPart, err := krbcrypto.DecryptEncPart(token.APRep.EncPart, i.serviceSessionKey, keyusage.AP_REP_ENCPART)
	if err != nil {
		return nil, err
	}
	part := &messages.EncAPRepPart{}
	if err := part.Unmarshal(encPart); err != nil {
		return nil, err
	}
	if len(part.Subkey.KeyValue) > 0 {
		i.acceptorSubkey = part.Subkey
	}
	return nil, nil
}

func (i *KerberosInitiator) sum(bs []byte) []byte {
	key, ok := i.contextKey()
	if !ok {
		return nil
	}

	flags := byte(0)
	if len(i.acceptorSubkey.KeyValue) > 0 {
		flags = krbgssapi.MICTokenFlagAcceptorSubkey
	}
	token := &krbgssapi.MICToken{
		Flags:     flags,
		SndSeqNum: 0,
		Payload:   bs,
	}
	if err := token.SetChecksum(key, keyusage.GSSAPI_INITIATOR_SIGN); err != nil {
		return nil
	}
	out, err := token.Marshal()
	if err != nil {
		return nil
	}
	return out
}

func (i *KerberosInitiator) sessionKey() []byte {
	key, ok := i.contextKey()
	if !ok {
		return nil
	}
	if len(i.acceptorSubkey.KeyValue) == 0 && len(key.KeyValue) > 16 {
		return append([]byte(nil), key.KeyValue[:16]...)
	}
	return append([]byte(nil), key.KeyValue...)
}

func (i *KerberosInitiator) contextKey() (types.EncryptionKey, bool) {
	if len(i.acceptorSubkey.KeyValue) > 0 {
		return i.acceptorSubkey, true
	}
	if len(i.serviceSessionKey.KeyValue) > 0 {
		return i.serviceSessionKey, true
	}
	return types.EncryptionKey{}, false
}
