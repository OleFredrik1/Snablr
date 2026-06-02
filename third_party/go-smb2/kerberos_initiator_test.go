package smb2

import (
	"bytes"
	"testing"

	"github.com/hirochachacha/go-smb2/internal/spnego"
	"github.com/jcmturner/gokrb5/v8/credentials"
	krbgssapi "github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	krbspnego "github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestKerberosInitiatorUsesMicrosoftKerberosOID(t *testing.T) {
	t.Parallel()

	initiator := &KerberosInitiator{}
	if !initiator.oid().Equal(spnego.MsKerberosOid) {
		t.Fatalf("KerberosInitiator oid = %v, want %v", initiator.oid(), spnego.MsKerberosOid)
	}
}

func TestKerberosInitiatorSessionKeyPrefersAcceptorSubkey(t *testing.T) {
	t.Parallel()

	initiator := &KerberosInitiator{
		serviceSessionKey: types.EncryptionKey{KeyValue: []byte("service")},
		acceptorSubkey:    types.EncryptionKey{KeyValue: []byte("acceptor")},
	}

	if got := initiator.sessionKey(); !bytes.Equal(got, []byte("acceptor")) {
		t.Fatalf("sessionKey = %q, want acceptor", got)
	}
}

func TestKerberosInitiatorSessionKeyUsesFirst16BytesOfServiceKey(t *testing.T) {
	t.Parallel()

	serviceKey := bytes.Repeat([]byte{0x42}, 32)
	initiator := &KerberosInitiator{
		serviceSessionKey: types.EncryptionKey{KeyValue: serviceKey},
	}

	got := initiator.sessionKey()
	if !bytes.Equal(got, serviceKey[:16]) {
		t.Fatalf("sessionKey = %x, want first 16 bytes of service key", got)
	}
}

func TestKerberosInitiatorInitSecContextUsesProvidedTicket(t *testing.T) {
	t.Parallel()

	key := types.EncryptionKey{
		KeyType:  etypeID.AES128_CTS_HMAC_SHA1_96,
		KeyValue: bytes.Repeat([]byte{0x42}, 16),
	}
	initiator := &KerberosInitiator{
		Credentials: credentials.New("user", "EXAMPLE.COM"),
		Ticket: messages.Ticket{
			TktVNO: 5,
			Realm:  "EXAMPLE.COM",
			SName:  types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "cifs/fileserver.example.com"),
			EncPart: types.EncryptedData{
				EType:  etypeID.AES128_CTS_HMAC_SHA1_96,
				Cipher: []byte{0x01},
			},
		},
		SessionKey: key,
	}

	token, err := initiator.initSecContext()
	if err != nil {
		t.Fatalf("initSecContext returned error: %v", err)
	}
	if len(token) == 0 {
		t.Fatal("expected AP-REQ token")
	}
	if !bytes.Equal(initiator.serviceSessionKey.KeyValue, key.KeyValue) {
		t.Fatalf("serviceSessionKey = %x, want %x", initiator.serviceSessionKey.KeyValue, key.KeyValue)
	}

	var krbToken krbspnego.KRB5Token
	if err := krbToken.Unmarshal(token); err != nil {
		t.Fatalf("unmarshal KRB5 token: %v", err)
	}
	if err := krbToken.APReq.DecryptAuthenticator(key); err != nil {
		t.Fatalf("decrypt AP-REQ authenticator: %v", err)
	}
	if krbToken.APReq.Authenticator.Cksum.CksumType != 0 || len(krbToken.APReq.Authenticator.Cksum.Checksum) != 0 {
		t.Fatalf("expected no authenticator checksum, got %#v", krbToken.APReq.Authenticator.Cksum)
	}
	if krbToken.APReq.Authenticator.SeqNumber != 0 {
		t.Fatalf("expected no authenticator sequence number, got %d", krbToken.APReq.Authenticator.SeqNumber)
	}
	if len(krbToken.APReq.Authenticator.SubKey.KeyValue) != 0 {
		t.Fatalf("expected no authenticator subkey, got %x", krbToken.APReq.Authenticator.SubKey.KeyValue)
	}
}

func TestKerberosInitiatorSumBuildsVerifiableMIC(t *testing.T) {
	t.Parallel()

	key := types.EncryptionKey{
		KeyType:  etypeID.AES128_CTS_HMAC_SHA1_96,
		KeyValue: bytes.Repeat([]byte{0x42}, 16),
	}
	payload := []byte("mechanism-list")
	initiator := &KerberosInitiator{serviceSessionKey: key}

	mic := initiator.sum(payload)
	if len(mic) == 0 {
		t.Fatal("expected MIC token")
	}

	var token krbgssapi.MICToken
	if err := token.Unmarshal(mic, false); err != nil {
		t.Fatalf("unmarshal MIC token: %v", err)
	}
	token.Payload = payload
	ok, err := token.Verify(key, keyusage.GSSAPI_INITIATOR_SIGN)
	if err != nil {
		t.Fatalf("verify MIC token: %v", err)
	}
	if !ok {
		t.Fatal("expected MIC token to verify")
	}
}
