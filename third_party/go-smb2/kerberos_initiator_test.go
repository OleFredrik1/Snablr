package smb2

import (
	"bytes"
	"testing"

	"github.com/hirochachacha/go-smb2/internal/spnego"
	krbgssapi "github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
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

func TestKerberosInitiatorSessionKeyTruncatesServiceKey(t *testing.T) {
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
