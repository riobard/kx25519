package kx25519_test

import (
	"encoding/hex"
	"testing"

	. "github.com/riobard/kx25519"
)

// Test vectors from libsodium https://github.com/jedisct1/libsodium/blob/master/test/default/kx.exp
const (
	CliSk = "cb2f5160fc1f7e05a55ef49d340b48da2e5a78099d53393351cd579dd42503d6"
	CliPk = "0e0216223f147143d32615a91189c288c1728cba3cc5f9f621b1026e03d83129"
	SrvSk = "277d1c932cf8350251109639a74a3a0607afefa14eaf5739b472543649aec7bb"
	SrvPk = "cc034cfcd643e7d419fc535943f5af94224da6386cae5e88daf34167e9d84d0a"
	CliRx = "749519c68059bce69f7cfcc7b387a3de1a1e8237d110991323bf62870115731a"
	CliTx = "62c8f4fa81800abd0577d99918d129b65deb789af8c8351f391feb0cbf238604"
)

func TestKx(t *testing.T) {
	cliSk, err := hex.DecodeString(CliSk)
	if err != nil {
		t.Fatal(err)
	}
	cliPk, err := Pubkey(cliSk)
	if err != nil {
		t.Fatal(err)
	}
	if pk := hex.EncodeToString(cliPk); pk != CliPk {
		t.Fatal("client public key mismatch")
	}
	srvSk, err := hex.DecodeString(SrvSk)
	if err != nil {
		t.Fatal(err)
	}
	srvPk, err := Pubkey(srvSk)
	if err != nil {
		t.Fatal(err)
	}
	if pk := hex.EncodeToString(srvPk); pk != SrvPk {
		t.Fatal("server public key mismatch")
	}
	rx, tx, err := ClientSessionKeys(cliPk, cliSk, srvPk)
	if err != nil {
		t.Fatal(err)
	}
	if tx := hex.EncodeToString(tx); tx != CliTx {
		t.Logf("client tx mismatch")
	}
	if rx := hex.EncodeToString(rx); rx != CliRx {
		t.Logf("client rx mismatch")
	}

	srvRx, srvTx, err := ServerSessionKeys(srvPk, srvSk, cliPk)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(srvRx) != CliTx {
		t.Fatal("server rx mismatch")
	}
	if hex.EncodeToString(srvTx) != CliRx {
		t.Fatal("server tx mismatch")
	}
}

func BenchmarkKeyPair(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		KeyPair(nil)
	}
}

func BenchmarkClientKeys(b *testing.B) {
	sk, pk, err := KeyPair(nil)
	if err != nil {
		b.Fatal(err)
	}
	_, ppk, err := KeyPair(nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ClientSessionKeys(pk, sk, ppk)
	}
}

func BenchmarkServerKeys(b *testing.B) {
	sk, pk, err := KeyPair(nil)
	if err != nil {
		b.Fatal(err)
	}
	_, ppk, err := KeyPair(nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ServerSessionKeys(pk, sk, ppk)
	}
}
