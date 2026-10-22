package gh

import (
	"crypto/ed25519"
	"crypto/rsa"
	"golang.org/x/crypto/ssh"
)

func validUserKey(p ssh.PublicKey) bool {
	if p.Type() != "ssh-ed25519" && p.Type() != "ssh-rsa" {
		return false
	}
	k, ok := p.(ssh.CryptoPublicKey)
	if !ok {
		return false
	}
	switch x := k.CryptoPublicKey().(type) {
	case ed25519.PublicKey:
		return len(x) == 32
	case *rsa.PublicKey:
		return x.N.BitLen() >= 2048 && x.E >= 65537
	}
	return false
}
