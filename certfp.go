package soju

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func generateCertFP(keyType string, bits int) (privKeyBytes, certBytes []byte, err error) {
	var (
		privKey crypto.PrivateKey
		pubKey  crypto.PublicKey
	)
	switch keyType {
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, err
		}
		privKey = key
		pubKey = key.Public()
	case "ecdsa":
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		privKey = key
		pubKey = key.Public()
	case "ed25519":
		var err error
		pubKey, privKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
	}

	// Using PKCS#8 allows easier extension for new key types.
	privKeyBytes, err = x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	// Lets make a fair assumption nobody will use the same cert for more than 20 years...
	notAfter := notBefore.Add(24 * time.Hour * 365 * 20)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "soju auto-generated certificate"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certBytes, err = x509.CreateCertificate(rand.Reader, cert, cert, pubKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	return privKeyBytes, certBytes, nil
}
