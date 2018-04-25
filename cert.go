package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

const (
	caMaxAge   = 5 * 365 * 24 * time.Hour
	caUsage    = x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
)

func genKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func GenCA(name string) (certPEM, keyPEM []byte, err error) {
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now,
		NotAfter:              now.Add(caMaxAge),
		KeyUsage:              caUsage,
		BasicConstraintsValid: true,
		IsCA:               true,
		MaxPathLen:         2,
		SignatureAlgorithm: x509.SHA512WithRSA,
		DNSNames:           []string{"."},
	}
	key, err := genKeyPair()
	if err != nil {
		return
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: keyDER,
	})
	return
}
