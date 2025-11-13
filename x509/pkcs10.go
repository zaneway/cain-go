package x509

import (
	_ "crypto/sha1" // for crypto.SHA1
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

/**
CertificationRequest ::= SEQUENCE {
  certificationRequestInfo CertificationRequestInfo,
  signatureAlgorithm AlgorithmIdentifier,
  signature BIT STRING
}


CertificationRequestInfo ::= SEQUENCE {
  version INTEGER { v1(0) } (v1,...),
  subject Name,
  subjectPublicKeyInfo SubjectPublicKeyInfo,
  attributes [0] IMPLICIT Attributes
}
*/

type PKCS10 struct {
	CertificationRequestInfo *CertificationRequestInfo
	SignatureAlgorithm       pkix.AlgorithmIdentifier
	Signers                  asn1.BitString
}

type CertificationRequestInfo struct {
	Version              big.Int
	Subject              asn1.RawValue
	SubjectPublicKeyInfo publicKeyInfo
	Attributes           []asn1.RawValue `asn1:"tag:0"`
}
