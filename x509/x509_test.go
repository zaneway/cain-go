/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package x509

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/zaneway/cain-go/sm2"
)

func TestExt(t *testing.T) {
	decodeString, _ := base64.StdEncoding.DecodeString("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")
	var pqc PQCValidation
	rest, err := asn1.Unmarshal(decodeString, &pqc)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(rest)
	fmt.Println(pqc)

}

func TestX509(t *testing.T) {
	priv, err := sm2.GenerateKey(nil) // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	privPem, err := WritePrivateKeyToPem(priv, nil) // 生成密钥文件
	if err != nil {
		t.Fatal(err)
	}
	pubKey, _ := priv.Public().(*sm2.PublicKey)
	pubkeyPem, err := WritePublicKeyToPem(pubKey)       // 生成公钥文件
	privKey, err := ReadPrivateKeyFromPem(privPem, nil) // 读取密钥
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err = ReadPublicKeyFromPem(pubkeyPem) // 读取公钥
	if err != nil {
		t.Fatal(err)
	}
	templateReq := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test"},
		},
		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,
	}
	reqPem, err := CreateCertificateRequestToPem(&templateReq, privKey)
	if err != nil {
		t.Fatal(err)
	}
	req, err := ReadCertificateRequestFromPem(reqPem)
	if err != nil {
		t.Fatal(err)
	}
	err = req.CheckSignature()
	if err != nil {
		t.Fatalf("Request CheckSignature error:%v", err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"
	template := Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"TEST"},
			Country:      []string{"China"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Date(2021, time.October, 10, 12, 1, 1, 1, time.UTC),

		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       oidExtensionSubjectKeyId,
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}
	pubKey, _ = priv.Public().(*sm2.PublicKey)
	certpem, err := CreateCertificateToPem(&template, &template, pubKey, privKey)
	if err != nil {
		t.Fatal("failed to create cert file")
	}
	cert, err := ReadCertificateFromPem(certpem)
	if err != nil {
		t.Fatal("failed to read cert file")
	}
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		t.Fatal(err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
}

func TestCreateRevocationList(t *testing.T) {
	priv, err := sm2.GenerateKey(nil) // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	privPem, err := WritePrivateKeyToPem(priv, nil) // 生成密钥文件
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := ReadPrivateKeyFromPem(privPem, nil) // 读取密钥
	if err != nil {
		t.Fatal(err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate rsa key: %s", err)
	}
	tests := []struct {
		name          string
		key           crypto.Signer
		issuer        *Certificate
		template      *RevocationList
		expectedError string
	}{
		{
			name:          "nil template",
			key:           privKey,
			issuer:        nil,
			template:      nil,
			expectedError: "x509: template can not be nil",
		},
		{
			name:          "nil issuer",
			key:           privKey,
			issuer:        nil,
			template:      &RevocationList{},
			expectedError: "x509: issuer can not be nil",
		},
		{
			name: "issuer doesn't have crlSign key usage bit set",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCertSign,
			},
			template:      &RevocationList{},
			expectedError: "x509: issuer must have the crlSign key usage bit set",
		},
		{
			name: "issuer missing SubjectKeyId",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
			},
			template:      &RevocationList{},
			expectedError: "x509: issuer certificate doesn't contain a subject key identifier",
		},
		{
			name: "nextUpdate before thisUpdate",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour),
				NextUpdate: time.Time{},
			},
			expectedError: "x509: template.ThisUpdate is after template.NextUpdate",
		},
		{
			name: "nil Number",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "x509: template contains nil Number field",
		},
		{
			name: "invalid signature algorithm",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				SignatureAlgorithm: SHA256WithRSA,
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "x509: requested SignatureAlgorithm does not match private key type",
		},
		{
			name: "valid",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, rsa2048 key",
			key:  rsaPriv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, non-default signature algorithm",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				SignatureAlgorithm: SM2WithSM3,
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, extra extension",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    []int{2, 5, 29, 99},
						Value: []byte{5, 0},
					},
				},
			},
		},
		{
			name: "valid, empty list",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crl, err := CreateRevocationList(rand.Reader, tc.template, tc.issuer, tc.key)
			if err != nil && tc.expectedError == "" {
				t.Fatalf("CreateRevocationList failed unexpectedly: %s", err)
			} else if err != nil && tc.expectedError != err.Error() {
				t.Fatalf("CreateRevocationList failed unexpectedly, wanted: %s, got: %s", tc.expectedError, err)
			} else if err == nil && tc.expectedError != "" {
				t.Fatalf("CreateRevocationList didn't fail, expected: %s", tc.expectedError)
			}
			if tc.expectedError != "" {
				return
			}

			parsedCRL, err := ParseDERCRL(crl)
			if err != nil {
				t.Fatalf("Failed to parse generated CRL: %s", err)
			}
			if tc.template.SignatureAlgorithm != UnknownSignatureAlgorithm &&
				!parsedCRL.SignatureAlgorithm.Algorithm.Equal(signatureAlgorithmDetails[tc.template.SignatureAlgorithm].oid) {
				t.Fatalf("SignatureAlgorithm mismatch: got %v; want %v.", parsedCRL.SignatureAlgorithm,
					tc.template.SignatureAlgorithm)
			}

			if !reflect.DeepEqual(parsedCRL.TBSCertList.RevokedCertificates, tc.template.RevokedCertificates) {
				t.Fatalf("RevokedCertificates mismatch: got %v; want %v.",
					parsedCRL.TBSCertList.RevokedCertificates, tc.template.RevokedCertificates)
			}

			if len(parsedCRL.TBSCertList.Extensions) != 2+len(tc.template.ExtraExtensions) {
				t.Fatalf("Generated CRL has wrong number of extensions, wanted: %d, got: %d", 2+len(tc.template.ExtraExtensions), len(parsedCRL.TBSCertList.Extensions))
			}
			expectedAKI, err := asn1.Marshal(authKeyId{Id: tc.issuer.SubjectKeyId})
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			akiExt := pkix.Extension{
				Id:    oidExtensionAuthorityKeyId,
				Value: expectedAKI,
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[0], akiExt) {
				t.Fatalf("Unexpected first extension: got %v, want %v",
					parsedCRL.TBSCertList.Extensions[0], akiExt)
			}
			expectedNum, err := asn1.Marshal(tc.template.Number)
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			crlExt := pkix.Extension{
				Id:    oidExtensionCRLNumber,
				Value: expectedNum,
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[1], crlExt) {
				t.Fatalf("Unexpected second extension: got %v, want %v",
					parsedCRL.TBSCertList.Extensions[1], crlExt)
			}
			if len(parsedCRL.TBSCertList.Extensions[2:]) == 0 && len(tc.template.ExtraExtensions) == 0 {
				// If we don't have anything to check return early so we don't
				// hit a [] != nil false positive below.
				return
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[2:], tc.template.ExtraExtensions) {
				t.Fatalf("Extensions mismatch: got %v; want %v.",
					parsedCRL.TBSCertList.Extensions[2:], tc.template.ExtraExtensions)
			}
		})
	}
}
