//go:build go1.20
// +build go1.20

package pkcs7

import (
	"bytes"
	"testing"
)

// TestDecryptExplicitOAEPParameters covers an envelope whose OAEP digest and
// MGF1 digest differ. This requires Go 1.20 or newer, because crypto/rsa only
// gained the ability to select the MGF1 digest independently of the OAEP
// digest in that release. On older versions the parameters are rejected with
// an explicit error instead of being decrypted with the wrong MGF1 digest.
func TestDecryptExplicitOAEPParameters(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected string
	}{
		{
			// Legal RFC 4055 combination: SHA-256 digest with the default
			// MGF1-SHA-1, so the mask generation algorithm is declared as
			// something other than the digest.
			name:     "rsa-oaep-sha256-mgf1-sha1",
			fixture:  RSAOAEPSHA256MGF1SHA1EncryptedTestFixture,
			expected: "This is a test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := UnmarshalTestFixture(tt.fixture)
			p7, err := Parse(fixture.Input)
			if err != nil {
				t.Fatal(err)
			}
			content, err := p7.Decrypt(fixture.Certificate, fixture.PrivateKey)
			if err != nil {
				t.Fatalf("cannot Decrypt with error: %v", err)
			}
			if !bytes.Equal(content, []byte(tt.expected)) {
				t.Errorf("decrypted result does not match.\n\tExpected:%s\n\tActual:%s", []byte(tt.expected), content)
			}
		})
	}
}

// RSAOAEPSHA256MGF1SHA1EncryptedTestFixture declares SHA-256 as the OAEP
// digest and the default MGF1-SHA-1 as the mask generation function, a legal
// combination in which the two digests differ.
//
//	openssl cms -encrypt -binary -in test.txt -outform pem -recip certificate.pem -aes256 \
//	    -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256 -keyopt rsa_mgf1_md:sha1
var RSAOAEPSHA256MGF1SHA1EncryptedTestFixture = `
-----BEGIN PKCS7-----
MIIBtAYJKoZIhvcNAQcDoIIBpTCCAaECAQAxggFcMIIBWAIBADAxMCkxEDAOBgNV
BAoTB0FjbWUgQ28xFTATBgNVBAMTDEVkZGFyZCBTdGFyawIEItzA4TAcBgkqhkiG
9w0BAQcwD6ANMAsGCWCGSAFlAwQCAQSCAQBHz6Hkyb6c9SbBOWhi/OdQR8PSTHP1
adD5aZg+/otgrw0Cj6NNU7MeLHQccaG13OsMm3Uluf2ztnu+L4/8YjiGduezzrqD
BNHPYMSfygnpv4xzQCmMCKSJ78PBU7uh8/eluXKbaEoGooOq4bKyCsy4g6cDeEaR
m0N1MmCFoKh8FMhosPI3w5S12hXKH+HPJDLPRtJUZKU3MCSHXPTo9M5pfsD/9hj/
WxpBeNda/j6UXuzNozBtdx+H1ebQAvrVg36sBgqMzZYUBEBFedSAQ0GXrcmxLYZb
1qyXYuXbcv//ZdRNxXWfEbqpK9B4tp+w6hq0v7oy4yrM+6UsdSskMc2aMDwGCSqG
SIb3DQEHATAdBglghkgBZQMEASoEEKoizsgpU4tBsyei3cc6inqAEJkFfIR0V5S0
K2DJxMx9eRI=
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIEItzA4TANBgkqhkiG9w0BAQsFADApMRAwDgYDVQQKEwdB
Y21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3RhcmswHhcNMjEwMjIzMTIxODQ2WhcN
MjIwMjIzMTIxODQ3WjAlMRAwDgYDVQQKEwdBY21lIENvMREwDwYDVQQDEwhKb24g
U25vdzCCAR8wDQYJKoZIhvcNAQEBBQADggEMADCCAQcCggEAcWPIQrIZColwlCsn
ZK7ULUEkZHtvMOCaLaHA4laqLuJOeQxAyWpL1m11w3GpFeBwPEdrThoG8b04xaPB
CuO9MPTvYqWqT1Eq0UWgbEjpZGmiLOjmIeBS8GaajDQVVRLYLlVEfwt+GNqUvZEa
x7OqvnBoQ2aJZFk+5xsuXkhLzwx4NBAatdYbuh5j5iN69ASJzjaiYNq3Ct1PvsJN
ZZ2w98rAmbCjqkVJrN5/yFink6l15s9lyidrdDUl8Ig5gPatBpvsNG14d5c4bVD+
DJc0vpZ8fYSuW480mwlAeUV8DAxv7jTEKguDJgOAT3HknzMgCBY3USxsvyu4G29r
4jmEbQIBA6NIMEYwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwME
MB8GA1UdIwQYMBaAFOy+qIFIokwb/0GSIt4DOBOXMd5vMA0GCSqGSIb3DQEBCwUA
A4IBAQA8F85MhBw5QxwrwRluL4waSXpxdRNpkN2K59eEqTUc+5lFLhinvX9WwkvR
ToBiRpvX50GtCWZ/r5Lx2UxTyh3vKsgjhkXcvm6pvVVfqyz5pNQv3v2Q838xM98+
15srGU9uU71McPZ5MmkmfHfgBaz5CCfUcsroJJ19pebaSARkRnb0bR36voXUbtwM
F89PLjXUYLxSaWcOpRQ1ju0Kq7K3MDqauPzzl3HtrpGkCsoHMfb5o/HYNj+Pmxfl
l3QH5xhOzVdioaGwE4SkY5Z5szZ8n+qi/Zd59PBCOpLoXvcB9WRTMmYkxmDOVcwI
pQfViIYaatHkjbS/2C/Cx0hfb/6S
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIEnwIBAAKCAQBxY8hCshkKiXCUKydkrtQtQSRke28w4JotocDiVqou4k55DEDJ
akvWbXXDcakV4HA8R2tOGgbxvTjFo8EK470w9O9ipapPUSrRRaBsSOlkaaIs6OYh
4FLwZpqMNBVVEtguVUR/C34Y2pS9kRrHs6q+cGhDZolkWT7nGy5eSEvPDHg0EBq1
1hu6HmPmI3r0BInONqJg2rcK3U++wk1lnbD3ysCZsKOqRUms3n/IWKeTqXXmz2XK
J2t0NSXwiDmA9q0Gm+w0bXh3lzhtUP4MlzS+lnx9hK5bjzSbCUB5RXwMDG/uNMQq
C4MmA4BPceSfMyAIFjdRLGy/K7gbb2viOYRtAgEDAoIBAEuX2tchZgcGSw1yGkMf
OB4rbZhSSiCVvB5r1ew5xsnsNFCy1ducMo7zo9ehG2Pq9X2E8jQRWfZ+JdkX1gdC
fiCjSkHDxt+LceDZFZ2F8O2bwXNF7sFAN0rvEbLNY44MkB7jgv9c/rs8YykLZy/N
HH71mteZsO2Q1JoSHumFh99cwWHFhLxYh64qFeeH6Gqx6AM2YVBWHgs7OuKOvc8y
zUbf8xftPht1kMwwDR1XySiEYtBtn74JflK3DcT8oxOuCZBuX6sMJHKbVP41zDj+
FJZBmpAvNfCEYJUr1Hg+DpMLqLUg+D6v5vpliburbk9LxcKFZyyZ9QVe7GoqMLBu
eGsCgYEAummUj4MMKWJC2mv5rj/dt2pj2/B2HtP2RLypai4et1/Ru9nNk8cjMLzC
qXz6/RLuJ7/eD7asFS3y7EqxKxEmW0G8tTHjnzR/3wnpVipuWnwCDGU032HJVd13
LMe51GH97qLzuDZjMCz+VlbCNdSslMgWWK0XmRnN7Yqxvh6ao2kCgYEAm7fTRBhF
JtKcaJ7d8BQb9l8BNHfjayYOMq5CxoCyxa2pGBv/Mrnxv73Twp9Z/MP0ue5M5nZt
GMovpP5cGdJLQ2w5p4H3opcuWeYW9Yyru2EyCEAI/hD/Td3QVP0ukc19BDuPl5Wg
eIFs218uiVOU4pw3w+Et5B1PZ/F+ZLr5LGUCgYB8RmMKV11w7CyRnVEe1T56Ru09
Svlp4qQt0xucHr8k6ovSkTO32hd10yxw/fyot0lv1T61JHK4yUydhyDHYMQ81n3O
IUJqIv/qBpuOxvQ8UqwIQ3iU69uOk6TIhSaNlqlJwffQJEIgHf7kOdbOjchjMA7l
yLpmETPzscvUFGcXmwKBgGfP4i1lg283EvBp6Uq4EqQ/ViL6l5zECXce1y8Ady5z
xhASqiHRS9UpN9cU5qiCoyae3e75nhCGym3+6BE23Nede8UBT8G6HuaZZKOzHSeW
IVrVW1QLVN6T4DioybaI/gLSX7pjwFBWSJI/dFuNDexoJS1AyUK+NO/2VEMnUMhD
AoGAOsdn3Prnh/mjC95vraHCLap0bRBSexMdx77ImHgtFUUcSaT8DJHs+NZw1RdM
SZA0J+zVQ8q7B11jIgz5hMz+chedwoRjTL7a8VRTKHFmmBH0zlEuV7L79w6HkRCQ
VRg10GUN6heGLv0aOHbPdobcuVDH4sgOqpT1QnOuce34sQs=
-----END RSA PRIVATE KEY-----`
