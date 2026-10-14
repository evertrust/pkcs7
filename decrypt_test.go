package pkcs7

import (
	"bytes"
	"testing"
)

func TestDecrypt(t *testing.T) {
	fixture := UnmarshalTestFixture(EncryptedTestFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Fatal(err)
	}
	content, err := p7.Decrypt(fixture.Certificate, fixture.PrivateKey)
	if err != nil {
		t.Errorf("Cannot Decrypt with error: %v", err)
	}
	expected := []byte("This is a test")
	if !bytes.Equal(content, expected) {
		t.Errorf("Decrypted result does not match.\n\tExpected:%s\n\tActual:%s", expected, content)
	}
}

// echo -n "This is a test" > test.txt
// openssl cms -encrypt -in test.txt cert.pem
var EncryptedTestFixture = `
-----BEGIN PKCS7-----
MIIBGgYJKoZIhvcNAQcDoIIBCzCCAQcCAQAxgcwwgckCAQAwMjApMRAwDgYDVQQK
EwdBY21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3RhcmsCBQDL+CvWMA0GCSqGSIb3
DQEBAQUABIGAyFz7bfI2noUs4FpmYfztm1pVjGyB00p9x0H3gGHEYNXdqlq8VG8d
iq36poWtEkatnwsOlURWZYECSi0g5IAL0U9sj82EN0xssZNaK0S5FTGnB3DPvYgt
HJvcKq7YvNLKMh4oqd17C6GB4oXyEBDj0vZnL7SUoCAOAWELPeC8CTUwMwYJKoZI
hvcNAQcBMBQGCCqGSIb3DQMHBAhEowTkot3a7oAQFD//J/IhFnk+JbkH7HZQFA==
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIB1jCCAUGgAwIBAgIFAMv4K9YwCwYJKoZIhvcNAQELMCkxEDAOBgNVBAoTB0Fj
bWUgQ28xFTATBgNVBAMTDEVkZGFyZCBTdGFyazAeFw0xNTA1MDYwMzU2NDBaFw0x
NjA1MDYwMzU2NDBaMCUxEDAOBgNVBAoTB0FjbWUgQ28xETAPBgNVBAMTCEpvbiBT
bm93MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK6NU0R0eiCYVquU4RcjKc
LzGfx0aa1lMr2TnLQUSeLFZHFxsyyMXXuMPig3HK4A7SGFHupO+/1H/sL4xpH5zg
8+Zg2r8xnnney7abxcuv0uATWSIeKlNnb1ZO1BAxFnESc3GtyOCr2dUwZHX5mRVP
+Zxp2ni5qHNraf3wE2VPIQIDAQABoxIwEDAOBgNVHQ8BAf8EBAMCAKAwCwYJKoZI
hvcNAQELA4GBAIr2F7wsqmEU/J/kLyrCgEVXgaV/sKZq4pPNnzS0tBYk8fkV3V18
sBJyHKRLL/wFZASvzDcVGCplXyMdAOCyfd8jO3F9Ac/xdlz10RrHJT75hNu3a7/n
9KNwKhfN4A1CQv2x372oGjRhCW5bHNCWx4PIVeNzCyq/KZhyY9sxHE6f
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIICXgIBAAKBgQDK6NU0R0eiCYVquU4RcjKcLzGfx0aa1lMr2TnLQUSeLFZHFxsy
yMXXuMPig3HK4A7SGFHupO+/1H/sL4xpH5zg8+Zg2r8xnnney7abxcuv0uATWSIe
KlNnb1ZO1BAxFnESc3GtyOCr2dUwZHX5mRVP+Zxp2ni5qHNraf3wE2VPIQIDAQAB
AoGBALyvnSt7KUquDen7nXQtvJBudnf9KFPt//OjkdHHxNZNpoF/JCSqfQeoYkeu
MdAVYNLQGMiRifzZz4dDhA9xfUAuy7lcGQcMCxEQ1dwwuFaYkawbS0Tvy2PFlq2d
H5/HeDXU4EDJ3BZg0eYj2Bnkt1sJI35UKQSxblQ0MY2q0uFBAkEA5MMOogkgUx1C
67S1tFqMUSM8D0mZB0O5vOJZC5Gtt2Urju6vywge2ArExWRXlM2qGl8afFy2SgSv
Xk5eybcEiQJBAOMRwwbEoW5NYHuFFbSJyWll4n71CYuWuQOCzehDPyTb80WFZGLV
i91kFIjeERyq88eDE5xVB3ZuRiXqaShO/9kCQQCKOEkpInaDgZSjskZvuJ47kByD
6CYsO4GIXQMMeHML8ncFH7bb6AYq5ybJVb2NTU7QLFJmfeYuhvIm+xdOreRxAkEA
o5FC5Jg2FUfFzZSDmyZ6IONUsdF/i78KDV5nRv1R+hI6/oRlWNCtTNBv/lvBBd6b
dseUE9QoaQZsn5lpILEvmQJAZ0B+Or1rAYjnbjnUhdVZoy9kC4Zov+4UH3N/BtSy
KJRWUR0wTWfZBPZ5hAYZjTBEAFULaYCXlQKsODSp0M1aQA==
-----END PRIVATE KEY-----`

func TestDecryptKeyTransport(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
	}{
		{"PKCS#1 v1.5", KeyTransportPKCS1v15Fixture},
		{"OAEP defaults (SHA-1, MGF1-SHA-1)", KeyTransportOAEPDefaultFixture},
		{"OAEP SHA-256, MGF1-SHA-256", KeyTransportOAEPSHA256Fixture},
		{"OAEP SHA-256, MGF1-SHA-1", KeyTransportOAEPSHA256MGF1SHA1Fixture},
		{"OAEP SHA-384, MGF1-SHA-256, label", KeyTransportOAEPSHA384LabelFixture},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := UnmarshalTestFixture(tt.fixture + KeyTransportRecipientFixture)
			p7, err := Parse(fixture.Input)
			if err != nil {
				t.Fatal(err)
			}
			content, err := p7.Decrypt(fixture.Certificate, fixture.PrivateKey)
			if err != nil {
				t.Fatalf("Cannot Decrypt with error: %v", err)
			}
			expected := []byte("This is a test")
			if !bytes.Equal(content, expected) {
				t.Errorf("Decrypted result does not match.\n\tExpected:%s\n\tActual:%s", expected, content)
			}
		})
	}
}

func TestDecryptOAEPWrongLabel(t *testing.T) {
	// Same envelope as KeyTransportOAEPSHA384LabelFixture with the label removed,
	// so a decryptor that ignored the label would wrongly succeed.
	fixture := UnmarshalTestFixture(KeyTransportOAEPSHA384LabelFixture + KeyTransportRecipientFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Fatal(err)
	}
	data := p7.Raw.(EnvelopedData)
	recipient := SelectRecipientForCertificate(data.RecipientInfos, fixture.Certificate)
	opts, err := parseRSAOAEPParameters(recipient.KeyEncryptionAlgorithm.Parameters)
	if err != nil {
		t.Fatal(err)
	}
	opts.Label = nil
	if _, err := fixture.PrivateKey.Decrypt(nil, recipient.EncryptedKey, opts); err == nil {
		t.Error("Decrypt succeeded without the OAEP label")
	}
}

// The fixtures below were generated with OpenSSL 3 and a throwaway key:
//
//	openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -subj "/O=Acme Co/CN=OAEP Test Recipient" -days 36500 -out cert.pem
//	echo -n "This is a test" > test.txt
//	openssl cms -encrypt -aes128 -in test.txt -recip cert.pem -outform PEM [-keyopt ...]
//
// with these -keyopt values:
//
//	PKCS#1 v1.5:    none
//	OAEP defaults:  rsa_padding_mode:oaep
//	OAEP SHA-256:   rsa_padding_mode:oaep rsa_oaep_md:sha256 rsa_mgf1_md:sha256
//	MGF1-SHA-1:     rsa_padding_mode:oaep rsa_oaep_md:sha256 rsa_mgf1_md:sha1
//	SHA-384, label: rsa_padding_mode:oaep rsa_oaep_md:sha384 rsa_mgf1_md:sha256 rsa_oaep_label:0102030405060708

var KeyTransportPKCS1v15Fixture = `
-----BEGIN PKCS7-----
MIIBvAYJKoZIhvcNAQcDoIIBrTCCAakCAQAxggFkMIIBYAIBADBIMDAxEDAOBgNV
BAoMB0FjbWUgQ28xHDAaBgNVBAMME09BRVAgVGVzdCBSZWNpcGllbnQCFHdzQw2m
W5bC3LxkOlBQfuZcW4vlMA0GCSqGSIb3DQEBAQUABIIBAGLrIN6B154piCF1sGHr
5QhyGy7T/TKNbI/LghVual9AaLspJi5pmxchkGLeZ+K4Iy3ZgMwSYkw/w3x4vyl8
WzMV7SC7ENSjRV4Eug0u4m4F6Ewksm4weg3hnXprJo4MOOQvEFa9oAgH/HB8fk9c
nGzricd2Afz4ksxIdsocjMgbd2pqjwI8fv31F8qnCDs0USn3ZfUsvIG6tdXQRC44
nNvdMiYlALtfpmhojjRBZka0whTgB4YgrKaULrAV1lNm0Q3Ziik9bdXG7WRBn9en
IGqK3sjSJut0JUOb4VGugml/bt5t6+3CJpUIATy9G6EILPH21eCuFyQWiJM/e1K1
ZnswPAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBAgQQvvN/2gZJ9yBkiNrP8i06f4AQ
4UH4pli/TewazOnuLwRP2w==
-----END PKCS7-----
`

var KeyTransportOAEPDefaultFixture = `
-----BEGIN PKCS7-----
MIIBvAYJKoZIhvcNAQcDoIIBrTCCAakCAQAxggFkMIIBYAIBADBIMDAxEDAOBgNV
BAoMB0FjbWUgQ28xHDAaBgNVBAMME09BRVAgVGVzdCBSZWNpcGllbnQCFHdzQw2m
W5bC3LxkOlBQfuZcW4vlMA0GCSqGSIb3DQEBBzAABIIBAFh1F4gwHGwImK0Ft69l
lFnmtfceX1PgNzE7kIqIMxrHM4EapmWc7cvInnZ6HCcLdv6LyPkk2Ez5y27lETfV
L7+SgbzbdF/6EOpSUxZu5tpxobsyey9xHnK7TZqvIiNRDKhwQZpnKYSV5PltrMr8
JF9QOHs0wBx6hGR1vKMa9xBMlWPZnBkxztfJEHqB/mAYKMuz+QjQM5s6cU/m2QQ3
KoCewy5RfUhSaV3/YGKN30TVFxs9ajqs6/WVIXUNEhVx0K/eCVY7NcMqNRsDKG05
3Eth70Xnk30Yph3EUtMiJVctC9fZJpx2178HPd4YV/OHTk1fQ4WJfYwST5lKvLbN
5XIwPAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBAgQQy8ZJwcQmrKehZRV16xxxIIAQ
xvUmw9HpPsI1fnyd083fWw==
-----END PKCS7-----
`

var KeyTransportOAEPSHA256Fixture = `
-----BEGIN PKCS7-----
MIIB5wYJKoZIhvcNAQcDoIIB2DCCAdQCAQAxggGPMIIBiwIBADBIMDAxEDAOBgNV
BAoMB0FjbWUgQ28xHDAaBgNVBAMME09BRVAgVGVzdCBSZWNpcGllbnQCFHdzQw2m
W5bC3LxkOlBQfuZcW4vlMDgGCSqGSIb3DQEBBzAroA0wCwYJYIZIAWUDBAIBoRow
GAYJKoZIhvcNAQEIMAsGCWCGSAFlAwQCAQSCAQCLjwftY8WilltfFVoMRoU93LUR
T1LCjCbmluly9k1HGjFUco6ZaiaMesJY5CbjbRMYYVWEJeh2lQkX63M0MMicXl/p
VGyiKKsvprbZxadCybd8yOz27l0hS3a1XHdcm+mj1PaGmKsZYU6aLCfWe/nODfOT
GgAg2fFvTCAXbRn3P5jUmwcOiX/8W6ZHVJ1NCshpkuxdHxQ8zPTZ3TnTYJ32hfDR
VmhAVZJY44CoIkS6KeYLl8OxVSIDmK50UKccIg7Q1U4pyl58soVNRD12VmdjrlES
APyb7pyozJ6a7+gE8Bpz5EKbr0JOMMjiwWzSNbemrjSzhRex6fMFLBgRNR/gMDwG
CSqGSIb3DQEHATAdBglghkgBZQMEAQIEEPiknXqBnVVe8VZ+piAC196AENytqOs9
vse7eiVrfGmuR9M=
-----END PKCS7-----
`

var KeyTransportOAEPSHA256MGF1SHA1Fixture = `
-----BEGIN PKCS7-----
MIIBywYJKoZIhvcNAQcDoIIBvDCCAbgCAQAxggFzMIIBbwIBADBIMDAxEDAOBgNV
BAoMB0FjbWUgQ28xHDAaBgNVBAMME09BRVAgVGVzdCBSZWNpcGllbnQCFHdzQw2m
W5bC3LxkOlBQfuZcW4vlMBwGCSqGSIb3DQEBBzAPoA0wCwYJYIZIAWUDBAIBBIIB
AF6os3AhGZ9xuJdDfyJ5UvZPQaP97jDB/HM0ttXX/ciPjiNpiLhsScI3dr9w43H7
QnUZptJqxbq4bjilZdi/n/UCV3ee9avz3ezV4OJNDLUikxgu/OL5Ufj0jVVFaCxv
QZ0i4kh0PiYZrz8oghR0vNgoNiGuHkyThnXXNdojC0rkwlcWESHkHlziI6MIvveV
ZWJPBx3U/Xe89/MOx9FHFR23HnF8gAwxl4+uYA7P4W8PR7hXohujBQOPmcEcdIE/
wpEJHreqlfV9GEO4Vtt83zn4ylDXGqV0oBz4A5NclNbpvI9e1hcF4+/A2kxHWr+X
PWlpGpgr/NmZY+FIaEWD7+QwPAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBAgQQsDSZ
lMKgWROaBreY+17twYAQgm3dVD0BlpWS58BcDfCetA==
-----END PKCS7-----
`

var KeyTransportOAEPSHA384LabelFixture = `
-----BEGIN PKCS7-----
MIICAAYJKoZIhvcNAQcDoIIB8TCCAe0CAQAxggGoMIIBpAIBADBIMDAxEDAOBgNV
BAoMB0FjbWUgQ28xHDAaBgNVBAMME09BRVAgVGVzdCBSZWNpcGllbnQCFHdzQw2m
W5bC3LxkOlBQfuZcW4vlMFEGCSqGSIb3DQEBBzBEoA0wCwYJYIZIAWUDBAICoRow
GAYJKoZIhvcNAQEIMAsGCWCGSAFlAwQCAaIXMBUGCSqGSIb3DQEBCQQIAQIDBAUG
BwgEggEAWybvUs3e5xISKKkIf3zQVITnmPBb61gO3Iqz1+lMNmdGodu4KAYbE4v5
Ppv3RFgRvR+CLLpNz6FPMUCaJmVGguC+LDZ0R+/9UM/PRy46XSWSfWAPFnKfRJnT
YtWLtQVYnCpkNeRHuDu4fk90welNLXQSaLwGSEJkPJlSbW8ZIlp3l77txxXWTEZa
4vR4szedVvW9mYUEG1qC7ZkkKmvT2KDGZsJmfggpzIb3IDTCiYgvENNF0DYVNqhI
4h+vQGq/ANFq1se3jd4hufmtunc7MtU1iSqdYJzmG7lTy3lAxGekmFQ7/c1+f70o
L4XCL3OOW0UJG5DsJPqPS16s7oTVBzA8BgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEC
BBDDeO5g5RwA+WFYL0C1F3jVgBCuxSzYsG6PgYD1WUlS05d6
-----END PKCS7-----
`

var KeyTransportRecipientFixture = `
-----BEGIN CERTIFICATE-----
MIIDQzCCAiugAwIBAgIUd3NDDaZblsLcvGQ6UFB+5lxbi+UwDQYJKoZIhvcNAQEL
BQAwMDEQMA4GA1UECgwHQWNtZSBDbzEcMBoGA1UEAwwTT0FFUCBUZXN0IFJlY2lw
aWVudDAgFw0yNjEwMTQwNzUwNTBaGA8yMTI2MDkyMDA3NTA1MFowMDEQMA4GA1UE
CgwHQWNtZSBDbzEcMBoGA1UEAwwTT0FFUCBUZXN0IFJlY2lwaWVudDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKQwyvAUOUnVTpGULybMElYK0GRJMs+f
uMjryaiV3FXQDaOwve94SxJZV72y6lJ4t7S/xKayEdX/7KiO5lRXwS2uY8PIJKuL
76dmyvSvk4LCA7VQWQzZrgSygWZaDWjv4g4h8wNDGrLkrlCasuU6JLJbEp0iLQNA
uOfRp2iqnB4hF2E361KDlsAHOx1LA9ATqz9CVlsMcsXk1FesuGBIUddXzhpRdxuZ
AstYnkEoDmM+/T5oFy1IwxIV9jTLAilHRrDw5OuMP0X0Xuiv8DlZukbpnLSIbAW/
zEADyYN78rHxJ347ml5Opz3RKlgZ+2iVnplqfBiQR2ce4whOO8SAImUCAwEAAaNT
MFEwHQYDVR0OBBYEFKO9l7IAdsQPbDW9mC12weMm1D61MB8GA1UdIwQYMBaAFKO9
l7IAdsQPbDW9mC12weMm1D61MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAHzVwduVswPbzISuFuShcAEqBNZ6a/m249WyxbuSz1rB9w3kNPgQbZ5o
iKReZfAEaFrRrQsHdCnq2n+PrtUJILMeQD1LQjrL6WHdGhTcL0MP2E+PHPobv20X
EnkckUGofxW5Oyn1B4PGxhPF4Gj4Hu4yJ6MW6zY3l/IkT2k/7rSzCZoM1fJUpjbw
/4i4oxm1Ycdz7ZW5qJjx85kAsOQWdNEcfxpatew/jRm/ORF3SbQefXoQB4ECdmUh
daKOuUkYYwmQgVXXmnwN7j+jGpMsVTKZYJhZex7GWXN4njXnr4dVyEf/pDdrGcMK
vui4hTX24+SWVlgDfN/3vkcMtDdyvns=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIIEpAIBAAKCAQEApDDK8BQ5SdVOkZQvJswSVgrQZEkyz5+4yOvJqJXcVdANo7C9
73hLEllXvbLqUni3tL/EprIR1f/sqI7mVFfBLa5jw8gkq4vvp2bK9K+TgsIDtVBZ
DNmuBLKBZloNaO/iDiHzA0MasuSuUJqy5TokslsSnSItA0C459GnaKqcHiEXYTfr
UoOWwAc7HUsD0BOrP0JWWwxyxeTUV6y4YEhR11fOGlF3G5kCy1ieQSgOYz79PmgX
LUjDEhX2NMsCKUdGsPDk64w/RfRe6K/wOVm6RumctIhsBb/MQAPJg3vysfEnfjua
Xk6nPdEqWBn7aJWemWp8GJBHZx7jCE47xIAiZQIDAQABAoIBAAWl1q/lcjGzpa06
SgOX93WAOmTeDmJincpDhL9I0GMfR1N/ITlwi4czuDdCmpmAT4lnI048nS0douK1
b6otDpcSAu/ZcvF3sc8HU9SQ3uPGOrcXmXM+CvoHDePFwI+rLhJ1tn9BOqo2quGu
QJhupJPXWs+O57oklXexQtnwgchDewhRDncF19jM6kFz27nPJPlaChUQzAsFBrid
tihHFtJrlHNEWyJkciNoitJZjf1xm6ZdA6/hu39iusYZySeAxhltn+ia6uszWGSF
Ee0Bzr7dThRz4RaRRl/J2/bukR4JTIg8wSqHrL3ftkJPId8jDJonEAwCeOci4QhV
HePIig0CgYEAz6cww5enSjr6hNrVj8L9zPyB1tFy/xDFdgDq8alGCwAhlKjry2D6
GlTL8ZLSwugC+TXfti9i73H6QK5FAU/aa+R/mlreZAvzauOfhyHKZXJu0tVmdLw7
VylJ9UzxrfVwDJy3J8n6RnDARZLnCAhzCh5rkv7l3J6kZx9nJLoWrxcCgYEAymsY
I14pTodPXWB2m0RKNKkkkfXCW9fTbUspof+ooSNTkz9qUarYiSps7XWzPs0BOCkC
yjJ3QLRVdGZSm5j4PKAvk/lTGdwi1woo2c9Axs4J9HvZTW2DI58yiE24tWTnKvu3
iovBScy/34Gf8mYMlEStRtqeioxkgpXzI874x+MCgYEAkfGS71UuCZjsK+XWBWVp
leG+q6mnpic2cRpyBgkPpnmgIGic2OM+xLTmZdHoeX4xYNABfH1PjrTPyxfwfdyO
yhfdqzHEbhKMMYrru0D/jE9iHqJHkTIejsMBLPu4PKhs6SBYBgoJ8eoa6Is3/0hY
+jqpJrYp/eYt7CCBEKoNeV8CgYBP3YV+nu5pX5X+38qsZHtq37ngJTl0h2mSW++n
TXo5afjVxlWqt2AMbsLfxmrcwoJSqEvDf7nxu7Vj4eOCJQ78zK85EUyqjWLpucZ4
ef+y8SSYZC1PEYCGk4+anB/e4lsbaIn4jj/LYI/sHfb/6yfXcGl15VhcjhwyMfvn
Cwi5xQKBgQDNhH4O1srCZ988luIaIVrXaI7DA44i0bNr3Inxge0T3WeLeBcqAtTh
MPG6CyEP3nXn34EIfi6Czp9tn1vQFKxqX7HWKSzVEDs8qS3xe1TKSGsdsxryfwCu
g24rT9QkkowEbctK0nmZMS3OA0Af4u//Bucehs60LKHUVaHb9e7JMg==
-----END PRIVATE KEY-----
`
