// Copyright 2020 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package wx

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	rand2 "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"testing"
	"time"
)

func TestNewRandStrs(t *testing.T) {
	log.SetFlags(log.Ltime | log.Lshortfile)
	buf := new(bytes.Buffer)
	f := multipart.NewWriter(buf)
	r, err := f.CreateFormField("meta")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.NewEncoder(r).Encode(H{"filename": "x.jpg", "sha256": "435dfslkdjfa;sldkfja;sdf"}); err != nil {
		t.Fatal(err)
	}
	r, err = f.CreateFormFile("file", "file.jpg")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = r.Write([]byte("asdfasdf"))
	log.Println(buf.String())
}
func TestNewRandStr(t *testing.T) {
	log.SetFlags(log.Ltime | log.Lshortfile)
	mchId := "1276387801"
	sslCrt := []byte("-----BEGIN CERTIFICATE-----\nMIID8DCCAtigAwIBAgIUXbQoC1THyO2teqJpuMEqWWl5iwcwDQYJKoZIhvcNAQEL\nBQAwXjELMAkGA1UEBhMCQ04xEzARBgNVBAoTClRlbnBheS5jb20xHTAbBgNVBAsT\nFFRlbnBheS5jb20gQ0EgQ2VudGVyMRswGQYDVQQDExJUZW5wYXkuY29tIFJvb3Qg\nQ0EwHhcNMjAxMjMxMDYxNzMwWhcNMjUxMjMwMDYxNzMwWjCBgTETMBEGA1UEAwwK\nMTI3NjM4NzgwMTEbMBkGA1UECgwS5b6u5L+h5ZWG5oi357O757ufMS0wKwYDVQQL\nDCTljJfkuqzlo7nmraXmk43kvZznp5HmioDmnInpmZDlhazlj7gxCzAJBgNVBAYM\nAkNOMREwDwYDVQQHDAhTaGVuWmhlbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAKwbbmr7yld9XUd6THxVx47bBYLriEC2/Y89o+ohblvJj4N2DmF5cJWA\naRRs9i1l9zcGgxQvkufxyf88/KOh4wckmEbBsS/ozbJ2v0W8Ft30Kcf6UL0/Kod0\ni3j/pwgDlJcS0X6UTCByIeCDm0m/RKFGQWUSZy6Gt7zE8KdWucLCaPSfO3RHEJfc\n50isGqdMtoU2nJqkiD71KZUNZMFoc55SNzN08cHCYpfysMhMvtaBcmFTtK/u4fru\n4RCOHdOXq5OzUhb4wvuscLzDfwfz1ZxCnq5GepQV0y7JL9o4XGcNqlYSsuT+0tOU\nQ1/eYkD6DLizXfkLo6AfR0eMdR/zVEMCAwEAAaOBgTB/MAkGA1UdEwQCMAAwCwYD\nVR0PBAQDAgTwMGUGA1UdHwReMFwwWqBYoFaGVGh0dHA6Ly9ldmNhLml0cnVzLmNv\nbS5jbi9wdWJsaWMvaXRydXNjcmw/Q0E9MUJENDIyMEU1MERCQzA0QjA2QUQzOTc1\nNDk4NDZDMDFDM0U4RUJEMjANBgkqhkiG9w0BAQsFAAOCAQEAE2gzOwbl5NE7QvRq\nqhXfW6UDA4cTDTZ5HRojNhdM6YyFLwXnIXngVH+aNH4AlpJ3/VczUHIv5T6+GheE\nGROeQO/Iouv21lTX+bS/Y72bBlwLwfwkRGUogmsbGH8szJuPLamkbaOoA2HGaCOu\nQLNdaYTGlpXOk69w7zWV7YMb7Tq2i1ACi5lYCMeaNgM697kQKKoNdcka6OoZeBff\nczwbbLVtxN+a75rgLZWhG1a5suh/Stte5EWe3dZcWjVtyPbMpBjYhAjg5byeAZVk\nntBPwx708DkrDCFNmnk+DV2Z6rKWA0axJb95YxPDdlSb6ofER1KtjTzL9bHzVho2\n2y+Rqw==\n-----END CERTIFICATE-----")
	sslKey := []byte("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsG25q+8pXfV1H\nekx8VceO2wWC64hAtv2PPaPqIW5byY+Ddg5heXCVgGkUbPYtZfc3BoMUL5Ln8cn/\nPPyjoeMHJJhGwbEv6M2ydr9FvBbd9CnH+lC9PyqHdIt4/6cIA5SXEtF+lEwgciHg\ng5tJv0ShRkFlEmcuhre8xPCnVrnCwmj0nzt0RxCX3OdIrBqnTLaFNpyapIg+9SmV\nDWTBaHOeUjczdPHBwmKX8rDITL7WgXJhU7Sv7uH67uEQjh3Tl6uTs1IW+ML7rHC8\nw38H89WcQp6uRnqUFdMuyS/aOFxnDapWErLk/tLTlENf3mJA+gy4s135C6OgH0dH\njHUf81RDAgMBAAECggEAJVMppjAHGORKR4chcVGVHsknL9ZuzUIiSV9f3hXz/hn/\ncs42njMdFH8tys06smvLqnZSFR2gKYdJfH44eDBSsSjhkW7OQ4qkmZChOLlq6CXc\nrc7+lZxOV+QRn2MqUVWdcwoUvvPgcqTt7ef81IiTlLpM0mOkVvXGgTzgyBnJ3Y+6\nvPgALGAWTVxngyDkyK1BbAr4zeMweX5uiC0daCkKBNYIOJUDGtBIeu2JYOo63/s8\ng4RcgYOL1rYmAZM6bfhdI4uAn6IQN8nHtcUlwCkrTRkECQb7g8oh5ysXpSFkA59x\ngzowQQbo9cJoPLsldyn5Us3oVUILrnDHOE/yEWhGcQKBgQDgiAZhSDSxIKVbRdUq\n1Waq4+1V6Odb120CjZvXk5o0/nr0D+xIp05r5CKx33m4jAMj5EV4w8QDLSbmub0z\nA16yf3Q2KL12X7V9P7lRIttJaGYcSARVoIHm+Srvr/3eooAB0LxsWrMQB6ErihW9\nUS5ZK3/GIKoJxGvqueMTk/M+WwKBgQDEOnmr5LRuB3EYtW+kMlUaic9W/1VY/TFM\nt3EpqNE/1VpHN2WB5SGlH6qGoymFO8adVH7cVjgjekwZQIynI9GHqUN7n8vhtmyB\nH1PbDbtPlqZT7bS09X5QcGPuo9xXdOpcqV2iNz265T/XR1vHNRQnUQ5uvVbCUlpx\nqVMZJs32OQKBgQDAAvNZzDLratyd8lk6eSaEa8iyGCuKOe8KKOml8J8GRL4G63sI\nIrOIxp74+ACS1oF09yiF/vwoLzu+QgbPkkkwYpiSHELx8SU2iAFFpoZa/4GbG+dB\nBrMwP9L9CMcU1mibpNMN4n6Q7cVhg4PV04/MR8vMNnDTS3tyTycmvfZdUwKBgGgt\nBzVb2PJlHwTYJioM0qOhMCNmsP/qg4bQCNLuHhD+iswuO8SnSaJpWlXaP4vNPVd/\naU4+s9UZ81agr0t4t5+HHB2Aq3PsLlSqthEgjCXnu+vo0bwUbPf1gwhJlAwWNOn2\nvJAHNc2IMclvx+jNZCKvZLMj7/CAWiXnmAdNU6D5AoGAN4c0EsKkmSdKuHmwJQLI\nziHuMFfTf8ahsLAEPabHwe3OZM0pbGHsxp0Yd+98jN8nyEgraES1r4scKi8Ksg+y\nSX9fqtlwwvQHP6/INNTOcRviCUCuh4+kD7jhz0bENu1Oa/u9/jDUatMA2LAtoPVx\nsY96UkR0maga41wGvMW5UdY=\n-----END PRIVATE KEY-----")

	cb, _ := pem.Decode(sslCrt)
	pubKey, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ = pem.Decode(sslKey)
	priKey, err := x509.ParsePKCS8PrivateKey(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	h := sha256.New()
	ts := time.Now().Unix()
	rs := NewRandStr(32)

	req, err := http.NewRequest(http.MethodGet, "https://api.mch.weixin.qq.com/v3/certificates", nil)
	if err != nil {
		t.Fatal(err)
	}

	str := fmt.Sprintf("%v\n%v\n%v\n%v\n%v\n", req.Method, req.URL.Path, ts, rs, "")
	h.Write([]byte(str))
	signRaw, err := rsa.SignPKCS1v15(rand2.Reader, priKey.(*rsa.PrivateKey), crypto.SHA256, h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", fmt.Sprintf(`WECHATPAY2-SHA256-RSA2048 mchid="%v",nonce_str="%v",signature="%v",timestamp="%v",serial_no="%X"`,
		mchId, rs, base64.StdEncoding.EncodeToString(signRaw), ts, pubKey.SerialNumber))
	req.Header.Set("User-Agent", "Gdb/1.0")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := ioutil.ReadAll(resp.Body)
	log.Println(resp.Status, string(raw))

	str = fmt.Sprintf("%v\n%v\n%v\n",
		resp.Header.Get("Wechatpay-Timestamp"),
		resp.Header.Get("Wechatpay-Nonce"), string(raw))
	signRaw, err = base64.StdEncoding.DecodeString(resp.Header.Get("Wechatpay-Signature"))
	if err != nil {
		log.Fatal(err)
	}

	log.Println(pubKey.PublicKey.(*rsa.PublicKey))
	log.Printf("pubKey.SerialNumber: %X\n", pubKey.SerialNumber)
	h.Reset()
	h.Write([]byte(str))
	err = rsa.VerifyPKCS1v15(pubKey.PublicKey.(*rsa.PublicKey), crypto.SHA256, h.Sum(nil), signRaw)
	if err != nil {
		log.Println(">>>>>>>>>>", err)
	}

	for s, strings := range resp.Header {
		log.Println("resp.Header ->", s, strings)
	}

	var res struct {
		Data []struct {
			EffectiveTime      time.Time `json:"effective_time"`
			EncryptCertificate struct {
				Algorithm      string `json:"algorithm"`
				AssociatedData string `json:"associated_data"`
				Ciphertext     string `json:"ciphertext"`
				Nonce          string `json:"nonce"`
			} `json:"encrypt_certificate"`
			ExpireTime time.Time `json:"expire_time"`
			SerialNo   string    `json:"serial_no"`
		} `json:"data"`
	}
	if err = json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	log.Println(res)
	// AEAD_AES_256_GCM
	cipherRaw, _ := base64.StdEncoding.DecodeString(res.Data[0].EncryptCertificate.Ciphertext)
	block, err := aes.NewCipher([]byte("14da084a425129ed376084a49caae96b"))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := gcm.Open(nil, []byte(res.Data[0].EncryptCertificate.Nonce), cipherRaw, []byte(res.Data[0].EncryptCertificate.AssociatedData))
	if err != nil {
		t.Fatal(err)
	}
	log.Println(string(plain))
	raw, err = rsa.EncryptOAEP(sha1.New(), rand2.Reader, pubKey.PublicKey.(*rsa.PublicKey), []byte("name"), nil)
	if err != nil {
		t.Fatal(err)
	}
	log.Println(base64.StdEncoding.EncodeToString(raw))
}

func TestLimitString2(t *testing.T) {
	log.Printf("%x", sha256.Sum256([]byte("abcd\n")))
}

func TestClientMiddleware(t *testing.T) {
	log.SetFlags(log.Ltime | log.Lshortfile)
	log.Println(_hook == nil)
	cli := &http.Client{Transport: &mt{http.Transport{}}}
	log.Println(cli.Get("https://cashier.mywsy.cn"))
}
