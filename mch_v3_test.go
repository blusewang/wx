// Copyright 2020 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package wx

import (
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
	"net/http"
	"testing"
	"time"
)

func TestNewRandStr(t *testing.T) {
	log.SetFlags(log.Ltime | log.Lshortfile)
	mchId := ""
	sslCrt := []byte("")
	sslKey := []byte("")

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
	log.Printf("%X\n", pubKey.SerialNumber)
	h.Reset()
	h.Write([]byte(str))
	err = rsa.VerifyPKCS1v15(pubKey.PublicKey.(*rsa.PublicKey), crypto.SHA256, h.Sum(nil), signRaw)
	if err != nil {
		log.Println(err)
	}

	for s, strings := range resp.Header {
		log.Println(s, strings)
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
