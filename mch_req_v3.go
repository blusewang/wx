// Copyright 2020 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package wx

import (
	"crypto"
	rand2 "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/blusewang/wx/mch_api"
	"hash"
	"net/http"
)

// 商户请求
type mchReqV3 struct {
	account     MchAccount
	cert        *x509.Certificate
	privateKey  *rsa.PrivateKey
	hashHandler hash.Hash
	api         mch_api.MchApi
	ts          int64
	nonceStr    string
	sendData    interface{}
	res         interface{}
	err         error
}

// Send 填充POST里的Body数据
func (mr *mchReqV3) Send(data interface{}) *mchReqV3 {
	mr.sendData = data
	return mr
}

// Bind 绑定请求结果的解码数据体
func (mr *mchReqV3) Bind(data interface{}) *mchReqV3 {
	mr.res = data
	return mr
}

// Do 执行
func (mr *mchReqV3) Do() (err error) {

	return
}

func (mr *mchReqV3) prepareCert() (err error) {
	cb, _ := pem.Decode(mr.account.MchSSLCert)
	mr.cert, err = x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return
	}
	cb, _ = pem.Decode(mr.account.MchSSLKey)
	key, err := x509.ParsePKCS8PrivateKey(cb.Bytes)
	if err != nil {
		return
	}
	mr.privateKey = key.(*rsa.PrivateKey)
	mr.hashHandler = sha256.New()
	return
}

func (mr *mchReqV3) sign(request *http.Request, body interface{}) (err error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return
	}
	mr.nonceStr = NewRandStr(32)
	str := fmt.Sprintf("%v\n%v\n%v\n%v\n%v\n", request.Method, request.URL.Path, mr.ts, mr.nonceStr, string(raw))
	mr.hashHandler.Reset()
	mr.hashHandler.Write([]byte(str))
	signRaw, err := rsa.SignPKCS1v15(rand2.Reader, mr.privateKey, crypto.SHA256, mr.hashHandler.Sum(nil))
	if err != nil {
		return
	}

	request.Header.Set("Authorization", fmt.Sprintf(`WECHATPAY2-SHA256-RSA2048 mchid="%v",nonce_str="%v",signature="%v",timestamp="%v",serial_no="%X"`,
		mr.account.MchId, mr.nonceStr, base64.StdEncoding.EncodeToString(signRaw), mr.ts, mr.cert.SerialNumber))
	request.Header.Set("User-Agent", "Gdb/1.0")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	return
}
