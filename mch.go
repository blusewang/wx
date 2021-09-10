// Copyright 2020 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package wx

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	rand2 "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/blusewang/wx/mch_api"
	"net/http"
	"strconv"
	"time"
)

//var cache = make(map[string]*http.Client)

// MchAccount 商户账号
type MchAccount struct {
	MchId           string
	MchKey          string
	MchSSLCert      []byte // 私有加密传输时的证书
	MchSSLKey       []byte // 私有加密传输时的密钥
	MchRSAPublicKey []byte // 加密银行卡信息时用的公钥
}

// NewMchReqWithApp 创建请求
func (ma MchAccount) NewMchReqWithApp(api mch_api.MchApi, appId string) (req *mchReq) {
	return &mchReq{account: ma, api: api, appId: appId}
}

// NewMchReq 创建请求
func (ma MchAccount) NewMchReq(api mch_api.MchApi) (req *mchReq) {
	return &mchReq{account: ma, api: api}
}

// OrderSign4App 订单签名给App
func (ma MchAccount) OrderSign4App(or mch_api.PayUnifiedOrderRes) map[string]interface{} {
	data := make(map[string]interface{})
	data["appid"] = or.AppId
	data["partnerid"] = or.MchId
	data["prepayid"] = or.PrepayId
	data["package"] = "Sign=WXPay"
	data["noncestr"] = NewRandStr(32)
	data["timestamp"] = time.Now().Unix()
	data["sign"] = ma.orderSign(data)
	delete(data, "appid")
	return data
}

// OrderSign 订单签名，适用于H5、小程序
func (ma MchAccount) OrderSign(or mch_api.PayUnifiedOrderRes) map[string]interface{} {
	data := make(map[string]interface{})
	data["appId"] = or.AppId
	data["timeStamp"] = strconv.FormatInt(time.Now().Unix(), 10)
	data["nonceStr"] = NewRandStr(32)
	data["package"] = fmt.Sprintf("prepay_id=%v", or.PrepayId)
	data["signType"] = "MD5"
	data["paySign"] = ma.orderSign(data)
	delete(data, "appId")
	data["timestamp"] = data["timeStamp"]
	delete(data, "timeStamp")
	return data
}

// PayNotify 验证支付成功通知
func (ma MchAccount) PayNotify(pn mch_api.PayNotify) bool {
	if !pn.IsSuccess() || pn.Sign == "" {
		return false
	}
	sign := pn.Sign
	if pn.SignType == mch_api.MchSignTypeMD5 || pn.SignType == "" {
		if sign == ma.signMd5(pn) {
			return true
		}
	} else if pn.SignType == mch_api.MchSignTypeHMACSHA256 {
		if sign == ma.signHmacSha256(pn) {
			return true
		}
	}
	return false
}

// DecryptRefundNotify 验证支付成功通知
func (ma MchAccount) DecryptRefundNotify(rn mch_api.RefundNotify) (body mch_api.RefundNotifyBody, err error) {
	raw, err := base64.StdEncoding.DecodeString(rn.ReqInfo)
	if err != nil {
		return
	}
	block, err := aes.NewCipher([]byte(fmt.Sprintf("%x", md5.Sum([]byte(ma.MchKey)))))
	length := len(raw)
	size := block.BlockSize()
	decrypted := make([]byte, len(raw))
	for bs, be := 0, size; bs < len(raw); bs, be = bs+size, be+size {
		block.Decrypt(decrypted[bs:be], raw[bs:be])
	}
	up := int(decrypted[length-1])
	decrypted = decrypted[:length-up]
	err = xml.Unmarshal(decrypted, &body)
	return
}

// RsaEncrypt 银行卡机要信息加密
func (ma MchAccount) RsaEncrypt(plain string) (out string) {
	block, _ := pem.Decode(ma.MchRSAPublicKey)
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return
	}
	raw, err := rsa.EncryptOAEP(sha1.New(), rand2.Reader, publicKey, []byte(plain), nil)
	if err != nil {
		return
	}
	out = base64.StdEncoding.EncodeToString(raw)
	return
}

func (ma MchAccount) signMd5(obj interface{}) string {
	return fmt.Sprintf("%X", md5.Sum([]byte(mapSortByKey(obj2map(obj))+"&key="+ma.MchKey)))
}

func (ma MchAccount) signHmacSha256(obj interface{}) string {
	hm := hmac.New(sha256.New, []byte(ma.MchKey))
	hm.Write([]byte(mapSortByKey(obj2map(obj)) + "&key=" + ma.MchKey))
	return fmt.Sprintf("%X", hm.Sum(nil))
}

func (ma MchAccount) orderSign(data map[string]interface{}) string {
	return fmt.Sprintf("%X", md5.Sum([]byte(mapSortByKey(data)+"&key="+ma.MchKey)))
}

func (ma MchAccount) newPrivateClient() (cli *http.Client, err error) {
	block, restPem := pem.Decode(ma.MchSSLCert)
	if block == nil {
		err = errors.New("pem解析失败")
		return
	}
	var cert tls.Certificate
	cert.Certificate = append(cert.Certificate, block.Bytes)
	certDerBlockChain, _ := pem.Decode(restPem)
	if certDerBlockChain != nil {
		cert.Certificate = append(cert.Certificate, certDerBlockChain.Bytes)
	}
	// 解码pem格式的私钥
	var key interface{}
	keyDer, _ := pem.Decode(ma.MchSSLKey)
	if keyDer.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(keyDer.Bytes)
	} else if keyDer.Type == "PRIVATE KEY" {
		key, err = x509.ParsePKCS8PrivateKey(keyDer.Bytes)
	}
	if err != nil {
		return
	}
	cert.PrivateKey = key
	cli = client()
	cli.Transport.(*mt).t.TLSClientConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	cli.Transport.(*mt).t.DisableCompression = true
	//cli = http.Client{
	//	Transport: &http.Transport{
	//		TLSClientConfig: &tls.Config{
	//			Certificates: []tls.Certificate{cert},
	//		},
	//		DisableCompression: true,
	//	},
	//}
	return
}

// NewMchReqV3 创建请求
func (ma MchAccount) NewMchReqV3(api mch_api.MchApi) (req *mchReqV3) {
	return &mchReqV3{account: ma, api: api, hashHandler: sha256.New()}
}
