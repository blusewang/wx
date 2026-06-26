// Copyright 2020 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package wx

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
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
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/blusewang/wx/mch_api"
	"github.com/blusewang/wx/mch_api_v3"
)

// MchAccount 商户账号
type MchAccount struct {
	MchId          string
	MchKeyV2       string
	MchKeyV3       string
	certTls        tls.Certificate              // 我的证书 tls版 用于传输
	certX509       *x509.Certificate            // 我的证书 x509版 用于辅助加解密
	privateKey     *rsa.PrivateKey              // 我的Key
	publicKeyWxPay *rsa.PublicKey               // 加密银行卡信息时用的微信支付的公钥
	platformCert   map[string]*x509.Certificate // 平台证书缓存
	Err            error
	lastUpdateTime time.Time
}

// NewMchAccount 实例化商户账号
func NewMchAccount(ctx context.Context, mchId string, key2 *string, key3 string, cert, key, pubKey []byte, platformCerts [][]byte) (ma *MchAccount) {
	ma = &MchAccount{
		MchId:        mchId,
		MchKeyV3:     key3,
		platformCert: make(map[string]*x509.Certificate),
	}
	if key2 != nil {
		ma.MchKeyV2 = *key2
	}
	if ma.certX509, ma.Err = x509.ParseCertificate(cert); ma.Err != nil {
		log.Println(ma.Err)
		return
	}
	var o any
	o, ma.Err = x509.ParsePKCS8PrivateKey(key)
	if ma.Err != nil {
		return
	}
	ma.privateKey = o.(*rsa.PrivateKey)
	ma.certTls.Certificate = [][]byte{cert}
	ma.certTls.PrivateKey = key
	ma.publicKeyWxPay, ma.Err = x509.ParsePKCS1PublicKey(pubKey)
	for i := range platformCerts {
		_c, err := x509.ParseCertificate(platformCerts[i])
		if err != nil {
			return
		}
		ma.platformCert[fmt.Sprintf("%X", _c.SerialNumber)] = _c
	}
	ma.Err = ma.DownloadV3Cert(ctx)
	return
}

// NewMchReqWithApp 创建请求
func (ma MchAccount) NewMchReqWithApp(api mch_api.MchApi, appId string) IMchRequester {
	return new(mchReq{account: ma, api: api, appId: appId})
}

// NewMchReq 创建请求
func (ma MchAccount) NewMchReq(api mch_api.MchApi) IMchRequester {
	return &mchReq{account: ma, api: api}
}

// OrderSign4App 订单签名给App
func (ma MchAccount) OrderSign4App(or mch_api.PayUnifiedOrderRes) H {
	data := make(H)
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
func (ma MchAccount) OrderSign(or mch_api.PayUnifiedOrderRes) H {
	data := make(H)
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
	block, err := aes.NewCipher([]byte(fmt.Sprintf("%x", md5.Sum([]byte(ma.MchKeyV2)))))
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

// RsaEncrypt 机要信息加密V2
func (ma MchAccount) RsaEncrypt(plain string) (out string) {
	raw, err := rsa.EncryptOAEP(sha1.New(), rand2.Reader, ma.publicKeyWxPay, []byte(plain), nil)
	if err != nil {
		return
	}
	out = base64.StdEncoding.EncodeToString(raw)
	return
}

// RsaEncryptV3 机要信息加密V3
func (ma MchAccount) RsaEncryptV3(ctx context.Context, plain string) (out string) {
	var pk, err = ma.GetCertificate(ctx)
	if err != nil {
		return
	}
	raw, err := rsa.EncryptOAEP(sha1.New(), rand2.Reader, pk.PublicKey.(*rsa.PublicKey), []byte(plain), nil)
	if err != nil {
		return
	}
	out = base64.StdEncoding.EncodeToString(raw)
	return
}

// RsaDecrypt 机要信息解密 兼容V2/V3
func (ma MchAccount) RsaDecrypt(ciphertext string) (out string, err error) {
	raw, _ := base64.StdEncoding.DecodeString(ciphertext)
	raw, err = rsa.DecryptOAEP(sha1.New(), rand2.Reader, ma.privateKey, raw, nil)
	if err != nil {
		return
	}
	out = string(raw)
	return
}

// DecryptAES256GCM AEAD_AES_256_GCM 解密
func (ma MchAccount) DecryptAES256GCM(nonce, associatedData, ciphertext string) (out []byte, err error) {
	decodedCiphertext, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return
	}
	block, err := aes.NewCipher([]byte(ma.MchKeyV3))
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	out, err = gcm.Open(nil, []byte(nonce), decodedCiphertext, []byte(associatedData))
	return
}

func (ma MchAccount) signMd5(obj interface{}) string {
	return fmt.Sprintf("%X", md5.Sum([]byte(mapSortByKey(obj2map(obj))+"&key="+ma.MchKeyV2)))
}

func (ma MchAccount) signHmacSha256(obj interface{}) string {
	hm := hmac.New(sha256.New, []byte(ma.MchKeyV2))
	hm.Write([]byte(mapSortByKey(obj2map(obj)) + "&key=" + ma.MchKeyV2))
	return fmt.Sprintf("%X", hm.Sum(nil))
}

func (ma MchAccount) orderSign(data map[string]interface{}) string {
	return fmt.Sprintf("%X", md5.Sum([]byte(mapSortByKey(data)+"&key="+ma.MchKeyV2)))
}

func (ma MchAccount) newPrivateClient(ctx context.Context) (cli *http.Client, err error) {
	cli = client(ctx)
	cli.Transport.(*mt).t.TLSClientConfig = &tls.Config{
		Certificates: []tls.Certificate{ma.certTls},
	}
	cli.Transport.(*mt).t.DisableCompression = true
	return
}

// NewMchReqV3 创建请求
func (ma MchAccount) NewMchReqV3(api mch_api_v3.MchApiV3) IMchV3Requester {
	return new(mchReqV3{account: ma, api: api})
}

// GetCertificate 获取证书
func (ma MchAccount) GetCertificate(ctx context.Context) (cert *x509.Certificate, err error) {
	if len(ma.platformCert) == 0 || ma.lastUpdateTime.Add(1*time.Hour).Before(time.Now()) {
		if err = ma.DownloadV3Cert(ctx); err != nil {
			return
		}
	}
	for s := range ma.platformCert {
		if ma.platformCert[s].NotAfter.Before(time.Now().AddDate(0, 0, -1)) {
			delete(ma.platformCert, s)
		} else if cert == nil {
			cert = ma.platformCert[s]
		} else {
			if ma.platformCert[s].NotAfter.After(cert.NotAfter) {
				cert = ma.platformCert[s]
			}
		}
	}
	return
}

// DownloadV3Cert 获取微信支付官方证书
func (ma MchAccount) DownloadV3Cert(ctx context.Context) (err error) {
	var res mch_api_v3.OtherCertificatesResp
	err = ma.NewMchReqV3(mch_api_v3.OtherCertificates).Bind(&res).Do(ctx, http.MethodGet)
	if err != nil {
		return
	}
	for _, item := range res.Data {
		ct, err := ma.DecryptAES256GCM(item.EncryptCertificate.Nonce, item.EncryptCertificate.AssociatedData, item.EncryptCertificate.Ciphertext)
		if err != nil {
			return err
		}
		cb, _ := pem.Decode(ct)
		cert, err := x509.ParseCertificate(cb.Bytes)
		if err != nil {
			return err
		}
		ma.platformCert[fmt.Sprintf("%X", cert.SerialNumber)] = cert
		ma.lastUpdateTime = time.Now()
	}
	return
}

// SignBaseV3 V3版通用签名
func (ma MchAccount) SignBaseV3(message string) (sign string, err error) {
	s := sha256.New()
	s.Write([]byte(message))
	raw, err := rsa.SignPKCS1v15(rand2.Reader, ma.privateKey, crypto.SHA256, s.Sum(nil))
	if err != nil {
		return
	}
	sign = base64.StdEncoding.EncodeToString(raw)
	return
}

// VerifyV3 验签
func (ma MchAccount) VerifyV3(ctx context.Context, header http.Header, body []byte) (err error) {
	if len(ma.platformCert) == 0 {
		if err = ma.DownloadV3Cert(ctx); err != nil {
			return
		}
	}
	cert := ma.platformCert[header.Get("Wechatpay-Serial")]
	if cert == nil {
		log.Println("未能在缓存中匹配到对方ID的证书", header.Get("Wechatpay-Serial"))
		return nil
	}
	signRaw, err := base64.StdEncoding.DecodeString(header.Get("Wechatpay-Signature"))
	if err != nil {
		return
	}
	s := sha256.New()
	s.Write([]byte(fmt.Sprintf("%v\n%s\n%s\n",
		header.Get("Wechatpay-Timestamp"),
		header.Get("Wechatpay-Nonce"), string(body))))
	return rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, s.Sum(nil), signRaw)
}

// SignJSAPIV3 JSAPI支付订单签名
func (ma MchAccount) SignJSAPIV3(appId, prepayId string) (out H, err error) {
	ts := time.Now().Unix()
	nonce := NewRandStr(32)
	s, err := ma.SignBaseV3(fmt.Sprintf("%v\n%v\n%v\nprepay_id=%v\n", appId, ts, nonce, prepayId))
	if err != nil {
		return
	}
	out = H{
		"timestamp": fmt.Sprintf("%v", ts),
		"nonceStr":  nonce,
		"package":   fmt.Sprintf("prepay_id=%v", prepayId),
		"signType":  "RSA",
		"paySign":   s,
	}
	return
}

// SignAppV3 App支付订单签名
func (ma MchAccount) SignAppV3(appId, prepayId string) (out H, err error) {
	ts := time.Now().Unix()
	nonce := NewRandStr(32)
	s, err := ma.SignBaseV3(fmt.Sprintf("%v\n%v\n%v\n%v\n", appId, ts, nonce, prepayId))
	if err != nil {
		return
	}
	out = H{
		"partnerid": ma.MchId,
		"prepayid":  prepayId,
		"package":   "Sign=WXPay",
		"noncestr":  nonce,
		"timestamp": ts,
		"sign":      s,
	}
	return
}

func (ma MchAccount) PlatformCertificates() (certs []*x509.Certificate) {
	for s := range ma.platformCert {
		certs = append(certs, ma.platformCert[s])
	}
	return
}
