package wxApi

import (
	rand2 "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"
)

type H map[string]interface{}

func postWithCert(cert tls.Certificate, api string, body io.Reader) (resp *http.Response, err error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
			DisableCompression: true,
		},
	}
	req, err := http.NewRequest("POST", api, body)
	if err != nil {
		return
	}
	resp, err = client.Do(req)
	return
}

func postStreamWithCert(cert tls.Certificate, api string, data io.Reader) (body io.ReadCloser, err error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
			DisableCompression: true,
		},
	}
	req, err := http.NewRequest("POST", api, data)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	body = resp.Body
	return
}

// 安全地限制长度，并将微信不支持的字符替换成'x'，能满足商户平台的字符要求
func SafeString(str string, length int) string {
	if length <= 3 {
		return ""
	}
	runs := []rune(str)
	// 单字符长度高于3的，不是一般的utf8字符，剔除掉
	for k, v := range runs {
		switch len([]byte(string(v))) {
		case 1:
			// 全部放行
		case 3:
			if v < 19968 || v > 40869 {
				// 只支持中文
				runs[k] = 'x'
			}
		default:
			runs[k] = 'x'
		}
	}
	str = string(runs)
	if len(str) > length {
		var r2 []rune
		for k := range runs {

			if len(string(runs[:k])) <= length-3 {
				r2 = runs[:k]
			}
		}
		r2 = append(r2, '…')
		str = string(r2)
	}
	return str
}

// 限制长度，并将微信不支持的字符替换成'x'，能满足公众号App的字符要求
func LimitString(str string, length int) string {
	runs := []rune(str)
	// 单字符长度高于3的，不是一般的utf8字符，剔除掉
	for k, v := range runs {
		switch len([]byte(string(v))) {
		case 1:
			// 全部放行
		case 3:
			// 全部放行
		default:
			runs[k] = 'x'
		}
	}
	str = string(runs)
	if len(runs) > length {
		var r2 = runs[:length-1]
		r2 = append(r2, '…')
		str = string(r2)
	}
	return str
}

// 生成符合微信要求随机字符
func NewRandStr(length int) string {
	codes := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	codeLen := len(codes)
	data := make([]byte, length)
	rand.Seed(time.Now().UnixNano())

	for i := 0; i < length; i++ {
		idx := rand.Intn(codeLen)
		data[i] = codes[idx]
	}

	return string(data)
}
func obj2map(obj interface{}) (p map[string]interface{}) {
	vs := reflect.ValueOf(obj)
	if vs.Kind() == reflect.Ptr {
		vs = vs.Elem()
	}
	p = make(map[string]interface{})
	obj2mapOnce(vs, &p)
	return
}

func obj2mapOnce(vs reflect.Value, data *map[string]interface{}) {
	for i := 0; i < vs.NumField(); i++ {
		if vs.Type().Field(i).Anonymous {
			obj2mapOnce(vs.Field(i), data)
		} else {
			k := vs.Type().Field(i).Tag.Get("json")
			if k == "" {
				k = vs.Type().Field(i).Tag.Get("xml")
				if k == "xml" {
					continue
				}
			}
			if k == "sign" || k == "-" {
				continue
			}
			k = strings.Split(k, ",")[0]
			// 跳过空值
			if reflect.Zero(vs.Field(i).Type()).Interface() == vs.Field(i).Interface() {
				continue
			}
			(*data)[k] = vs.Field(i).Interface()
		}
	}
}

func mapSortByKey(data map[string]interface{}) string {
	var keys []string
	nData := ""
	for k := range data {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	for _, k := range keys {
		nData = fmt.Sprintf("%v&%v=%v", nData, k, data[k])
	}
	return nData[1:]
}

var certs = make(map[string]*tls.Certificate)

func parseCertificate(pemByte, keyByte []byte, password string) (cert *tls.Certificate, err error) {
	if certs[password] != nil {
		return certs[password], nil
	}

	block, restPem := pem.Decode(pemByte)
	if block == nil {
		err = errors.New("pem解析失败")
		return
	}

	var c tls.Certificate
	c.Certificate = append(c.Certificate, block.Bytes)
	certDerBlockChain, _ := pem.Decode(restPem)
	if certDerBlockChain != nil {
		c.Certificate = append(c.Certificate, certDerBlockChain.Bytes)
	}
	// 解码pem格式的私钥
	var key interface{}
	keyDer, _ := pem.Decode(keyByte)
	if keyDer.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(keyDer.Bytes)
	} else if keyDer.Type == "PRIVATE KEY" {
		key, err = x509.ParsePKCS8PrivateKey(keyDer.Bytes)
	}
	if err != nil {
		return
	}
	c.PrivateKey = key
	cert = &c
	certs[password] = cert
	return
}

func rsaEncrypt(rsaPubic []byte, plain string) (cipherText string, err error) {
	block, _ := pem.Decode(rsaPubic)
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return
	}
	raw, err := rsa.EncryptOAEP(sha1.New(), rand2.Reader, publicKey, []byte(plain), nil)
	if err != nil {
		return
	}
	cipherText = base64.StdEncoding.EncodeToString(raw)
	return
}
