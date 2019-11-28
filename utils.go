package wxApi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	rand2 "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"
)

type H map[string]interface{}

func parseXml(raw []byte, any interface{}) (err error) {
	err = xml.Unmarshal(raw, &any)
	return
}

func get(api string) (raw []byte, err error) {
	resp, err := http.Get(api)
	if err != nil {
		return
	}
	raw, err = ioutil.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return
}

func postJSON(api string, postData interface{}) (raw []byte, err error) {
	buf := &bytes.Buffer{}
	if err = json.NewEncoder(buf).Encode(postData); err != nil {
		return
	}
	resp, err := http.Post(api, "application/json", buf)
	if err != nil {
		return
	}
	raw, err = ioutil.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return
}

func getWithCert(cert tls.Certificate, api string) (raw []byte, err error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
			DisableCompression: true,
		},
	}
	req, err := http.NewRequest("GET", api, nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	raw, err = ioutil.ReadAll(resp.Body)
	return
}

func postWithCert(cert tls.Certificate, api string, body []byte) (raw []byte, err error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
			DisableCompression: true,
		},
	}
	req, err := http.NewRequest("POST", api, bytes.NewBuffer(body))
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	raw, err = ioutil.ReadAll(resp.Body)
	return
}

func postWithCert2(cert tls.Certificate, api string, body io.Reader) (resp *http.Response, err error) {
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

func XmlToMap(xmlStr string, isIgnoreFirst bool) map[string]interface{} {
	m := make(map[string]interface{})
	p := xml.NewDecoder(strings.NewReader(xmlStr))
	val := ""
	for {
		token, err := p.Token()
		if err != nil {
			break
		}
		switch t := token.(type) {
		case xml.StartElement:
			if isIgnoreFirst {
				isIgnoreFirst = false
				continue
			}
			val = t.Name.Local
		case xml.CharData:
			if val != "" {
				m[val] = string(t)
			}
		case xml.EndElement:
			val = ""
		}
	}
	return m
}

func SafeString(str string, length int) string {
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
	if len([]byte(str)) > length {
		var r2 []rune
		for k := range runs {
			if len([]byte(string(runs[:k]))) <= length {
				r2 = runs[:k]
			}
		}
		r2 = r2[:len(r2)-1]
		r2 = append(r2, '…')
		str = string(r2)
	}
	return str
}

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
	ts := reflect.TypeOf(obj)
	vs := reflect.ValueOf(obj)
	p = make(map[string]interface{})
	n := ts.NumField()
	for i := 0; i < n; i++ {
		k := ts.Field(i).Tag.Get("json")
		if k == "" {
			k = ts.Field(i).Tag.Get("xml")
			if k == "xml" {
				continue
			}
		}
		if k == "sign" || k == "-" {
			continue
		}
		// 跳过空值
		if reflect.Zero(vs.Field(i).Type()).Interface() == vs.Field(i).Interface() {
			continue
		}
		p[k] = vs.Field(i).Interface()
	}
	return
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

//EncryptMsg 加密消息
func encryptMsg(random, rawXMLMsg []byte, appID, aesKey string) (encryptMsg []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("panic error: err=%v", e)
			return
		}
	}()
	var key []byte
	key, err = aesKeyDecode(aesKey)
	if err != nil {
		panic(err)
	}
	ciphered := aesEncryptMsg(random, rawXMLMsg, appID, key)
	encryptMsg = []byte(base64.StdEncoding.EncodeToString(ciphered))
	return
}

//AESEncryptMsg ciphertext = AES_Encrypt[random(16B) + msg_len(4B) + rawXMLMsg + appId]
//参考：github.com/chanxuehong/wechat.v2
func aesEncryptMsg(random, rawXMLMsg []byte, appID string, aesKey []byte) (ciphered []byte) {
	const (
		BlockSize = 32            // PKCS#7
		BlockMask = BlockSize - 1 // BLOCK_SIZE 为 2^n 时, 可以用 mask 获取针对 BLOCK_SIZE 的余数
	)

	appIDOffset := 20 + len(rawXMLMsg)
	contentLen := appIDOffset + len(appID)
	amountToPad := BlockSize - contentLen&BlockMask
	plaintextLen := contentLen + amountToPad

	plaintext := make([]byte, plaintextLen)

	// 拼接
	copy(plaintext[:16], random)
	encodeNetworkByteOrder(plaintext[16:20], uint32(len(rawXMLMsg)))
	copy(plaintext[20:], rawXMLMsg)
	copy(plaintext[appIDOffset:], appID)

	// PKCS#7 补位
	for i := contentLen; i < plaintextLen; i++ {
		plaintext[i] = byte(amountToPad)
	}

	// 加密
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, aesKey[:16])
	mode.CryptBlocks(plaintext, plaintext)

	ciphered = plaintext
	return
}

//DecryptMsg 消息解密
func decryptMsg(appID, encryptedMsg, aesKey string) (random, rawMsgXMLBytes []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("panic error: err=%v", e)
			return
		}
	}()
	var encryptedMsgBytes, key, getAppIDBytes []byte
	encryptedMsgBytes, err = base64.StdEncoding.DecodeString(encryptedMsg)
	if err != nil {
		return
	}
	key, err = aesKeyDecode(aesKey)
	if err != nil {
		panic(err)
	}
	random, rawMsgXMLBytes, getAppIDBytes, err = aesDecryptMsg(encryptedMsgBytes, key)
	if err != nil {
		err = fmt.Errorf("消息解密失败,%v", err)
		return
	}
	if appID != string(getAppIDBytes) {
		err = fmt.Errorf("消息解密校验APPID失败")
		return
	}
	return
}

func aesKeyDecode(encodedAESKey string) (key []byte, err error) {
	if len(encodedAESKey) != 43 {
		err = fmt.Errorf("the length of encodedAESKey must be equal to 43")
		return
	}
	key, err = base64.StdEncoding.DecodeString(encodedAESKey + "=")
	if err != nil {
		return
	}
	if len(key) != 32 {
		err = fmt.Errorf("encodingAESKey invalid")
		return
	}
	return
}

// AESDecryptMsg ciphertext = AES_Encrypt[random(16B) + msg_len(4B) + rawXMLMsg + appId]
//参考：github.com/chanxuehong/wechat.v2
func aesDecryptMsg(ciphertext []byte, aesKey []byte) (random, rawXMLMsg, appID []byte, err error) {
	const (
		BlockSize = 32            // PKCS#7
		BlockMask = BlockSize - 1 // BLOCK_SIZE 为 2^n 时, 可以用 mask 获取针对 BLOCK_SIZE 的余数
	)

	if len(ciphertext) < BlockSize {
		err = fmt.Errorf("the length of ciphertext too short: %d", len(ciphertext))
		return
	}
	if len(ciphertext)&BlockMask != 0 {
		err = fmt.Errorf("ciphertext is not a multiple of the block size, the length is %d", len(ciphertext))
		return
	}

	plaintext := make([]byte, len(ciphertext)) // len(plaintext) >= BLOCK_SIZE

	// 解密
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, aesKey[:block.BlockSize()])
	mode.CryptBlocks(plaintext, ciphertext)

	// PKCS#7 去除补位
	amountToPad := int(plaintext[len(plaintext)-1])
	if amountToPad < 1 || amountToPad > BlockSize {
		err = fmt.Errorf("the amount to pad is incorrect: %d", amountToPad)
		return
	}
	plaintext = plaintext[:len(plaintext)-amountToPad]

	// 反拼接
	// len(plaintext) == 16+4+len(rawXMLMsg)+len(appId)
	if len(plaintext) <= 20 {
		err = fmt.Errorf("plaintext too short, the length is %d", len(plaintext))
		return
	}
	rawXMLMsgLen := int(decodeNetworkByteOrder(plaintext[16:20]))
	if rawXMLMsgLen < 0 {
		err = fmt.Errorf("incorrect msg length: %d", rawXMLMsgLen)
		return
	}
	appIDOffset := 20 + rawXMLMsgLen
	if len(plaintext) <= appIDOffset {
		err = fmt.Errorf("msg length too large: %d", rawXMLMsgLen)
		return
	}

	random = plaintext[:16:20]
	rawXMLMsg = plaintext[20:appIDOffset:appIDOffset]
	appID = plaintext[appIDOffset:]
	return
}

// 把整数 n 格式化成 4 字节的网络字节序
func encodeNetworkByteOrder(orderBytes []byte, n uint32) {
	orderBytes[0] = byte(n >> 24)
	orderBytes[1] = byte(n >> 16)
	orderBytes[2] = byte(n >> 8)
	orderBytes[3] = byte(n)
}

// 从 4 字节的网络字节序里解析出整数
func decodeNetworkByteOrder(orderBytes []byte) (n uint32) {
	return uint32(orderBytes[0])<<24 |
		uint32(orderBytes[1])<<16 |
		uint32(orderBytes[2])<<8 |
		uint32(orderBytes[3])
}
