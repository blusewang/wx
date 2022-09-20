// Copyright 2020 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package wx

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/blusewang/wx/mch_api_v3"
	"io/ioutil"
	"log"
	"net/http"
	"path"
	"strings"
	"time"
)

var (
	// wechatPayCerts 微信支付官方证书缓存
	wechatPayCerts = NewPayCerManager()
)

// 商户请求
type mchReqV3 struct {
	account  MchAccount
	api      mch_api_v3.MchApiV3
	sendData interface{}
	res      interface{}
	err      error
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
func (mr *mchReqV3) Do(method string) (err error) {
	if wechatPayCerts.IsEmpty() {
		if err = mr.account.DownloadV3Cert(); err != nil {
			return
		}
	}
	var buf = new(bytes.Buffer)
	if mr.sendData != nil {
		if err = json.NewEncoder(buf).Encode(mr.sendData); err != nil {
			return
		}
	}
	api := fmt.Sprintf("https://api.mch.weixin.qq.com/v3/%v", mr.api)
	if strings.HasPrefix(string(mr.api), "http") {
		api = string(mr.api)
	}
	var cli = client()
	req, err := http.NewRequest(method, api, bytes.NewReader(buf.Bytes()))
	if err != nil {
		return
	}
	if err = mr.sign(req, buf.Bytes()); err != nil {
		return
	}
	resp, err := cli.Do(req)
	defer resp.Body.Close()
	if err != nil {
		return
	}
	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
		var rs mch_api_v3.ErrorResp
		_ = json.Unmarshal(raw, &rs)
		return errors.New(rs.Message)
	}
	if mr.api != mch_api_v3.OtherCertificates {
		if err = mr.account.VerifyV3(resp.Header, raw); err != nil {
			return
		}
	}
	if resp.StatusCode == http.StatusOK {
		if mr.res != nil {
			return json.Unmarshal(raw, &mr.res)
		} else {
			return
		}
	} else {
		return
	}
}

// Upload 上传图片视频
func (mr *mchReqV3) Upload(fileName string, raw []byte) (err error) {
	// 准备证书
	if wechatPayCerts.IsEmpty() {
		if err = mr.account.DownloadV3Cert(); err != nil {
			return
		}
	}
	// 准备描述
	s := sha256.New()
	s.Write(raw)
	meta, err := json.Marshal(H{"filename": fileName, "sha256": fmt.Sprintf("%X", s.Sum(nil))})
	if err != nil {
		return
	}
	// 开始构建请求体
	// 微信不承认golang 自带的 multipart 规范
	var body = new(bytes.Buffer)
	var nonce = NewRandStr(23)
	var boundary = fmt.Sprintf("--%v\r\n", nonce)
	body.WriteString(boundary)
	body.WriteString("Content-Disposition: form-data; name=\"meta\";\r\n")
	body.WriteString("Content-Type: application/json\r\n\r\n")
	body.Write(meta)
	body.WriteString("\r\n")
	body.WriteString(boundary)
	body.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=\"file\"; filename=\"%v\";\r\n", fileName))
	body.WriteString(fmt.Sprintf("Content-Type: image/%v\r\n\r\n", path.Ext(fileName)))
	body.Write(raw)
	body.WriteString("\r\n")
	body.WriteString(fmt.Sprintf("--%v--\r\n", nonce))

	// 构建API地址
	api := fmt.Sprintf("https://api.mch.weixin.qq.com/v3/%v", mr.api)
	if strings.HasPrefix(string(mr.api), "http") {
		api = string(mr.api)
	}
	// 构建请求
	req, err := http.NewRequest(http.MethodPost, api, bytes.NewReader(body.Bytes()))
	if err != nil {
		return
	}
	// 签名
	if err = mr.sign(req, meta); err != nil {
		return
	}
	req.Header.Set("Content-Type", "multipart/form-data")
	// 网络操作
	resp, err := client().Do(req)
	defer resp.Body.Close()
	if err != nil {
		return
	}

	// 处理结果
	raw, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
		var rs mch_api_v3.ErrorResp
		_ = json.Unmarshal(raw, &rs)
		log.Println(api, rs, resp.Header.Get("Request-ID"))
		return errors.New(fmt.Sprintf("%v | Request-ID:%v", rs.Message, resp.Header.Get("Request-ID")))
	}
	if err = mr.account.VerifyV3(resp.Header, raw); err != nil {
		return
	}
	if resp.StatusCode == http.StatusOK {
		return json.Unmarshal(raw, &mr.res)
	} else {
		return
	}
}

func (mr *mchReqV3) sign(request *http.Request, body []byte) (err error) {
	request.Header.Set("User-Agent", "Gdb/1.0")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if !wechatPayCerts.IsEmpty() {
		request.Header.Set("Wechatpay-Serial", wechatPayCerts.GetSerialNo())
	}
	if body == nil {
		body = make([]byte, 0)
	}
	nonce := NewRandStr(32)
	ts := time.Now().Unix()
	sign, err := mr.account.SignBaseV3(fmt.Sprintf("%v\n%v\n%v\n%v\n%v\n", request.Method,
		request.URL.RequestURI(), ts, nonce, string(body)))
	if err != nil {
		return
	}
	request.Header.Set("Authorization", fmt.Sprintf(`WECHATPAY2-SHA256-RSA2048 mchid="%v",nonce_str="%v",signature="%v",timestamp="%v",serial_no="%X"`,
		mr.account.MchId, nonce, sign, ts, mr.account.certX509.SerialNumber))
	return
}
