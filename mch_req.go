// Copyright 2020 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package wx

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/blusewang/wx/mch_api"
	"net/http"
	"reflect"
	"strings"
)

// 商户请求
type mchReq struct {
	account MchAccount
	//privateClient   *http.Client // 私有加密传输客户端
	api             mch_api.MchApi
	appId           string
	isHmacSign      bool
	isPrivateClient bool
	sendData        interface{}
	res             interface{}
	err             error
}

// Send 填充POST里的Body数据
func (mr *mchReq) Send(data interface{}) *mchReq {
	mr.sendData = data
	return mr
}

// UseHMacSign 使用 HMAC-SHA256 签名
// 默认采用 MD5 签名
func (mr *mchReq) UseHMacSign() *mchReq {
	mr.isHmacSign = true
	return mr
}

// UsePrivateCert 使用私有证书通信
func (mr *mchReq) UsePrivateCert() *mchReq {
	mr.isPrivateClient = true
	return mr
}

// Bind 绑定请求结果的解码数据体
func (mr *mchReq) Bind(data interface{}) *mchReq {
	mr.res = data
	return mr
}

// Do 执行
func (mr *mchReq) Do() (err error) {
	if err = mr.sign(); err != nil {
		return
	}

	var buf = new(bytes.Buffer)
	if err = xml.NewEncoder(buf).Encode(mr.sendData); err != nil {
		return
	}
	api := fmt.Sprintf("https://api.mch.weixin.qq.com/%v", mr.api)
	if strings.HasPrefix(string(mr.api), "http") {
		api = string(mr.api)
	}
	var cli *http.Client
	if mr.isPrivateClient {
		cli, err = mr.account.newPrivateClient()
		if err != nil {
			return err
		}
	} else {
		cli = client()
	}
	resp, err := cli.Post(api, "application/xml", buf)
	defer resp.Body.Close()
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	if err = xml.NewDecoder(resp.Body).Decode(&mr.res); err != nil {
		return
	}
	return
}

func (mr *mchReq) sign() (err error) {
	if mr.sendData == nil {
		return errors.New("the data to be sign is not set")
	}

	vf := reflect.ValueOf(mr.sendData)
	if vf.Kind() != reflect.Ptr {
		return errors.New("the send data must be ptr")
	}

	if vf.Elem().FieldByName("MchBase").IsValid() {
		var base = vf.Elem().FieldByName("MchBase")
		base.FieldByName("MchId").SetString(mr.account.MchId)
		base.FieldByName("AppId").SetString(mr.appId)
		base.FieldByName("NonceStr").SetString(NewRandStr(32))

		var sign string
		if mr.isHmacSign {
			base.FieldByName("SignType").SetString(mch_api.MchSignTypeHMACSHA256)
			sign = mr.account.signHmacSha256(mr.sendData)
		} else {
			sign = mr.account.signMd5(mr.sendData)
		}
		base.FieldByName("Sign").SetString(sign)
	} else if vf.Elem().FieldByName("Sign").IsValid() && vf.Elem().FieldByName("NonceStr").IsValid() {
		vf.Elem().FieldByName("NonceStr").SetString(NewRandStr(32))
		var sign string
		if mr.isHmacSign {
			if vf.Elem().FieldByName("SignType").IsValid() {
				vf.Elem().FieldByName("SignType").SetString(mch_api.MchSignTypeHMACSHA256)
				sign = mr.account.signHmacSha256(mr.sendData)
			}
		} else {
			sign = mr.account.signMd5(mr.sendData)
		}
		vf.Elem().FieldByName("Sign").SetString(sign)
	}

	return
}
