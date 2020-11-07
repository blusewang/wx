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
	"log"
	"net/http"
	"reflect"
	"strings"
)

var privateClientCache = make(map[string]*http.Client)

// 商户请求
type mchReq struct {
	account         MchAccount
	privateClient   *http.Client // 私有加密传输客户端
	api             mch_api.MchApi
	appId           string
	isHmacSign      bool
	isPrivateClient bool
	sendData        interface{}
	res             interface{}
	err             error
}

// 填充POST里的Body数据
func (mr *mchReq) Send(data interface{}) *mchReq {
	mr.sendData = data
	return mr
}

// 使用 HMAC-SHA256 签名
// 默认采用 MD5 签名
func (mr *mchReq) UseHMacSign() *mchReq {
	mr.isHmacSign = true
	return mr
}

// 使用私有证书通信
func (mr *mchReq) UsePrivateCert() *mchReq {
	mr.isPrivateClient = true
	return mr
}

// 绑定请求结果的解码数据体
func (mr *mchReq) Bind(data interface{}) *mchReq {
	mr.res = data
	return mr
}

// 执行
func (mr *mchReq) Do() (err error) {
	var cli = *http.DefaultClient
	if mr.isPrivateClient {
		if privateClientCache[mr.account.MchId] != nil {
			cli = *privateClientCache[mr.account.MchId]
		} else {
			cli, err = mr.account.newPrivateClient()
			if err != nil {
				return
			}
			privateClientCache[mr.account.MchId] = &cli
		}
	}
	if err = mr.sign(); err != nil {
		return
	}

	var buf = new(bytes.Buffer)
	if err = xml.NewEncoder(buf).Encode(mr.sendData); err != nil {
		return
	}
	log.Println(buf.String())
	api := fmt.Sprintf("https://api.mch.weixin.qq.com/%v", mr.api)
	if strings.HasPrefix(string(mr.api), "http") {
		api = string(mr.api)
	}
	resp, err := cli.Post(api, "application/xml", buf)
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

	if reflect.ValueOf(mr.sendData).Kind() != reflect.Ptr {
		return errors.New("the send data must be ptr")
	}

	var base = reflect.ValueOf(mr.sendData).Elem().FieldByName("MchBase")
	base.FieldByName("MchId").SetString(mr.account.MchId)
	base.FieldByName("AppId").SetString(mr.appId)
	base.FieldByName("NonceStr").SetString(NewRandStr(32))

	var sign string
	//base.FieldByName("SignType").SetString(mch_api.MchSignTypeMD5)
	if mr.isHmacSign {
		base.FieldByName("SignType").SetString(mch_api.MchSignTypeHMACSHA256)
		sign = mr.account.signHmacSha256(mr.sendData)
	} else {
		sign = mr.account.signMd5(mr.sendData)
	}
	base.FieldByName("Sign").SetString(sign)
	return
}
