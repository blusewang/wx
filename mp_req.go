// Copyright 2020 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package wx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/blusewang/wx/mp_api"
	"github.com/google/go-querystring/query"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"reflect"
)

// Api请求数据体
type mpReq struct {
	account  MpAccount
	path     mp_api.MpApi
	param    interface{}
	sendData interface{}
	res      interface{}
	err      error
}

// Query 填充查询信息
// access_token 会自动填充，无需指定
func (mp *mpReq) Query(d interface{}) *mpReq {
	mp.param = d
	return mp
}

// SendData 填充POST里的Body数据
func (mp *mpReq) SendData(d interface{}) *mpReq {
	mp.sendData = d
	return mp
}

// Bind 绑定请求结果的解码数据体
func (mp *mpReq) Bind(d interface{}) *mpReq {
	if reflect.ValueOf(d).Kind() != reflect.Ptr {
		mp.err = errors.New("mp.Bind must be Ptr")
	}
	mp.res = d
	return mp
}

// Download 下载
func (mp *mpReq) Download() (resp *http.Response, err error) {
	if mp.err != nil {
		err = mp.err
		return
	}

	var v url.Values
	v, err = query.Values(mp.param)
	if err != nil {
		return
	}

	if mp.account.AccessToken != "" {
		v.Set("access_token", mp.account.AccessToken)
	}
	if mp.account.ServerHost == "" {
		mp.account.ServerHost = mp_api.ServerHostUniversal
	}
	var apiUrl = fmt.Sprintf("https://%v/%v?%v", mp.account.ServerHost, mp.path, v.Encode())
	var req *http.Request
	if mp.sendData == nil {
		req, err = http.NewRequest(http.MethodGet, apiUrl, nil)
	} else {
		var buf = new(bytes.Buffer)
		var coder = json.NewEncoder(buf)
		coder.SetEscapeHTML(false)
		if err = coder.Encode(mp.sendData); err != nil {
			return
		}
		req, err = http.NewRequest(http.MethodPost, apiUrl, buf)
		req.Header.Set("Content-Type", "application/json")
	}
	if err != nil {
		return
	}
	return client().Do(req)
}

// Do 执行
func (mp *mpReq) Do() (err error) {
	if mp.err != nil {
		return mp.err
	}

	var v url.Values
	v, err = query.Values(mp.param)
	if err != nil {
		return err
	}

	if mp.account.AccessToken != "" {
		v.Set("access_token", mp.account.AccessToken)
	}
	if mp.account.ServerHost == "" {
		mp.account.ServerHost = mp_api.ServerHostUniversal
	}
	var apiUrl = fmt.Sprintf("https://%v/%v?%v", mp.account.ServerHost, mp.path, v.Encode())
	var req *http.Request
	if mp.sendData == nil {
		req, err = http.NewRequest(http.MethodGet, apiUrl, nil)
	} else {
		var buf = new(bytes.Buffer)
		var coder = json.NewEncoder(buf)
		coder.SetEscapeHTML(false)
		if err = coder.Encode(mp.sendData); err != nil {
			return
		}
		req, err = http.NewRequest(http.MethodPost, apiUrl, buf)
		req.Header.Set("Content-Type", "application/json")
	}
	if err != nil {
		return
	}
	resp, err := client().Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return
	}
	if mp.res == nil {
		mp.res = &mp_api.MpBaseResp{}
	}
	if err = json.NewDecoder(resp.Body).Decode(mp.res); err != nil {
		return
	}
	rv := reflect.ValueOf(mp.res).Elem()
	for i := 0; i < rv.NumField(); i++ {
		iv := rv.Field(i)
		if iv.Type().String() == "mp_api.MpBaseResp" {
			if iv.FieldByName("ErrCode").Int() > 0 {
				err = errors.New(fmt.Sprintf("%v %v", iv.FieldByName("ErrCode").Int(), iv.FieldByName("ErrMsg").String()))
				return
			}
		}
	}
	bs, has := mp.res.(*mp_api.MpBaseResp)
	if has {
		if bs.ErrCode > 0 {
			err = errors.New(fmt.Sprintf("%v %v", bs.ErrCode, bs.ErrMsg))
		}
	}
	return
}

// Upload 上传文档。
// reader 一个打开的文件reader。
// fileExtension 该文件的后缀名。
func (mp *mpReq) Upload(reader io.Reader, fileExtension string) (err error) {
	if mp.err != nil {
		return mp.err
	}

	var v url.Values
	v, err = query.Values(mp.param)
	if err != nil {
		return err
	}

	if mp.account.AccessToken != "" {
		v.Set("access_token", mp.account.AccessToken)
	}
	if mp.account.ServerHost == "" {
		mp.account.ServerHost = mp_api.ServerHostUniversal
	}
	var apiUrl = fmt.Sprintf("https://%v/%v?%v", mp.account.ServerHost, mp.path, v.Encode())
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	wf, err := w.CreateFormFile("media", fmt.Sprintf("/tmp/%v.%v", NewRandStr(23), fileExtension))
	if err != nil {
		return
	}
	if _, err = io.Copy(wf, reader); err != nil {
		return
	}
	// 关闭`w`令数据从缓冲区刷写入`body`
	if err = w.Close(); err != nil {
		return
	}
	resp, err := client().Post(apiUrl, w.FormDataContentType(), body)
	defer resp.Body.Close()
	if err != nil {
		return
	}
	if mp.res == nil {
		mp.res = &mp_api.MpBaseResp{}
	}
	if err = json.NewDecoder(resp.Body).Decode(mp.res); err != nil {
		return
	}
	bs, has := mp.res.(*mp_api.MpBaseResp)
	if has {
		if bs.ErrCode > 0 {
			err = errors.New(fmt.Sprintf("%v %v", bs.ErrCode, bs.ErrMsg))
		}
	}
	return
}
