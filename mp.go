package wxApi

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/blusewang/wxApi-go/mp_api"
	"github.com/google/go-querystring/query"
	"github.com/youkale/go-querystruct/params"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

// 应用账号
// ServerHost 默认为：mp_api.ServerHostUniversal
type MpAccount struct {
	AppId          string            `json:"app_id"`
	AccessToken    string            `json:"access_token"`
	AppSecret      string            `json:"app_secret"`
	PrivateToken   string            `json:"private_token"`
	EncodingAESKey string            `json:"encoding_aes_key"`
	JsSdkTicket    string            `json:"js_sdk_ticket"`
	ServerHost     mp_api.ServerHost `json:"server_host"`
}

// 读取通知消息
func (ma MpAccount) ReadMessage(req *http.Request) (msg mp_api.MessageData, err error) {
	var q mp_api.MessageQuery
	if err = params.Unmarshal(req.URL.Query(), &q); err != nil {
		return
	}
	if q.EchoStr != "" {
		return
	}
	if err = q.Validate(ma.PrivateToken); err != nil {
		return
	}
	if err = xml.NewDecoder(req.Body).Decode(&msg); err != nil {
		return
	}
	if msg.Encrypt != "" {
		if err = msg.ShouldDecode(ma.EncodingAESKey); err != nil {
			return
		}
	}
	return
}

func (ma MpAccount) UrlSign(u string) (d map[string]interface{}) {
	data := make(map[string]interface{})
	data["noncestr"] = NewRandStr(32)
	data["jsapi_ticket"] = ma.JsSdkTicket
	data["timestamp"] = time.Now().Unix()
	data["url"] = u
	d = make(map[string]interface{})
	d["appId"] = ma.AppId
	d["timestamp"] = data["timestamp"]
	d["nonceStr"] = data["noncestr"]

	str := mapSortByKey(data)
	raw := sha1.Sum([]byte(str))
	d["signature"] = strings.ToUpper(fmt.Sprintf("%x", raw))
	d["jsApiList"] = []string{}
	return
}

// Api请求数据体
type mpReq struct {
	account  MpAccount
	path     mp_api.MpApi
	param    interface{}
	sendData interface{}
	res      interface{}
	err      error
}

// 新建一个请求
func (ma MpAccount) NewMpReq(path mp_api.MpApi) *mpReq {
	return &mpReq{account: ma, path: path}
}

// 填充查询信息
// access_token 会自动填充，无需指定
func (mp *mpReq) Query(d interface{}) *mpReq {
	mp.param = d
	return mp
}

// 填充POST里的Body数据
func (mp *mpReq) SendData(d interface{}) *mpReq {
	mp.sendData = d
	return mp
}

// 绑定请求结果的解码数据体
func (mp *mpReq) Bind(d interface{}) *mpReq {
	if reflect.ValueOf(d).Kind() != reflect.Ptr {
		mp.err = errors.New("mp.Bind must be Ptr")
	}
	mp.res = d
	return mp
}

// 执行
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
	var resp *http.Response
	if mp.sendData == nil {
		resp, err = http.Get(apiUrl)
	} else {
		var buf = new(bytes.Buffer)
		if err = json.NewEncoder(buf).Encode(mp.sendData); err != nil {
			return
		}
		resp, err = http.Post(apiUrl, "application/json", buf)
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
	bs, has := mp.res.(*mp_api.MpBaseResp)
	if has {
		if bs.ErrCode > 0 {
			err = errors.New(fmt.Sprintf("%v %v", bs.ErrCode, bs.ErrMsg))
		}
	}
	return
}

// 上传文档。
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
	resp, err := http.Post(apiUrl, w.FormDataContentType(), body)
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
