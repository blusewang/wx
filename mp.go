package wxApi

import (
	"crypto/sha1"
	"encoding/xml"
	"fmt"
	"github.com/blusewang/wxApi-go/mp_api"
	"github.com/youkale/go-querystruct/params"
	"net/http"
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

// 微信网页的网址签名
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

// 新建一个请求
func (ma MpAccount) NewMpReq(path mp_api.MpApi) *mpReq {
	return &mpReq{account: ma, path: path}
}
