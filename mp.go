package wxApi

import (
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"reflect"
	"sort"
	"strings"
	"time"
)

type Mp struct {
	AppId          string
	AppName        string
	AccessToken    string
	Expire         time.Time
	AppSecret      string
	PrivateToken   string
	EncodingAESKey string
}

// 获取access_token
type accessTokenRes struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}
func (m Mp) AuthToken() (rs accessTokenRes,err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=%v&secret=%v",m.AppId,m.AppSecret)
	raw,err := get(api)
	if err != nil { return }
	err = m.parse(raw,&rs)
	if err != nil {log.Println("GET",api,string(raw))}
	return
}

// App 通过code获取access_token
type appAuthToken struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenId       string `json:"openid"`
	Scope        string `json:"scope"`
}
func (m Mp) AppAuthToken(code string) (rs appAuthToken,err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/sns/oauth2/access_token?appid=%v&secret=%v&code=%v" +
		"&grant_type=authorization_code",m.AppId,m.AppSecret,code)
	raw,err := get(api)
	if err != nil { return }
	err = m.parse(raw,&rs)
	if err != nil {log.Println("GET",api,string(raw))}
	return
}

// App 获取用户个人信息（UnionID机制）
type UserInfo struct {
	OpenId        string  `json:"openid"`
	NickName      string  `json:"nickname"`
	Sex           int64   `json:"sex"`
	Province      string  `json:"province"`
	City          string  `json:"city"`
	Country       string  `json:"country"`
	HeadImgUrl    string  `json:"headimgurl"`
	UnionId       string  `json:"unionid"`
	Subscribe     int64   `json:"subscribe"`
	SubscribeTime int64   `json:"subscribe_time"`
	Remark        string  `json:"remark"`
	TagIdList     []int64 `json:"tagid_list"`
	QrScene       int64   `json:"qr_scene"`
	QrSceneStr    string  `json:"qr_scene_str"`
}
func (m Mp) AppUserInfo(openId string) (rs UserInfo, err error){
	api := fmt.Sprintf("https://api.weixin.qq.com/sns/userinfo?access_token=%v&openid=%v&lang=zh_CN",m.AccessToken,openId)
	raw,err := get(api)
	if err != nil {return}
	err = m.parse(raw,&rs)
	if err != nil {log.Println("GET",api,string(raw))}
	return
}

// 生成临时二维码
type shortQrCodeReq struct {
	ExpireSeconds int    `json:"expire_seconds"`
	ActionName    string `json:"action_name"`
	ActionInfo    struct {
		Scene struct {
			SceneId int `json:"scene_id"`
		} `json:"scene"`
	} `json:"action_info"`
}
type shortQrCode struct {
	Ticket        string `json:"ticket"`
	ExpireSeconds int    `json:"expire_seconds"`
	Url           string `json:"url"`
}
func (m Mp) CreateShortQrCode(sceneId, secondsOut int) (rs shortQrCode,err error){
	var req shortQrCodeReq
	req.ExpireSeconds = secondsOut
	req.ActionName = "QR_SCENE"
	req.ActionInfo.Scene.SceneId = sceneId
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token=%v",m.AccessToken)
	raw,err := postJSON(api,req)
	err = m.parse(raw,&rs)
	if err != nil {log.Println("POST",api,req,string(raw))}
	return
}

// 验证公众号接口
func (m Mp) ValidateSignature(signature string,timestamp string,nonce string) (err error){
	arr := []string{m.PrivateToken,timestamp,nonce}
	sort.Strings(arr)

	sign := fmt.Sprintf("%x",sha1.Sum([]byte(strings.Join(arr,""))))

	if signature != sign { err = errors.New("签名验证失败") }
	return
}

//获取粉丝详细
func (m Mp) UserInfo(openId string) (rs UserInfo,err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/user/info?access_token=%v&openid=%v&lang=zh_CN",
		m.AccessToken,openId)
	raw,err := get(api)
	if err != nil {return}
	err = m.parse(raw,&rs)
	if err != nil {log.Println("GET",api,string(raw))}
	return
}

// 发送客服消息
func (m Mp) SendMsg(openid, msgType string,content interface{}) (err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token=%v", m.AccessToken)
	data := make(H)
	data["touser"] = openid
	data["msgtype"] = msgType
	switch msgType {
	case "text":
		data[msgType] = H{
			"content": content,
		}
	case "image", "mpnews", "voice":
		data[msgType] = H{
			"media_id": content,
		}
	case "news":
		data[msgType] = content
	}
	raw,err := postJSON(api,data)
	if err != nil {return}
	err = m.parse(raw,err)
	return
}

// 发送模板消息
type tpsMsgSendRes struct {
	wxErr
	MsgId int64 `json:"msgid"`
}
func (m Mp) SendTpsMsg(openid, tplId, path string,content interface{}) (rs tpsMsgSendRes,err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=%v", m.AccessToken)
	data := make(H)
	data["touser"] = openid
	data["template_id"] = tplId
	data["url"] = path
	data["miniprogram"] = H{
		"appid":"",
		"pagepath":path,
	}
	data["data"] = content
	raw,err := postJSON(api,data)
	if err != nil {return}
	err = m.parse(raw,&rs)
	if err != nil {log.Println("POST",api,data,string(raw))}
	return
}

// 根据OpenID列表群发
type massSendRes struct {
	wxErr
	MsgId     int64 `json:"msg_id"`
	MsgDataId int64 `json:"msg_data_id"`
}
func (m Mp) MassSend(openIds []string, msgType string, content interface{}) (rs massSendRes,err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/message/mass/send?access_token=%v",m.AccessToken)
	post := make(H)
	post["touser"] = openIds
	post["msgtype"] = msgType
	if msgType == "text" {
		post["text"] = H{"content":content}
	}
	raw,err := postJSON(api,post)
	err = m.parse(raw,&rs)
	if err != nil {log.Println("POST",api,post,string(raw))}
	return
}

// 小程序 登录凭证校验
type mpCode2SessionRes struct {
	wxErr
	OpenId     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionId    string `json:"unionid"`
}
func (m Mp) MpCode2Session(code string) (rs mpCode2SessionRes,err error){
	api := fmt.Sprintf("https://api.weixin.qq.com/sns/jscode2session?appid=%v&secret=%v&js_code=%v" +
		"&grant_type=authorization_code",m.AppId,m.AppSecret,code)
	raw,err := get(api)
	if err != nil {return}
	err = m.parse(raw,&rs)
	if err != nil {log.Println("GET",api,string(raw))}
	return
}


// 公众号消息与事件的分发
func (m Mp) HandleMsg(msg io.ReadCloser, handler interface{}) (err error) {
	// 读取
	raw,err := ioutil.ReadAll(msg)
	if err != nil { return err }
	// 转换
	data := XmlToMap(string(raw),true)

	// 按需解密
	encrypt,_ := data["Encrypt"].(string)
	_,raw,err = decryptMsg(m.AppId,encrypt,m.EncodingAESKey)
	if err != nil { return err }
	data = XmlToMap(string(raw),true)

	// 判断数据项
	if data["MsgType"] == nil || data["FromUserName"] == nil { return errors.New("不明来源")}

	// 按数据类型组合处理方法名
	var method string
	if reflect.TypeOf(data["MsgType"]).String() == "string" {
		msgType,_ := data["MsgType"].(string)
		event,_ := data["Event"].(string)
		method = strings.Title(strings.ToLower(msgType))
		if method == "Event" && data["Event"] != nil && reflect.TypeOf(data["Event"]).String() == "string"{
			method += strings.Title(strings.ToLower(event))
		}
	}

	// 动态调用方法处理
	action := reflect.ValueOf(handler).MethodByName(method)
	if action == reflect.Zero(reflect.TypeOf(action)).Interface() { return nil }
	go action.Call([]reflect.Value{reflect.ValueOf(data)})

	return nil
}






// 公众号消息与事件的分发
func (m *Mp) parse(raw []byte,any interface{}) (err error){
	err = json.Unmarshal(raw,&any)
	if err != nil { return } else {
		we,err := parseJsonErr(raw)
		if we.ErrCode == 40001 { m.Expire = time.Now()}
		return err
	}
}





