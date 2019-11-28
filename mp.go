package wxApi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
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
	Ticket         string
}

type MpBaseResp struct {
	ErrCode int64  `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

// access_token
type accessTokenRes struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

// 获取access_token
func (m Mp) AuthToken() (rs accessTokenRes, err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=%v&secret=%v", m.AppId, m.AppSecret)
	raw, err := get(api)
	if err != nil {
		return
	}
	err = m.parse(raw, &rs)
	if err != nil {
		log.Println("GET", api, string(raw))
	}
	return
}

// App access_token
type appAuthToken struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenId       string `json:"openid"`
	Scope        string `json:"scope"`
}

// App 通过code获取access_token
func (m Mp) AppAuthToken(code string) (rs appAuthToken, err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/sns/oauth2/access_token?appid=%v&secret=%v&code=%v"+
		"&grant_type=authorization_code", m.AppId, m.AppSecret, code)
	raw, err := get(api)
	if err != nil {
		return
	}
	err = m.parse(raw, &rs)
	if err != nil {
		log.Println("GET", api, string(raw))
	}
	return
}

// access_token
type ticket struct {
	Ticket    string `json:"ticket"`
	ExpiresIn int64  `json:"expires_in"`
}

// 获取access_token
func (m *Mp) GetTicket(ticketType string) (rs ticket, err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token=%v&type=%v",
		m.AccessToken, ticketType)
	raw, err := get(api)
	if err != nil {
		return
	}
	err = m.parse(raw, &rs)
	if err != nil {
		log.Println("GET", api, string(raw))
	}
	return
}

// js-sdk url签名
func (m Mp) UrlSign(url string) (d H) {
	data := make(H)
	data["noncestr"] = NewRandStr(32)
	data["jsapi_ticket"] = m.Ticket
	data["timestamp"] = time.Now().Unix()
	data["url"] = url
	d = make(H)
	d["appId"] = m.AppId
	d["timestamp"] = data["timestamp"]
	d["nonceStr"] = data["noncestr"]
	d["signature"] = m.sha1Sign(data)
	d["jsApiList"] = []string{}
	return
}

// SHA1签名
func (m Mp) sha1Sign(data H) string {
	str := mapSortByKey(data)
	raw := sha1.Sum([]byte(str))
	return strings.ToUpper(fmt.Sprintf("%x", raw))
}

// js sdk access_token
type jsAccessToken struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Openid       string `json:"openid"`
}

// 获取js sdk access_token
func (m *Mp) JsCodeToken(code string) (rs jsAccessToken, err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/sns/oauth2/access_token?appid=%v&secret=%v&code=%v&grant_type=authorization_code",
		m.AppId, m.AppSecret, code)
	raw, err := get(api)
	if err != nil {
		return
	}
	err = m.parse(raw, &rs)
	if err != nil {
		log.Println("GET", api, string(raw))
	}
	return
}

// 微信粉丝信息
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

func (ui UserInfo) String() string {
	raw, _ := json.Marshal(ui)
	return string(raw)
}

// 获取粉丝微信信息（UnionID机制）
func (m Mp) AppUserInfo(at jsAccessToken) (rs UserInfo, err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/sns/userinfo?access_token=%v&openid=%v&lang=zh_CN",
		at.AccessToken, at.Openid)
	raw, err := get(api)
	if err != nil {
		return
	}
	err = m.parse(raw, &rs)
	if err != nil {
		log.Println("GET", api, string(raw))
	}
	return
}

// 获取用户ID列表结果
type UsersSegment struct {
	Total int64 `json:"total"`
	Count int64 `json:"count"`
	Data  struct {
		OpenId []string `json:"openid"`
	} `json:"data"`
	NextOpenId string `json:"next_openid"`
}

// 获取用户ID列表
func (m Mp) UserGet(nextOpenId string) (us UsersSegment, err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/user/get?access_token=%v&next_openid=%v",
		m.AccessToken, nextOpenId)
	resp, err := http.Get(api)
	if err != nil {
		return
	}
	err = json.NewDecoder(resp.Body).Decode(&us)
	return
}

// 批量获取粉丝信息请求项
type UserGetBatchReqItem struct {
	Openid string `json:"openid"`
	Lang   string `json:"lang"`
}

// 批量获取粉丝请求
type UserGetBatchReq struct {
	UserList []UserGetBatchReqItem `json:"user_list"`
}

// 批量获取粉丝信息结果
type UserGetBatchResp struct {
	UserInfoList []UserInfo `json:"user_info_list"`
}

// 批量获取粉丝信息
func (m Mp) UserInfoGetBatch(req UserGetBatchReq) (res UserGetBatchResp, err error) {
	if len(req.UserList) > 100 {
		err = errors.New("最多支持一次拉取100条")
		return
	}

	var buf = new(bytes.Buffer)
	if err = json.NewEncoder(buf).Encode(req); err != nil {
		return
	}

	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/user/info/batchget?access_token=%v", m.AccessToken)
	resp, err := http.Post(api, contentJson, buf)
	if err != nil {
		return
	}
	err = json.NewDecoder(resp.Body).Decode(&res)
	return
}

// 创建临时二维码请求
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

// 创建临时二维码
func (m Mp) CreateShortQrCode(sceneId, secondsOut int) (rs shortQrCode, err error) {
	var req shortQrCodeReq
	req.ExpireSeconds = secondsOut
	req.ActionName = "QR_SCENE"
	req.ActionInfo.Scene.SceneId = sceneId
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token=%v", m.AccessToken)
	raw, err := postJSON(api, req)
	err = m.parse(raw, &rs)
	if err != nil {
		log.Println("POST", api, req, string(raw))
	}
	return
}

// 创建临时文本参数二维码请求
type shortQrStrCodeReq struct {
	ExpireSeconds int    `json:"expire_seconds"`
	ActionName    string `json:"action_name"`
	ActionInfo    struct {
		Scene struct {
			SceneStr string `json:"scene_str"`
		} `json:"scene"`
	} `json:"action_info"`
}

// 创建临时文本参数二维码
func (m Mp) CreateShortQrStrCode(sceneStr string, secondsOut int) (rs shortQrCode, err error) {
	var req shortQrStrCodeReq
	req.ExpireSeconds = secondsOut
	req.ActionName = "QR_STR_SCENE"
	req.ActionInfo.Scene.SceneStr = sceneStr
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token=%v", m.AccessToken)
	raw, err := postJSON(api, req)
	err = m.parse(raw, &rs)
	if err != nil {
		log.Println("POST", api, req, string(raw))
	}
	return
}

// 公众号消息请求验证参数
type ValidateReq struct {
	Signature    string `form:"signature" binding:"required"`
	Timestamp    string `form:"timestamp" binding:"required"`
	Nonce        string `form:"nonce" binding:"required"`
	EchoStr      string `form:"echostr"`
	OpenId       string `form:"openid"`
	EncryptType  string `form:"encrypt_type"`
	MsgSignature string `form:"msg_signature"`
}

// 公众号消息请求验证
func (m Mp) ValidateSignature(req ValidateReq) (err error) {
	arr := []string{m.PrivateToken, req.Timestamp, req.Nonce}
	sort.Strings(arr)

	sign := fmt.Sprintf("%x", sha1.Sum([]byte(strings.Join(arr, ""))))

	if req.Signature != sign {
		err = errors.New("签名验证失败")
	}
	return
}

//获取粉丝详细
func (m Mp) UserInfo(openId string) (rs UserInfo, err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/user/info?access_token=%v&openid=%v&lang=zh_CN",
		m.AccessToken, openId)
	raw, err := get(api)
	if err != nil {
		return
	}
	err = m.parse(raw, &rs)
	if err != nil {
		log.Println("GET", api, string(raw))
	}
	return
}

// 添加客服账号请求
type KfAccountAddReq struct {
	KfAccount string `json:"kf_account"`
	Nickname  string `json:"nickname"`
	Password  string `json:"password"`
}

// 客服账号 - 添加
func (m Mp) KfAccountAdd(req KfAccountAddReq) (err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/customservice/kfaccount/add?access_token=%v", m.AccessToken)
	var buf = new(bytes.Buffer)
	if err = json.NewEncoder(buf).Encode(buf); err != nil {
		return
	}
	resp, err := http.Post(api, contentJson, buf)
	if err != nil {
		return
	}
	var rs MpBaseResp
	if err = json.NewDecoder(resp.Body).Decode(&rs); err != nil {
		return
	}
	if rs.ErrCode != 0 {
		return errors.New(rs.ErrMsg)
	}
	return
}

// 客服账号 - 修改
func (m Mp) KfAccountUpdate(req KfAccountAddReq) (err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/customservice/kfaccount/update?access_token=%v", m.AccessToken)
	var buf = new(bytes.Buffer)
	if err = json.NewEncoder(buf).Encode(buf); err != nil {
		return
	}
	resp, err := http.Post(api, contentJson, buf)
	if err != nil {
		return
	}
	var rs MpBaseResp
	if err = json.NewDecoder(resp.Body).Decode(&rs); err != nil {
		return
	}
	if rs.ErrCode != 0 {
		return errors.New(rs.ErrMsg)
	}
	return
}

// 客服账号 - 删除
func (m Mp) KfAccountDel(req KfAccountAddReq) (err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/customservice/kfaccount/del?access_token=%v", m.AccessToken)
	var buf = new(bytes.Buffer)
	if err = json.NewEncoder(buf).Encode(buf); err != nil {
		return
	}
	resp, err := http.Post(api, contentJson, buf)
	if err != nil {
		return
	}
	var rs MpBaseResp
	if err = json.NewDecoder(resp.Body).Decode(&rs); err != nil {
		return
	}
	if rs.ErrCode != 0 {
		return errors.New(rs.ErrMsg)
	}
	return
}

// 获取客服账号结果列表
type KfListResp struct {
	KfList []struct {
		KfAccount    string `json:"kf_account"`
		KfNick       string `json:"kf_nick"`
		KfId         string `json:"kf_id"`
		KfHeadImgUrl string `json:"kf_headimgurl"`
	} `json:"kf_list"`
}

// 客服账号 - 获取
func (m Mp) KfList() (err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/customservice/getkflist?access_token=%v", m.AccessToken)
	var buf = new(bytes.Buffer)
	if err = json.NewEncoder(buf).Encode(buf); err != nil {
		return
	}
	resp, err := http.Post(api, contentJson, buf)
	if err != nil {
		return
	}
	var rs MpBaseResp
	if err = json.NewDecoder(resp.Body).Decode(&rs); err != nil {
		return
	}
	if rs.ErrCode != 0 {
		return errors.New(rs.ErrMsg)
	}
	return
}

// 发送客服消息
func (m Mp) SendMsg(openid, msgType string, content interface{}) (err error) {
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
	default:
		data[msgType] = content
	}
	raw, err := postJSON(api, data)
	if err != nil {
		return
	}
	err = m.parse(raw, err)
	return
}

// 发送模板消息结果
type tpsMsgSendRes struct {
	wxErr
	MsgId int64 `json:"msgid"`
}

// 发送模板消息
func (m Mp) SendTpsMsg(openid, tplId, path string, content interface{}) (rs tpsMsgSendRes, err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=%v", m.AccessToken)
	data := make(H)
	data["touser"] = openid
	data["template_id"] = tplId
	data["url"] = path
	data["miniprogram"] = H{
		"appid":    "",
		"pagepath": path,
	}
	data["data"] = content
	raw, err := postJSON(api, data)
	if err != nil {
		return
	}
	err = m.parse(raw, &rs)
	return
}

// 根据OpenID列表群发请求
type massSendRes struct {
	wxErr
	MsgId     int64 `json:"msg_id"`
	MsgDataId int64 `json:"msg_data_id"`
}

// 根据OpenID列表群发
func (m Mp) MassSend(openIds []string, msgType string, content interface{}) (rs massSendRes, err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/message/mass/send?access_token=%v", m.AccessToken)
	post := make(H)
	post["touser"] = openIds
	post["msgtype"] = msgType
	if msgType == "text" {
		post["text"] = H{"content": content}
	}
	raw, err := postJSON(api, post)
	err = m.parse(raw, &rs)
	if err != nil {
		log.Println("POST", api, post, string(raw))
	}
	return
}

// 小程序 登录凭证校验结果
type MpCode2SessionRes struct {
	wxErr
	OpenId     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionId    string `json:"unionid"`
}

// 小程序 登录凭证校验
func (m Mp) MpCode2Session(code string) (rs MpCode2SessionRes, err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/sns/jscode2session?appid=%v&secret=%v&js_code=%v"+
		"&grant_type=authorization_code", m.AppId, m.AppSecret, code)
	raw, err := get(api)
	if err != nil {
		return
	}
	err = m.parse(raw, &rs)
	if err != nil {
		log.Println("GET", api, string(raw))
	}
	return
}

// 上传媒体文件请求
type mediaRes struct {
	Type      string `json:"type"`
	MediaId   string `json:"media_id"`
	CreatedAt int64  `json:"created_at"`
}

// 上传媒体文件
func (m Mp) Upload(f io.Reader, t string) (rs mediaRes, err error) {
	ts := map[string]string{
		"image": "jpg",
		"voice": "mp3",
		"video": "mp4",
		"thumb": "jpg",
	}
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/media/upload?access_token=%v&type=%v", m.AccessToken, t)
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	wf, err := w.CreateFormFile("media", fmt.Sprintf("/tmp/media.%v", ts[t]))
	if err != nil {
		return
	}
	if _, err = io.Copy(wf, f); err != nil {
		return
	}
	w.Close()
	res, err := http.Post(api, w.FormDataContentType(), body)
	if err != nil {
		return
	}
	err = json.NewDecoder(res.Body).Decode(&rs)
	return
}

// 公众号消息
type MpMessage struct {
	ToUserName   string  `xml:"ToUserName" json:"to_user_name"`
	Encrypt      string  `xml:"Encrypt" json:"encrypt"`
	FromUserName string  `xml:"FromUserName" json:"from_user_name"`
	CreateTime   int64   `xml:"CreateTime" json:"create_time"`
	MsgType      string  `xml:"MsgType" json:"msg_type"`
	Content      string  `xml:"Content" json:"content"`
	MsgId        int64   `xml:"msg_id" json:"msg_id"`
	PicUrl       string  `xml:"PicUrl" json:"pic_url"`
	MediaId      string  `xml:"MediaId" json:"media_id"`
	Format       string  `xml:"Format" json:"format"`
	Recognition  string  `xml:"Recognition" json:"recognition"`
	ThumbMediaId string  `xml:"ThumbMediaId" json:"thumb_media_id"`
	LocationX    float64 `xml:"Location_X" json:"location_x"`
	LocationY    float64 `xml:"Location_Y" json:"location_y"`
	Scale        int64   `xml:"Scale" json:"scale"`
	Label        string  `xml:"Label" json:"label"`
	Title        string  `xml:"Title" json:"title"`
	Description  string  `xml:"Description" json:"description"`
	Url          string  `xml:"Url" json:"url"`
	Event        string  `xml:"Event" json:"event"`
	EventKey     string  `xml:"EventKey" json:"event_key"`
	Ticket       string  `xml:"Ticket" json:"ticket"`
	Latitude     float64 `xml:"Latitude" json:"latitude"`
	Longitude    float64 `xml:"Longitude" json:"longitude"`
	Precision    float64 `xml:"Precision" json:"precision"`
	SessionFrom  string  `xml:"SessionFrom" json:"session_from"`
	Status       string  `xml:"status" json:"status"`
	MsgID        int64   `xml:"MsgID" json:"msg_id"`
	SentCount    int64   `xml:"SentCount" json:"sent_count"`
	AppId        string  `xml:"-" json:"app_id"`
}

// 公众号消息解密
func (msg *MpMessage) ShouldDecode(key string) (err error) {
	if msg.Encrypt == "" {
		// 没加密
		return
	}
	if msg.FromUserName != "" {
		// 解密过了
		return
	}

	// 读密钥
	raw, err := base64.StdEncoding.DecodeString(key + "=")
	if err != nil {
		return
	}

	// 生成密钥
	block, err := aes.NewCipher(raw)
	if err != nil {
		return
	}
	// 读密文
	raw, err = base64.StdEncoding.DecodeString(msg.Encrypt)
	if err != nil {
		return
	}
	if len(raw) < block.BlockSize() {
		return errors.New("无效密文")
	}
	// 解密
	cipher.NewCBCDecrypter(block, raw[:block.BlockSize()]).CryptBlocks(raw, raw)

	// 微信格式解码 AES_Encrypt[random(16B) + msg_len(4B) + rawXMLMsg + appId]
	_pad := int(raw[len(raw)-1])
	_length := binary.BigEndian.Uint32(raw[16:20])
	raw = raw[:len(raw)-_pad]

	// 取出格式化数据
	if err = xml.Unmarshal(raw[20:_length+20], &msg); err != nil {
		return
	}
	msg.AppId = string(raw[_length+20:])
	return
}

// 公众号消息与事件的分发
func (m Mp) HandleMsg(msg io.ReadCloser, handler interface{}) (err error) {
	// 读取
	raw, err := ioutil.ReadAll(msg)
	if err != nil {
		return err
	}
	// 转换
	data := XmlToMap(string(raw), true)

	// 按需解密
	encrypt, _ := data["Encrypt"].(string)
	_, raw, err = decryptMsg(m.AppId, encrypt, m.EncodingAESKey)
	if err != nil {
		return err
	}
	data = XmlToMap(string(raw), true)

	// 判断数据项
	if data["MsgType"] == nil || data["FromUserName"] == nil {
		return errors.New("不明来源")
	}

	// 按数据类型组合处理方法名
	var method string
	if reflect.TypeOf(data["MsgType"]).String() == "string" {
		msgType, _ := data["MsgType"].(string)
		event, _ := data["Event"].(string)
		method = strings.Title(strings.ToLower(msgType))
		if method == "Event" && data["Event"] != nil && reflect.TypeOf(data["Event"]).String() == "string" {
			method += strings.Title(strings.ToLower(event))
		}
	}

	// 动态调用方法处理
	action := reflect.ValueOf(handler).MethodByName(method)
	if !action.IsValid() {
		return nil
	}

	go action.Call([]reflect.Value{reflect.ValueOf(data)})

	return nil
}

// 公众号消息与事件的分发
func (m *Mp) parse(raw []byte, any interface{}) (err error) {
	err = json.Unmarshal(raw, &any)
	if err != nil {
		return
	} else {
		we, err := parseJsonErr(raw)
		if we.ErrCode == 40001 || we.ErrCode == 42001 {
			m.Expire = time.Now()
		}
		return err
	}
}

// 长链接转短链接
func (m *Mp) ShortUrl(lUrl string) (sUrl string, err error) {
	res, err := http.Post(
		fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/shorturl?access_token=%v", m.AccessToken),
		contentJson,
		strings.NewReader(fmt.Sprintf(`{"action":"long2short","long_url":"%v"}`, lUrl)),
	)
	if err != nil {
		return
	}
	var rs struct {
		MpBaseResp
		ShortUrl string `json:"short_url"`
	}
	if err = json.NewDecoder(res.Body).Decode(&rs); err != nil {
		return
	}
	if rs.ErrCode > 0 {
		err = errors.New(rs.ErrMsg)
	}
	sUrl = rs.ShortUrl
	return
}
