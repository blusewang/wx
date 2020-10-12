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
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
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
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/token?"+
		"grant_type=client_credential&appid=%v&secret=%v", m.AppId, m.AppSecret)
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
	MpBaseResp
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

// 创建二维码请求
type QrReq struct {
	ExpireSeconds int64  `json:"expire_seconds"`
	ActionName    string `json:"action_name"`
	ActionInfo    struct {
		Scene struct {
			SceneId  int64  `json:"scene_id"`
			SceneStr string `json:"scene_str"`
		} `json:"scene"`
	} `json:"action_info"`
}

// 创建二维码结果
type QrResp struct {
	MpBaseResp
	Ticket        string `json:"ticket"`
	ExpireSeconds int    `json:"expire_seconds"`
	Url           string `json:"url"`
}

// 创建二维码
func (m Mp) Qr(req QrReq) (rs QrResp, err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token=%v", m.AccessToken)
	var buf = new(bytes.Buffer)
	if err = json.NewEncoder(buf).Encode(req); err != nil {
		return
	}
	resp, err := http.Post(api, contentJson, buf)
	if err != nil {
		return
	}
	err = json.NewDecoder(resp.Body).Decode(&rs)
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
}

// 客服账号 - 添加
func (m Mp) KfAccountAdd(req KfAccountAddReq) (err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/customservice/kfaccount/add?access_token=%v", m.AccessToken)
	var buf = new(bytes.Buffer)
	if err = json.NewEncoder(buf).Encode(req); err != nil {
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
	if err = json.NewEncoder(buf).Encode(req); err != nil {
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
	if err = json.NewEncoder(buf).Encode(req); err != nil {
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
const CustomServiceGetKfListApi = "cgi-bin/customservice/getkflist"

type CustomServiceGetKfList struct {
	Req url.Values
	Res struct {
		KfList []struct {
			KfAccount    string `json:"kf_account"`
			KfNick       string `json:"kf_nick"`
			KfId         int64  `json:"kf_id"`
			KfHeadImgUrl string `json:"kf_headimgurl"`
		} `json:"kf_list"`
	} // 这个接口不规范
}

func (m Mp) KfUploadHeadImg(f io.Reader, kfAccount string) (err error) {
	api := fmt.Sprintf("https://api.weixin.qq.com/customservice/kfaccount/uploadheadimg?"+
		"access_token=%v&kf_account=%v",
		m.AccessToken, kfAccount)
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	defer w.Close()
	wf, err := w.CreateFormFile("media", fmt.Sprintf("/tmp/media.%v", "png"))
	if err != nil {
		return
	}
	if _, err = io.Copy(wf, f); err != nil {
		return
	}
	res, err := http.Post(api, w.FormDataContentType(), body)
	if err != nil {
		return
	}
	var rs MpBaseResp
	if err = json.NewDecoder(res.Body).Decode(&rs); err != nil {
		return
	}
	if rs.ErrCode != 0 {
		err = errors.New(rs.ErrMsg)
	}
	return
}

// 发送客服消息
const MessageCustomSendApi = "cgi-bin/message/custom/send"

type MessageCustomSendType string

const (
	MessageCustomSendTypeText            = "text"
	MessageCustomSendTypeImage           = "image"
	MessageCustomSendTypeVideo           = "video"
	MessageCustomSendTypeMusic           = "music"
	MessageCustomSendTypeNews            = "news"
	MessageCustomSendTypeMpNews          = "mpnews"
	MessageCustomSendTypeMsgMenu         = "msgmenu"
	MessageCustomSendTypeWxCard          = "wxcard"
	MessageCustomSendTypeMiniProgramPage = "miniprogrampage"
)

type MessageCustomSendArticle struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Url         string `json:"url"`
	PicUrl      string `json:"picurl"`
}
type MessageCustomSendMsgMenuItem struct {
	Id      string `json:"id"`
	Content string `json:"content"`
}

type MessageCustomSend struct {
	Req struct {
		ToUser  string                `json:"touser"`
		MsgType MessageCustomSendType `json:"msgtype"`
		Text    struct {
			Content string `json:"content"`
		} `json:"text"`
		Image struct {
			MediaId string `json:"media_id"`
		} `json:"image"`
		Voice struct {
			MediaId string `json:"media_id"`
		} `json:"voice"`
		Video struct {
			MediaId      string `json:"media_id"`
			ThumbMediaId string `json:"thumb_media_id"`
			Title        string `json:"title"`
			Description  string `json:"description"`
		} `json:"video"`
		Music struct {
			Title        string `json:"title"`
			Description  string `json:"description"`
			MusicUrl     string `json:"music_url"`
			HqMusicUrl   string `json:"hq_music_url"`
			ThumbMediaId string `json:"thumb_media_id"`
		} `json:"music"`
		News struct {
			Articles []MessageCustomSendArticle `json:"articles"`
		} `json:"news"`
		MpNews struct {
			MediaId string `json:"media_id"`
		} `json:"mp_news"`
		MsgMenu struct {
			HeadContent string                         `json:"head_content"`
			List        []MessageCustomSendMsgMenuItem `json:"list"`
			TailContent string                         `json:"tail_content"`
		}
		WxCard struct {
			CardId string `json:"card_id"`
		} `json:"wx_card"`
		MiniProgramPage struct {
			Title        string `json:"title"`
			AppId        string `json:"appid"`
			PagePath     string `json:"pagepath"`
			ThumbMediaId string `json:"thumb_media_id"`
		} `json:"miniprogrampage"`
		CustomService struct {
			KfAccount string `json:"kf_account"`
		} `json:"customservice"`
	}
	Res struct {
		MpBaseResp
		MsgId     int64 `json:"msg_id"`
		MsgDataId int64 `json:"msg_data_id"`
	}
}

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
	MpBaseResp
	MsgId int64 `json:"msgid"`
}

// 发送模板消息
const MessageTemplateSendApi = "cgi-bin/message/template/send"

type MessageTemplateSendItem struct {
	Value string `json:"value"`
	Color string `json:"color"`
}
type MessageTemplateSend struct {
	Req struct {
		ToUser      string `json:"touser"`
		TemplateId  string `json:"template_id"`
		Url         string `json:"url"`
		MiniProgram struct {
			AppId    string `json:"appid"`
			PagePath string `json:"pagepath"`
		} `json:"mini_program"`
		Data map[string]MessageTemplateSendItem `json:"data"`
	}
	Res struct {
		MpBaseResp
		MsgId int64 `json:"msgid"`
	}
}

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
const MessageMassSendApi = "cgi-bin/message/mass/send"

type MessageMassSendType string

const (
	MessageMassSendTypeMpNews  = "mpnews"
	MessageMassSendTypeText    = "text"
	MessageMassSendTypeVoice   = "voice"
	MessageMassSendTypeImage   = "image"
	MessageMassSendTypeMpVideo = "mpvideo"
	MessageMassSendTypeWxCard  = "wxcard"
)

type MessageMassSend struct {
	Req struct {
		ToUser  []string            `json:"touser"`
		MsgType MessageMassSendType `json:"msgtype"`
		MpNews  struct {
			MediaId string `json:"media_id,omitempty"`
		} `json:"mpnews,omitempty"`
		SendIgnoreReprint int `json:"send_ignore_reprint"`
		Text              struct {
			Content string `json:"content"`
		} `json:"text,omitempty"`
		Voice struct {
			MediaId string `json:"media_id"`
		} `json:"voice,omitempty"`
		Images struct {
			MediaIds           []string `json:"media_ids"`
			Recommend          string   `json:"recommend"`
			NeedOpenComment    int      `json:"need_open_comment"`
			OnlyFansCanComment int      `json:"only_fans_can_comment"`
		} `json:"images,omitempty"`
		MpVideo struct {
			MediaId     string `json:"media_id"`
			Title       string `json:"title"`
			Description string `json:"description"`
		} `json:"mpvideo,omitempty"`
		WxCard struct {
			CardId string `json:"card_id"`
		} `json:"wxcard,omitempty"`
	}
	Res struct {
		MpBaseResp
		MsgId     int64 `json:"msg_id"`
		MsgDataId int64 `json:"msg_data_id"`
	}
}
type massSendRes struct {
	MpBaseResp
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
const MpCode2SessionApi = "sns/jscode2session"

type MpCode2Session struct {
	Req url.Values
	Res struct {
		MpBaseResp
		OpenId     string `json:"openid"`
		SessionKey string `json:"session_key"`
		UnionId    string `json:"unionid"`
	}
}

type MpCode2SessionRes struct {
	MpBaseResp
	OpenId     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionId    string `json:"unionid"`
}

// 小程序 登录凭证校验
func (m *Mp) MpCode2Session(code string) (rs MpCode2SessionRes, err error) {
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
	body := new(bytes.Buffer)
	w := multipart.NewWriter(body)
	wf, err := w.CreateFormFile("media", fmt.Sprintf("/tmp/media.%v", ts[t]))
	if err != nil {
		return
	}
	if _, err = io.Copy(wf, f); err != nil {
		return
	}
	_ = w.Close()
	res, err := http.Post(api, w.FormDataContentType(), body)
	if err != nil {
		return
	}
	err = json.NewDecoder(res.Body).Decode(&rs)
	return
}

// 公众号消息
type MpMessage struct {
	ToUserName   string  `xml:"ToUserName" json:"to_user_name,omitempty"`
	Encrypt      string  `xml:"Encrypt" json:"encrypt,omitempty"`
	FromUserName string  `xml:"FromUserName" json:"from_user_name,omitempty"`
	CreateTime   int64   `xml:"CreateTime" json:"create_time,omitempty"`
	MsgType      string  `xml:"MsgType" json:"msg_type,omitempty"`
	Content      string  `xml:"Content" json:"content,omitempty"`
	MsgId        int64   `xml:"MsgId" json:"msg_id,omitempty"`
	PicUrl       string  `xml:"PicUrl" json:"pic_url,omitempty"`
	MediaId      string  `xml:"MediaId" json:"media_id,omitempty"`
	Format       string  `xml:"Format" json:"format,omitempty"`
	Recognition  string  `xml:"Recognition" json:"recognition,omitempty"`
	ThumbMediaId string  `xml:"ThumbMediaId" json:"thumb_media_id,omitempty"`
	LocationX    float64 `xml:"Location_X" json:"location_x,omitempty"`
	LocationY    float64 `xml:"Location_Y" json:"location_y,omitempty"`
	Scale        int64   `xml:"Scale" json:"scale,omitempty"`
	Label        string  `xml:"Label" json:"label,omitempty"`
	Title        string  `xml:"Title" json:"title,omitempty"`
	Description  string  `xml:"Description" json:"description,omitempty"`
	Url          string  `xml:"Url" json:"url,omitempty"`
	Event        string  `xml:"Event" json:"event,omitempty"`
	EventKey     string  `xml:"EventKey" json:"event_key,omitempty"`
	Ticket       string  `xml:"Ticket" json:"ticket,omitempty"`
	Latitude     float64 `xml:"Latitude" json:"latitude,omitempty"`
	Longitude    float64 `xml:"Longitude" json:"longitude,omitempty"`
	Precision    float64 `xml:"Precision" json:"precision,omitempty"`
	SessionFrom  string  `xml:"SessionFrom" json:"session_from,omitempty"`
	Status       string  `xml:"Status" json:"status,omitempty"`
	MsgID        int64   `xml:"MsgID" json:"msgID,omitempty"`
	SentCount    int64   `xml:"SentCount" json:"sent_count,omitempty"`
	AppId        string  `xml:"-" json:"app_id,omitempty"`
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
	msg.Encrypt = ""
	return
}

func (m *Mp) parse(raw []byte, any interface{}) (err error) {
	err = json.Unmarshal(raw, &any)
	if err != nil {
		return
	} else {
		we, err := parseJsonErr(raw)
		if (err == nil && (we.ErrCode == 40001 || we.ErrCode == 42001)) || err != nil {
			m.Expire = time.Now()
		}
		return err
	}
}

// 长链接转短链接
const ShortUrlApi = "cgi-bin/shorturl"

type ShortUrl struct {
	Req struct {
		Action  string `json:"action"`
		LongUrl string `json:"long_url"`
	}
	Res struct {
		MpBaseResp
		ShortUrl string `json:"short_url"`
	}
}

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

func (m *Mp) Get(api string, values url.Values, res interface{}) (err error) {
	values.Set("access_token", m.AccessToken)
	resp, err := http.Get(fmt.Sprintf("https://api.weixin.qq.com/%v?%v", api, values.Encode()))
	if err != nil {
		return
	}
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return
	}
	bs, has := res.(MpBaseResp)
	if has {
		if bs.ErrCode > 0 {
			err = errors.New(bs.ErrMsg)
		}
	}
	return
}

func (m *Mp) Post(api string, req interface{}, res interface{}) (err error) {
	if reflect.TypeOf(res).Kind() != reflect.Ptr {
		return errors.New("res must pointer")
	}
	var form = new(bytes.Buffer)
	if err = json.NewEncoder(form).Encode(req); err != nil {
		return
	}
	resp, err := http.Post(
		fmt.Sprintf("https://api.weixin.qq.com/%v?access_token=%v", api, m.AccessToken),
		contentJson,
		form,
	)
	if err != nil {
		return
	}
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return
	}
	bs, has := res.(MpBaseResp)
	if has {
		if bs.ErrCode > 0 {
			err = errors.New(bs.ErrMsg)
		}
	}
	return
}

// 对话能力 - 添加顾问
const GuideAccountAddApi = "cgi-bin/guide/addguideacct"

type GuideAccountAdd struct {
	Req struct {
		GuideAccount    string `json:"guide_account,omitempty"`
		GuideOpenId     string `json:"guide_openid,omitempty"`
		GuideHeadimgurl string `json:"guide_headimgurl,omitempty"`
		GuideNickname   string `json:"guide_nickname,omitempty"`
	}
	Res MpBaseResp
}

// 对话能力 - 获取顾问
const GuideAccountGetApi = "cgi-bin/guide/getguideacct"

type GuideAccountGet struct {
	Req struct {
		GuideAccount string `json:"guide_account"`
		GuideOpenId  string `json:"guide_openid"`
	}
	Res struct {
		MpBaseResp
		GuideAccount    string `json:"guide_account"`
		GuideOpenid     string `json:"guide_openid"`
		GuideNickname   string `json:"guide_nickname"`
		GuideHeadimgurl string `json:"guide_headimgurl"`
		Status          int64  `json:"status"`
	}
}

// 对话能力 - 为顾问分配客户
const GuideBuyerRelationAddApi = "guide/addguidebuyerrelation"

type GuideBuyerRelationAdd struct {
	Req struct {
		GuideAccount string `json:"guide_account,omitempty"`
		GuideOpenid  string `json:"guide_openid,omitempty"`
		GuideBuyer
		BuyerList []GuideBuyer `json:"buyer_list,omitempty"`
	}
	Res MpBaseResp
}

type GuideBuyer struct {
	OpenId        string `json:"openid,omitempty"`
	BuyerNickname string `json:"buyer_nickname,omitempty"`
}
