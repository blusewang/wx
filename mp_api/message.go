package mp_api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// 消息通知`query`数据
type MessageQuery struct {
	Signature    string `param:"signature" binding:"required"`
	Timestamp    string `param:"timestamp" binding:"required"`
	Nonce        string `param:"nonce" binding:"required"`
	EchoStr      string `param:"echostr"`
	OpenId       string `param:"openid"`
	EncryptType  string `param:"encrypt_type"`
	MsgSignature string `param:"msg_signature"`
}

// 安全验证
func (mq MessageQuery) Validate(PrivateToken string) (err error) {
	arr := []string{PrivateToken, mq.Timestamp, mq.Nonce}
	sort.Strings(arr)

	sign := fmt.Sprintf("%x", sha1.Sum([]byte(strings.Join(arr, ""))))

	if mq.Signature != sign {
		err = errors.New("签名验证失败")
	}
	return
}

// 公众号消息
type MessageData struct {
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
func (msg *MessageData) ShouldDecode(EncodingAESKey string) (err error) {
	if msg.Encrypt == "" {
		// 没加密
		return
	}
	if msg.FromUserName != "" {
		// 解密过了
		return
	}

	// 读密钥
	raw, err := base64.StdEncoding.DecodeString(EncodingAESKey + "=")
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

type KfAccountData struct {
	KfId         int64  `json:"kf_id,omitempty"`
	KfAccount    string `json:"kf_account"`
	NickName     string `json:"nickname"`
	Password     string `json:"password"`
	KfHeadImgUrl string `json:"kf_headimgurl,omitempty"`
}

type MessageCustomServiceKfAccountUploadHeadImgQuery struct {
	KfAccount string `url:"kf_account"`
}

type MessageCustomServiceKfListRes struct {
	MpBaseResp
	KfList []KfAccountData `json:"kf_list"`
}

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
type MessageCustomSendData struct {
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

type MessageTemplateSendDataItem struct {
	Value string `json:"value"`
	Color string `json:"color"`
}
type MessageTemplateMiniProgram struct {
	AppId    string `json:"appid"`
	PagePath string `json:"pagepath"`
}
type MessageTemplateSendData struct {
	ToUser      string                                 `json:"touser"`
	TemplateId  string                                 `json:"template_id"`
	Url         string                                 `json:"url"`
	MiniProgram MessageTemplateMiniProgram             `json:"mini_program"`
	Data        map[string]MessageTemplateSendDataItem `json:"data"`
}

type MessageTemplateSendRes struct {
	MpBaseResp
	MsgId int64 `json:"msgid"`
}

type MessageMassSendMediaId struct {
	MediaId string `json:"media_id"`
}
type MessageMassSendText struct {
	Content string `json:"content"`
}
type MessageMassSendImages struct {
	MediaIds           []string `json:"media_ids"`
	Recommend          string   `json:"recommend"`
	NeedOpenComment    int      `json:"need_open_comment"`
	OnlyFansCanComment int      `json:"only_fans_can_comment"`
}
type MessageMassSendMpVideo struct {
	MediaId     string `json:"media_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}
type MessageMassSendWxCard struct {
	CardId string `json:"card_id"`
}
type MessageMassSendData struct {
	ToUser            []string                `json:"touser"`
	MsgType           MessageMassSendType     `json:"msgtype"`
	MpNews            *MessageMassSendMediaId `json:"mpnews,omitempty"`
	Text              *MessageMassSendText    `json:"text,omitempty"`
	Voice             *MessageMassSendMediaId `json:"voice,omitempty"`
	Images            *MessageMassSendImages  `json:"images,omitempty"`
	MpVideo           *MessageMassSendMpVideo `json:"mpvideo,omitempty"`
	WxCard            *MessageMassSendWxCard  `json:"wxcard,omitempty"`
	SendIgnoreReprint int                     `json:"send_ignore_reprint"`
}

type MessageMassSendRes struct {
	MpBaseResp
	MsgId     int64 `json:"msg_id"`
	MsgDataId int64 `json:"msg_data_id"`
}
