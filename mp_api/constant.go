package mp_api

type ServerHost string

const (
	// 服务器类型

	// ServerHostUniversal 通用域名
	ServerHostUniversal = "api.weixin.qq.com"
	// ServerHostUniversal2 通用异地容灾域名
	ServerHostUniversal2 = "api2.weixin.qq.com"
	// ServerHostShangHai 上海域名
	ServerHostShangHai = "sh.api.weixin.qq.com"
	// ServerHostShenZhen 深圳域名
	ServerHostShenZhen = "sz.api.weixin.qq.com"
	// ServerHostHK 香港域名
	ServerHostHK = "hk.api.weixin.qq.com"
)

type MpApi string

const (
	// 开始开发

	// BasicInformationToken 获取Access token
	BasicInformationToken = "cgi-bin/token"
	// BasicInformationApiDomainIp 获取微信服务器IP地址
	BasicInformationApiDomainIp = "cgi-bin/get_api_domain_ip"
	// BasicInformationCallbackCheck 网络检测
	BasicInformationCallbackCheck = "cgi-bin/callback/check"

	// 自定义菜单

	// CustomMenuCreate 创建自定义菜单
	CustomMenuCreate = "cgi-bin/menu/create"
	// CustomMenuCurrentSelfMenuInfo 查询自定义菜单
	CustomMenuCurrentSelfMenuInfo = "cgi-bin/get_current_selfmenu_info"
	// CustomMenuDelete 删除默认菜单及全部个性化菜单
	CustomMenuDelete = "cgi-bin/menu/delete"

	// 消息

	// MessageCustomServiceKfAccountAdd 添加客服
	MessageCustomServiceKfAccountAdd = "customservice/kfaccount/add"
	// MessageCustomServiceKfAccountUpdate 修改客服
	MessageCustomServiceKfAccountUpdate = "customservice/kfaccount/update"
	// MessageCustomServiceKfAccountDel 删除客服
	MessageCustomServiceKfAccountDel = "customservice/kfaccount/del"
	// MessageCustomServiceKfAccountUploadHeadImg 上传客服头像
	MessageCustomServiceKfAccountUploadHeadImg = "customservice/kfaccount/uploadheadimg"
	// MessageCustomServiceKfList 获取所有客服
	MessageCustomServiceKfList = "cgi-bin/customservice/getkflist"
	// MessageCustomSend 客服接口-发消息
	MessageCustomSend = "cgi-bin/message/custom/send"
	// MessageTemplateSend 发送模板消息
	MessageTemplateSend = "cgi-bin/message/template/send"
	// MessageMassSend 根据OpenID列表群发
	MessageMassSend = "cgi-bin/message/mass/send"

	// 媒体文件上传

	// MediaUploadImg 上传图文消息内的图片获取URL
	MediaUploadImg = "cgi-bin/media/uploadimg"
	// MediaUpload 新增临时素材
	MediaUpload = "cgi-bin/media/upload"

	// 微信网页开发

	// OaWebAppsSnsAuth2AccessToken 通过code换取网页授权access_token
	OaWebAppsSnsAuth2AccessToken = "sns/oauth2/access_token"
	// OaWebAppsSnsUserInfo 拉取用户信息(需scope为 snsapi_userinfo)
	OaWebAppsSnsUserInfo = "sns/userinfo"
	// OaWebAppsJsSDKTicket 获取JsSDK ticket
	OaWebAppsJsSDKTicket = "cgi-bin/ticket/getticket"

	// 用户管理

	// UserTagsCreate 创建标签
	UserTagsCreate = "cgi-bin/tags/create"
	// UserTagsGet 获取公众号已创建的标签
	UserTagsGet = "cgi-bin/tags/get"
	// UserTagsUpdate 编辑标签
	UserTagsUpdate = "cgi-bin/tags/update"
	// UserTagsDelete 删除标签
	UserTagsDelete = "cgi-bin/tags/delete"
	// UserTagGet 获取标签下粉丝列表
	UserTagGet = "cgi-bin/user/tag/get"
	// UserTagMembersBatch 批量为用户打标签
	UserTagMembersBatch = "cgi-bin/tags/members/batchtagging"
	// UserTagMembersBatchUnTag 批量为用户取消标签
	UserTagMembersBatchUnTag = "cgi-bin/tags/members/batchuntagging"
	// UserTagsGetIdList 获取用户身上的标签列表
	UserTagsGetIdList = "cgi-bin/tags/getidlist"
	// UserInfoUpdateRemark 用户设置备注名
	UserInfoUpdateRemark = "cgi-bin/user/info/updateremark"
	// UserInfo 获取用户基本信息（包括UnionID机制）
	UserInfo = "cgi-bin/user/info"
	// UserInfoBatchGet 批量获取用户基本信息
	UserInfoBatchGet = "cgi-bin/user/info/batchget"
	// UserGet 获取关注者列表
	UserGet = "cgi-bin/user/get"

	// 账号管理

	// AccountQrCreate 二维码
	AccountQrCreate = "cgi-bin/qrcode/create"
	// AccountShortUrl 长链接转成短链接
	AccountShortUrl = "cgi-bin/shorturl"

	// 对话能力

	// GuideAccountAdd 添加顾问
	GuideAccountAdd = "cgi-bin/guide/addguideacct"
	// GuideAddBuyer 为顾问分配客户
	GuideAddBuyer = "cgi-bin/guide/addguidebuyerrelation"

	// MiniProgramJsCode2Session 小程序
	MiniProgramJsCode2Session = "sns/jscode2session" // 登录凭证校验

	// OCR

	// OcrBandCard 银行卡识别
	OcrBandCard = "cv/ocr/bankcard"
	// OcrBusinessLicense 营业执照识别
	OcrBusinessLicense = "cv/ocr/bizlicense"
	// OcrDrivingLicense 营业执照识别
	OcrDrivingLicense = "cv/ocr/drivinglicense"
	// OcrIdCard 营业执照识别
	OcrIdCard = "cv/ocr/idcard"
	// OcrText 普通文字识别
	OcrText = "cv/ocr/comm"
)

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

type MessageMassSendType string

const (
	MessageMassSendTypeMpNews  = "mpnews"
	MessageMassSendTypeText    = "text"
	MessageMassSendTypeVoice   = "voice"
	MessageMassSendTypeImages  = "images"
	MessageMassSendTypeMpVideo = "mpvideo"
	MessageMassSendTypeWxCard  = "wxcard"
)

type MediaType string

const (
	MediaTypeImage = "image"
	MediaTypeVoice = "voice"
	MediaTypeVideo = "video"
	MediaTypeThumb = "thumb"
)

type QrActionType string

const (
	QrActionTypeScene         = "QR_SCENE"
	QrActionTypeStrScene      = "QR_STR_SCENE"
	QrActionTypeLimitScene    = "QR_LIMIT_SCENE"
	QrActionTypeLimitStrScene = "QR_LIMIT_STR_SCENE"
)

const ShortUrlAction = "long2short"

type TokenGrantType string

const (
	TokenGrantTypeClientCredential = "client_credential"
	TokenGrantTypeAuthCode         = "authorization_code"
)

type JsSDKTicketType string

const (
	JsSDKTicketTypeJSAPI  = "jsapi"
	JsSDKTicketTypeWxCard = "wx_card"
)
