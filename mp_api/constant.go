package mp_api

type ServerHost string

const (
	// 服务器类型
	ServerHostUniversal  = "api.weixin.qq.com"    // 通用域名
	ServerHostUniversal2 = "api2.weixin.qq.com"   // 通用异地容灾域名
	ServerHostShangHai   = "sh.api.weixin.qq.com" // 上海域名
	ServerHostShengZhen  = "sz.api.weixin.qq.com" // 深圳域名
	ServerHostHK         = "hk.api.weixin.qq.com" // 香港域名
)

type MpApi string

const (
	// 开始开发
	BasicInformationToken         = "cgi-bin/token"             // 获取Access token
	BasicInformationApiDomainIp   = "cgi-bin/get_api_domain_ip" // 获取微信服务器IP地址
	BasicInformationCallbackCheck = "cgi-bin/callback/check"    // 网络检测

	// 自定义菜单
	CustomMenuCreate              = "cgi-bin/menu/create"               // 创建自定义菜单
	CustomMenuCurrentSelfMenuInfo = "cgi-bin/get_current_selfmenu_info" // 查询自定义菜单
	CustomMenuDelete              = "cgi-bin/menu/delete"               // 删除默认菜单及全部个性化菜单

	// 消息
	MessageCustomServiceKfAccountAdd           = "customservice/kfaccount/add"           // 添加客服
	MessageCustomServiceKfAccountUpdate        = "customservice/kfaccount/update"        // 修改客服
	MessageCustomServiceKfAccountDel           = "customservice/kfaccount/del"           // 删除客服
	MessageCustomServiceKfAccountUploadHeadImg = "customservice/kfaccount/uploadheadimg" // 上传客服头像
	MessageCustomServiceKfList                 = "cgi-bin/customservice/getkflist"       // 获取所有客服
	MessageCustomSend                          = "cgi-bin/message/custom/send"           // 客服接口-发消息
	MessageTemplateSend                        = "cgi-bin/message/template/send"         // 发送模板消息

	// 媒体文件上传
	MediaUploadImg = "cgi-bin/media/uploadimg" // 上传图文消息内的图片获取URL
	MediaUpload    = "cgi-bin/media/upload"    // 新增临时素材

	// 微信网页开发
	OaWebAppsSnsAuth2AccessToken = "sns/oauth2/access_token" // 通过code换取网页授权access_token
	OaWebAppsSnsUserInfo         = "sns/userinfo"            // 拉取用户信息(需scope为 snsapi_userinfo)

	// 用户管理
	UserTagsCreate           = "cgi-bin/tags/create"                 // 创建标签
	UserTagsGet              = "cgi-bin/tags/get"                    // 获取公众号已创建的标签
	UserTagsUpdate           = "cgi-bin/tags/update"                 // 编辑标签
	UserTagsDelete           = "cgi-bin/tags/delete"                 // 删除标签
	UserTagGet               = "cgi-bin/user/tag/get"                // 获取标签下粉丝列表
	UserTagMembersBatch      = "cgi-bin/tags/members/batchtagging"   // 批量为用户打标签
	UserTagMembersBatchUnTag = "cgi-bin/tags/members/batchuntagging" // 批量为用户取消标签
	UserTagsGetIdList        = "cgi-bin/tags/getidlist"              // 获取用户身上的标签列表

	GuideAccountAdd        = "cgi-bin/guide/addguideacct"
	UserManagementUserInfo = "cgi-bin/user/info"   // 获取用户基本信息（包括UnionID机制）
	TagsCreate             = "cgi-bin/tags/create" // 创建标签
	TagsGet                = "cgi-bin/tags/get"    // 获取公众号已创建的标签
	TagsDelete             = "cgi-bin/tags/delete" // 删除标签

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

type MediaType string

const (
	MediaTypeImage = "image"
	MediaTypeVoice = "voice"
	MediaTypeVideo = "video"
	MediaTypeThumb = "thumb"
)
