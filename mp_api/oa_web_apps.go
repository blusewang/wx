package mp_api

type OaWebAppsSnsAuth2AccessTokenQuery struct {
	AppId     string `param:"appid"`
	Secret    string `param:"secret"`
	Code      string `param:"code"`
	GrantType string `param:"grant_type"`
}
type OaWebAppsSnsAuth2AccessTokenRes struct {
	MpBaseResp
	AccessToken  string `json:"access_token"`
	ExpireIn     int64  `json:"expire_in"`
	RefreshToken string `json:"refresh_token"`
	OpenId       string `json:"openid"`
	Scope        string `json:"scope"`
}

type OaWebAppsSnsUserInfoQuery struct {
	OpenId string `param:"open_id"`
	Lang   string `param:"lang"`
}

type OaWebAppsSnsUserInfoRes struct {
	MpBaseResp
	OpenId     string   `json:"open_id"`
	NickName   string   `json:"nickname"`
	Sex        int64    `json:"sex"`
	Province   string   `json:"province"`
	City       string   `json:"city"`
	Country    string   `json:"country"`
	HeadImgUrl string   `json:"headimgurl"`
	Privilege  []string `json:"privilege"`
	UnionId    string   `json:"unionid"`
}

type OaWebAppsJsSDKTicketQuery struct {
	Type JsSDKTicketType `param:"type"`
}

type OaWebAppsJsSDKTicketRes struct {
	MpBaseResp
	Ticket    string `json:"ticket"`
	ExpiresIn int64  `json:"expires_in"`
}
