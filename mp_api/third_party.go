package mp_api

const (
	ThirdPartyApiStartPushTicket = "cgi-bin/component/api_start_push_ticket"
	ThirdPartyApiToken           = "cgi-bin/component/api_component_token"
	ThirdPartyApiQueryAuth       = "cgi-bin/component/api_query_auth"
	ThirdPartyApiAuthorizerToken = "cgi-bin/component/api_authorizer_token"
	ThirdPartyJsCode2Session     = "sns/component/jscode2session"
)

type ThirdPartyAuthFuncscopeCategory struct {
	FuncscopeCategory struct {
		Id   int    `json:"id"`
		Type int    `json:"type"`
		Name string `json:"name"`
		Desc string `json:"desc"`
	} `json:"funcscope_category"`
}
type ThirdPartyQueryAuthResp struct {
	MpBaseResp
	AuthorizationInfo struct {
		AuthorizerAppid        string                            `json:"authorizer_appid"`
		AuthorizerAccessToken  string                            `json:"authorizer_access_token"`
		ExpiresIn              int                               `json:"expires_in"`
		AuthorizerRefreshToken string                            `json:"authorizer_refresh_token"`
		FuncInfo               []ThirdPartyAuthFuncscopeCategory `json:"func_info"`
	} `json:"authorization_info"`
}

type ThirdPartyApiAuthorizerTokenResp struct {
	MpBaseResp
	AuthorizerAccessToken  string `json:"authorizer_access_token"`
	ExpiresIn              int    `json:"expires_in"`
	AuthorizerRefreshToken string `json:"authorizer_refresh_token"`
}

type ThirdPartyJsCode2SessionQuery struct {
	Appid                string `url:"appid"`
	GrantType            string `url:"grant_type"`
	ComponentAppid       string `url:"component_appid"`
	ComponentAccessToken string `url:"component_access_token"`
	JsCode               string `url:"js_code"`
}
type ThirdPartyJsCode2SessionResp struct {
	MpBaseResp
	SessionKey string `json:"session_key"`
	Unionid    string `json:"unionid"`
	Openid     string `json:"openid"`
}
