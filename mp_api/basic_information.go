package mp_api

type BasicInformationTokenQuery struct {
	GrantType string `url:"grant_type"`
	AppId     string `url:"appid"`
	Secret    string `url:"secret"`
}

type BasicInformationTokenRes struct {
	MpBaseResp
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

type GetApiDomainIpRes struct {
	MpBaseResp
	IpList []string `json:"ip_list"`
}

type CallbackCheckData struct {
	Action        string `json:"action"`
	CheckOperator string `json:"check_operator"`
}

type CallbackCheckRes struct {
	MpBaseResp
	Dns []struct {
		Ip           string `json:"ip"`
		RealOperator string `json:"real_operator"`
	} `json:"dns"`
	Ping []struct {
		Ip           string `json:"ip"`
		FromOperator string `json:"from_operator"`
		PackageLoss  string `json:"package_loss"`
		Time         string `json:"time"`
	} `json:"ping"`
}
