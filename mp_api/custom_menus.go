package mp_api

type MenuButton struct {
	Type      string       `json:"type"`
	Name      string       `json:"name"`
	Key       string       `json:"key,omitempty"`
	Url       string       `json:"url,omitempty"`
	MediaId   string       `json:"media_id,omitempty"`
	AppId     string       `json:"appid,omitempty"`
	PagePath  string       `json:"pagepath,omitempty"`
	SubButton []MenuButton `json:"sub_button,omitempty"`
}

type MenuCreateData struct {
	Button []MenuButton `json:"button"`
}

type CustomMenuCurrentSelfMenuInfoRes struct {
	MpBaseResp
	IsMenuOpen   int64 `json:"is_menu_open"`
	SelfMenuInfo struct {
		Button []MenuButton `json:"button"`
	} `json:"selfmenu_info"`
}
