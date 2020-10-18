package mp_api

type UserTag struct {
	Id    int64  `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
	Count int64  `json:"count,omitempty"`
}

type UserTagsCreateData struct {
	Tag UserTag `json:"tag"`
}

type UserTagsCreateRes struct {
	MpBaseResp
	Tag UserTag `json:"tag"`
}

type UserTagsGetRes struct {
	MpBaseResp
	Tags []UserTag `json:"tags"`
}

type UserTagsDeleteData struct {
	Tag UserTag `json:"tag"`
}

type UserInfoQuery struct {
	OpenId string `url:"openid"`
	Lang   string `url:"lang"`
}
type UserInfoRes struct {
	MpBaseResp
	Subscribe      int64   `json:"subscribe"`
	OpenId         string  `json:"openid"`
	NickName       string  `json:"nickname"`
	Sex            int64   `json:"sex"`
	Language       string  `json:"language"`
	City           string  `json:"city"`
	Province       string  `json:"province"`
	Country        string  `json:"country"`
	HeadImgUrl     string  `json:"headimgurl"`
	SubscribeTime  int64   `json:"subscribe_time"`
	UnionId        string  `json:"unionid"`
	Remark         string  `json:"remark"`
	GroupId        int64   `json:"group_id"`
	TagIdList      []int64 `json:"tagid_list"`
	SubscribeScene string  `json:"subscribe_scene"`
	QrScene        int64   `json:"qr_scene"`
	QrSceneStr     string  `json:"qr_scene_str"`
}
