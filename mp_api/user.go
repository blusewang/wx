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

type UserTagsUpdateData struct {
	Tag UserTag `json:"tag"`
}

type UserTagsDeleteData struct {
	Tag UserTag `json:"tag"`
}

type UserTagGetQuery struct {
	TagId      int64  `url:"tagid"`
	NextOpenId string `url:"next_openid"`
}

type UserTagGetRes struct {
	Count int64 `json:"count"`
	Data  struct {
		OpenId []string `json:"openid"`
	} `json:"data"`
	NextOpenId string `json:"next_openid"`
}

type UserTagMembersBatchData struct {
	OpenIdList []string `json:"openid_list"`
	TagId      int64    `json:"tagid"`
}

type UserTagMembersBatchUnTagData struct {
	OpenIdList []string `json:"openid_list"`
	TagId      int64    `json:"tagid"`
}

type UserTagsGetIdListData struct {
	OpenId string `json:"openid"`
}

type UserTagsGetIdListRes struct {
	MpBaseResp
	TagIdList []int64 `json:"tagid_list"`
}

type UserInfoUpdateRemarkData struct {
	OpenId string `json:"openid"`
	Remark string `json:"remark"`
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

type UserInfoBatchGetDataItem struct {
	OpenId string `json:"open_id"`
	Lang   string `json:"lang"`
}

type UserInfoBatchGetData struct {
	UserList []UserInfoBatchGetDataItem `json:"user_list"`
}

type UserInfoBatchGetRes struct {
	MpBaseResp
	UserInfoList []UserInfoRes `json:"user_info_list"`
}

type UserGetQuery struct {
	NextOpenId string `url:"next_openid"`
}

type UserGetRes struct {
	MpBaseResp
	Total int64 `json:"total"`
	Count int64 `json:"count"`
	Data  struct {
		OpenId []string `json:"openid"`
	} `json:"data"`
	NextOpenId string `json:"next_openid"`
}
