package mp_api

type MediaUploadImgRes struct {
	MpBaseResp
	Url string `json:"url"`
}

type MediaUploadQuery struct {
	Type MediaType `url:"type"`
}
type MediaUploadRes struct {
	MpBaseResp
	Type      string `json:"type"`
	MediaId   string `json:"media_id"`
	CreatedAt int64  `json:"created_at"`
}
