package wxApi

import (
	"log"
	"testing"
)

func TestMp_UrlSign(t *testing.T) {
	var mp Mp
	mp.AppId = ""
	mp.AccessToken = "20_yTW5klfqkUC7S4t6KnpbkDUhABRfX8Cy08FDrOtywxWTNXKQ9Yb9GofXPMp-E612Ws4dfMquNkVLOPBvN-iPntohWFJt0BZOe6jkm_2vB1wBpRnrggaPpuKYHHziBdRZ8rhM6PBjwlG2CfR5PEXjADAFUN"
	mp.Ticket = "sM4AOVdWfPE4DxkXGEs8VDBHBi5leSJ5SXaqosbAfR0VxBBWLZOEZpeSBNF9YLk7EJTblEkfqI28KTkK0r1S_g"

	var rs = mp.UrlSign("http://www.mywsy.cn/")
	log.Println(rs)
}
