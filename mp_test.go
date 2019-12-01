package wxApi

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"strconv"
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

func TestMp_AppAuthToken(t *testing.T) {
	log.Println(fmt.Sprintf("%X", []byte("时会将订单剩余")))
}

func TestMpMessage_ShouldDecode(t *testing.T) {
	var buf = new(bytes.Buffer)
	buf.WriteString(`<xml><ToUserName><![CDATA[gh_930afe6ccfc4]]></ToUserName>
<FromUserName><![CDATA[oEG8Ss5_zZ8iZcaxwNMrVItCLVWA]]></FromUserName>
<CreateTime>1575092600</CreateTime>
<MsgType><![CDATA[event]]></MsgType>
<Event><![CDATA[MASSSENDJOBFINISH]]></Event>
<MsgID>3147484542</MsgID>
<Status><![CDATA[send success]]></Status>
<TotalCount>11</TotalCount>
<FilterCount>9</FilterCount>
<SentCount>9</SentCount>
<ErrorCount>0</ErrorCount>
<CopyrightCheckResult><Count>0</Count>
<ResultList></ResultList>
<CheckState>0</CheckState>
</CopyrightCheckResult>
<ArticleUrlResult><Count>0</Count>
<ResultList></ResultList>
</ArticleUrlResult>
</xml>`)
	var msg, msg2 MpMessage
	if err := xml.NewDecoder(buf).Decode(&msg); err != nil {
		t.Fatal(err)
	}
	log.Println(msg.MsgType, msg.MsgId, msg.MsgID)
	log.Println(strconv.FormatInt(msg.MsgID, 10))

	raw, _ := json.Marshal(msg)
	log.Println(string(raw))
	_ = json.Unmarshal(raw, &msg2)
	log.Println(msg2.MsgType, msg2.MsgId, msg2.MsgID)
}
