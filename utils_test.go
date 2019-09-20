package wxApi

import (
	"log"
	"testing"
)

func TestSafeString(t *testing.T) {
	str := "大慢美业美容服务有限公司中"
	log.Println(SafeString(str, 32))
}
