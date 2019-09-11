package wxApi

import (
	"log"
	"testing"
)

func TestSafeString(t *testing.T) {
	log.Println(SafeString("A     晟鑫造型    卢洋", 7))
}
