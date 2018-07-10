package logger

import (
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"testing"
)

//测试接口
func TestAPI(t *testing.T) {
	log.Println(BountyAddress)
	str := ""
	resp, err := http.Post(LOG_SERVER_API,
		"application/x-www-form-urlencoded",
		strings.NewReader(str))
	defer resp.Body.Close()
	if err != nil {
		t.Errorf("log api error %s", err.Error())
		return
	}
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("HTTP CODE: %d", resp.StatusCode)
	log.Println(string(body))
}
