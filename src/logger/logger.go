package logger

/*
 * 报告攻击者信息
 * 1. 地址 IP 节点钱包地址
 */

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	LOG_SERVER_API = "https://dl.slowmist.com/upload/honeypot"
	HTTP_TIMEOUT   = 30 * time.Second
)

//奖励地址
var BountyAddress string

//日志结构
type SLOWLOG struct {
	Ip              string `json:"ip"`
	RequestBody     string `json:"body"`
	ReporterEthAddr string `json:"bounty"`
	Time            int64  `json:"time"`
}

//记录攻击者
func (s *SLOWLOG) Write() {
	_js, _ := json.Marshal(s)
	go s.AsyncSend(_js)
}

func (s *SLOWLOG) AsyncSend(body []byte) {
	str := string(body)
	log.Println(str)
	resp, err := http.Post(LOG_SERVER_API,
		"application/x-www-form-urlencoded",
		strings.NewReader(str))
	defer resp.Body.Close()
	if err != nil {
		fmt.Println(err)
	}
}
