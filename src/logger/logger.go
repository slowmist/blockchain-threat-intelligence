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
)

const (
	LOG_SERVER_API = "https://dl.slowmist.com/upload"
	// LOG_SERVER_API = "http://localhost/upload/honeypot"
	// HTTP_TIMEOUT = 30 * time.Second
)

//奖励地址
var BountyAddress string

//启动日志
type STARTLOG struct {
	ClientVersion   string `json:"version"`
	ReporterEthAddr string `json:"bounty"`
	Time            int64  `json:"time"`
}

func (s *STARTLOG) Write() {
	_js, _ := json.Marshal(s)
	go post(LOG_SERVER_API+"/honeypot", _js)
}

//攻击者日志
type ATTACKLOG struct {
	IP              string `json:"ip"`
	RequestBody     string `json:"body"`
	ReporterEthAddr string `json:"bounty"`
	Time            int64  `json:"time"`
}

func (s *ATTACKLOG) Write() {
	_js, _ := json.Marshal(s)
	go post(LOG_SERVER_API+"/version", _js)
}

//发送日志
func post(url string, body []byte) {
	str := string(body)
	if len(str) > 1024*10 { //限制最大10k的上传数据
		log.Println("len", len(str))
		return
	}
	fmt.Println(str)
	resp, err := http.Post(url,
		"application/x-www-form-urlencoded",
		strings.NewReader(str))
	defer resp.Body.Close()
	if err != nil {
		fmt.Println(err)
	}
}
