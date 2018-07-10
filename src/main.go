package main

/*
	Blockchain Threat Intelligence Sharing Platform By slowmist.com
	http/https反向代理，支持自定义回包规则（另一种原生的实现方法是 httputil.NewSingleHostReverseProxy, 有待测试）
	1. 开启监听端口
	2. Go协程处理每一个请求
	3. 加载配置文件 随机地址
	4. 解析并处理回包
	5. 返回，结束

	回传日志：
		1. 地址 IP 节点钱包地址
*/

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/slowmist/blockchain-threat-intelligence/src/etc"
	"github.com/slowmist/blockchain-threat-intelligence/src/filter"
	"github.com/slowmist/blockchain-threat-intelligence/src/logger"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	HTTP_TIMEOUT = 30 * time.Second //源站超时时间
)

//全局参数
type SLOWMIST struct {
	SLOWMIST_targetURL      *url.URL
	SLOWMIST_listenAddress  string
	SLOWMIST_isSSL          bool
	SLOWMIST_certPath       string
	SLOWMIST_privateKeyPath string
}

//监听端口
func (s *SLOWMIST) initServer() (net.Listener, error) {
	listenAddr := s.SLOWMIST_listenAddress
	if s.SLOWMIST_isSSL == true {
		fmt.Println("Listening on:", fmt.Sprintf("https://%s", listenAddr))
		_, err1 := os.Stat(s.SLOWMIST_certPath)
		_, err2 := os.Stat(s.SLOWMIST_privateKeyPath)
		var (
			cer tls.Certificate
			err error
		)
		if os.IsExist(err1) && os.IsExist(err2) {
			cer, err = tls.LoadX509KeyPair(s.SLOWMIST_certPath, s.SLOWMIST_privateKeyPath)
		} else {
			_cert, _ := etc.Asset(s.SLOWMIST_certPath)
			_pkey, _ := etc.Asset(s.SLOWMIST_privateKeyPath)
			cer, err = tls.X509KeyPair([]byte(_cert), []byte(_pkey))
		}
		if err != nil {
			log.Println(`certificate default file load failed!`, err.Error())
			return nil, err
		}
		config := &tls.Config{Certificates: []tls.Certificate{cer}}
		listener, err := tls.Listen("tcp", listenAddr, config)
		if err != nil {
			log.Println(`https listener failed!`, err.Error())
			return nil, err
		}
		return listener, err
	} else {
		fmt.Println("Listening on:", fmt.Sprintf("http://%s", listenAddr))
		listener, err := net.Listen("tcp", listenAddr)
		if err != nil {
			log.Println(`http listener failed!`, err.Error())
			return nil, err
		}
		return listener, err
	}
}

//构造新请求
func (s *SLOWMIST) buildNewReq(request *http.Request) (*http.Request, error) {
	_n := request.URL
	_n.Scheme = s.SLOWMIST_targetURL.Scheme
	_n.Host = s.SLOWMIST_targetURL.Host
	req, err := http.NewRequest(request.Method, _n.String(), request.Body)
	if err != nil {
		log.Println("Error new request:", err.Error())
		return req, err
	}
	req.Close = true
	for key := range request.Header {
		req.Header.Set(key, request.Header.Get(key))
	}
	if request.Referer() != "" {
		req.Header.Set("Referer", strings.Replace(request.Referer(), request.Host, s.SLOWMIST_targetURL.Host, -1))
	}
	req.Header.Del("Accept-Encoding")
	return req, err
}

//连接处理
func (s *SLOWMIST) handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	request.RemoteAddr = conn.RemoteAddr().String()
	if err != nil {
		log.Println("Error parsing request:", err.Error())
		return
	}
	requestTextBuff, _ := ioutil.ReadAll(request.Body)
	//请求源站
	req, _ := s.buildNewReq(request)
	client := &http.Client{
		Timeout: HTTP_TIMEOUT,
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Proxy error:", err.Error())
		return
	}
	//根据请求参数修改响应内容
	request.Body = ioutil.NopCloser(bytes.NewBufferString(string(requestTextBuff)))
	filter.ModifyResponse(request, resp)

	modifiedResponse, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Println("Error converting requests to bytes:", err.Error())
		return
	}
	_, err = conn.Write(modifiedResponse)
	if err != nil {
		log.Println("Error responding to clientclient:", err.Error())
		return
	}
}

func main() {
	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "target",
			Value: "https://mainnet.infura.io/LWLRS6nNpQR09kd6j1vE",
			Usage: "The ethereum host we used to proxy.",
		},
		cli.StringFlag{
			Name:  "listen",
			Value: "0.0.0.0:8545",
			Usage: "Address and port to run proxy service on. Format address:port.",
		},
		cli.StringFlag{
			Name:  "https",
			Value: "0",
			Usage: "Listen with TLS.",
		},
		cli.StringFlag{
			Name:  "cert",
			Value: "etc/server.crt",
			Usage: "Path to the x509 encoded SSL certificate in PEM format.",
		},
		cli.StringFlag{
			Name:  "private-key",
			Value: "etc/server.key",
			Usage: "Path to the x509 encoded certificate in PEM format.",
		},
		cli.StringFlag{
			Name:  "bounty",
			Value: "0x1234567890123456789012345678901234567800",
			Usage: `Send bounty(SlowMist Zone Token) to this address. (default: "0x1234567890123456789012345678901234567800")`,
		},
	}
	app.Action = func(c *cli.Context) error {
		_u, _ := url.Parse(c.String("target"))
		_t := &SLOWMIST{
			SLOWMIST_targetURL:      _u,
			SLOWMIST_listenAddress:  c.String("listen"),
			SLOWMIST_isSSL:          c.Bool("https"),
			SLOWMIST_certPath:       c.String("cert"),
			SLOWMIST_privateKeyPath: c.String("private-key"),
		}
		logger.BountyAddress = c.String("bounty")

		var s net.Listener
		s, _ = _t.initServer()

		for {
			conn, err := s.Accept()
			if err != nil {
				log.Println("Error when accepting request,", err.Error())
				continue
			}
			go _t.handleConnection(conn)
		}
	}
	app.Run(os.Args)
}
