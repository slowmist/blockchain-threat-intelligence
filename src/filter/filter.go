package filter

/*
 * 解析配置规则
 */

import (
	"bytes"
	// "encoding/hex"
	"encoding/xml"
	"fmt"
	"github.com/slowmist/blockchain-threat-intelligence/src/etc"
	// "github.com/ethereum/go-ethereum/crypto"
	"github.com/slowmist/blockchain-threat-intelligence/src/logger"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	FILTER_CONFIG_FILE = "etc/rule.xml" //配置文件
)

var (
	XML_RULES, _ = ReadConfig()
)

type Resources struct {
	XMLName xml.Name `xml:"resources"`
	Rule    []Rule   `xml:"rule"`
}

type Rule struct {
	Method  string `xml:"method"`
	Match   string `xml:"match"`
	Replace string `xml:"replace"`
}

var idre1 = regexp.MustCompile("id\":")
var idre2 = regexp.MustCompile(",")
var idre3 = regexp.MustCompile("}")

//生成真实以太坊地址
// func RealEthAddress() (string, error) {
// 	key, err := crypto.GenerateKey()
// 	if err != nil {
// 		log.Fatal(err)
// 		return "", err
// 	}
// 	address := crypto.PubkeyToAddress(key.PublicKey).Hex()
// 	privateKey := hex.EncodeToString(key.D.Bytes())

// 	return address, nil
// }

//生成随机以太坊地址
func GenerateEthAddress() string {
	str := "0123456789abcdef"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 40; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}

	return "0x" + string(result)
}

func Cutidstr(str string) string {
	sstr := str[idre1.FindStringIndex(str)[1]:]
	idstr := ""
	if len(idre2.FindStringIndex(sstr)) > 0 {
		idstr = sstr[:idre2.FindStringIndex(sstr)[0]]
	} else if len(idre3.FindStringIndex(sstr)) > 0 {
		idstr = sstr[:idre3.FindStringIndex(sstr)[0]]
	}
	return idstr
}

//根据请求特征码修改响应内容
func ModifyResponse(req *http.Request, resp *http.Response) {
	//提取body req.Body是一个reader，所以只能读取一次后再赋值回
	requestTextBuff, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Println("Error read buff:", err.Error())
		return
	}
	requestText := string(requestTextBuff)
	// reqestUri := req.RequestURI
	// request.Body = ioutil.NopCloser(bytes.NewBufferString(requestText))
	//空置时直接返回原值
	idtext := ""
	if len(idre1.FindString(requestText)) > 0 {
		idtext = Cutidstr(requestText)
	}
	for _, o := range XML_RULES.Rule {
		// m := o.Method
		k := o.Match
		v := o.Replace
		var re = regexp.MustCompile(k)
		if len(re.FindString(requestText)) > 0 {
			v = strings.Replace(v, "0x7fa4cbba9a4f14040da18ffc6778c25e4cc71f39", GenerateEthAddress(), -1)
			transresponseText := fmt.Sprintf(v, idtext) + "\n"
			resp.ContentLength = int64(len(transresponseText))
			newresponse := bytes.NewBufferString(transresponseText)
			resp.Body = ioutil.NopCloser(newresponse)
			//记录日志
			_ip := req.RemoteAddr
			_lg := &logger.SLOWLOG{
				Ip:              _ip,
				RequestBody:     requestText,
				ReporterEthAddr: logger.BountyAddress,
				Time:            time.Now().Unix(),
			}
			_lg.Write()
			log.Println("rewrite mode")
			break
		}
	}
}

//从xml文件中读取配置
func ReadConfig() (Resources, error) {
	var rs Resources
	content, err := etc.Asset(FILTER_CONFIG_FILE)
	if err != nil {
		log.Fatal(err)
		return rs, err
	}
	err = xml.Unmarshal(content, &rs)
	if err != nil {
		log.Fatal(err)
		return rs, err
	}
	return rs, err
}
