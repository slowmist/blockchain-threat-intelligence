package filter

import (
	"encoding/xml"
	"github.com/slowmist/blockchain-threat-intelligence/src/etc"
	// "io/ioutil"
	"log"
	// "regexp"
	"testing"
)

//测试xml文件读取
func TestReadConfig(t *testing.T) {
	content, err := etc.Asset(FILTER_CONFIG_FILE)
	if err != nil {
		t.Errorf("xml read error %s", err.Error())
	}
	var rs Resources
	err = xml.Unmarshal(content, &rs)
	if err != nil {
		t.Errorf("xml parse error %s", err.Error())
	}
	log.Printf("total %d rules!", len(rs.Rule))
}

//测试生成以太坊地址
func TestGenerateEthAddress(t *testing.T) {
	address := GenerateEthAddress()
	log.Println("Eth address:", address)
	// if err != nil {
	// 	t.Errorf("generate eth address error %s", err.Error())
	// }
}
