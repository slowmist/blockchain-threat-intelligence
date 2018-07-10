# Blockchain Threat Intelligence Sharing Platform（区块链威胁情报共享平台）

> by 慢雾安全团队 & Joinsec Team

## 简介
慢雾区块链威胁情报共享平台是一个模拟以太坊、EOS等节点客户端 RPC 功能的工具，用于监测全球网络中针对区块链系统的攻击。

## 使用方法

### 1. 使用 Docker 运行
1.1 安装  [Docker][1]

1.2 下载源代码

```
$ git clone https://github.com/slowmist/blockchain-threat-intelligence.git
```

1.3 使用 Docker

```
$ cd blockchain-threat-intelligence
$ docker build --rm -t btisp-agent . //创建镜像
$ docker run -p 8545:8545 --name="btisp-agent-instance" btisp-agent --bounty 0x1234567890123456789012345678901234567800 //创建容器，并指定接收慢雾币激励的以太坊钱包地址
$ docker start btisp-agent-instance //启动容器
$ docker stop btisp-agent-instance //停止容器
$ docker rm btisp-agent-instance //删除容器
```

### 2. 源代码编译执行
2.1 安装 [Golang][2]

2.2 下载源代码

```
$ go get -u github.com/slowmist/blockchain-threat-intelligence
```

2.3 编译运行

```
$ go-bindata -pkg etc -o etc/bindata.go etc/ //打包配置资源
$ cd $GOPATH/src/github.com/slowmist/blockchain-threat-intelligence/bin 
$ go build -o btisp-agent ../src/ //编译
$ ./btisp-agent --bounty 0x1234567890123456789012345678901234567800 //启动，并指定接收慢雾币激励的以太坊钱包地址
```

## 命令详解

```
$ ./btisp-agent --help

USAGE:
   btisp-agent [global options] command [command options] [arguments...]

COMMANDS:
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --target value       The ethereum host we used to proxy. (default: "https://mainnet.infura.io/LWLRS6nNpQR09kd6j1vE")
   --listen value       Address and port to run proxy service on. Format address:port. (default: "0.0.0.0:8545")
   --https value        Listen with TLS. (default: "0")
   --cert value         Path to the x509 encoded SSL certificate in PEM format. (default: "etc/server.crt")
   --private-key value  Path to the x509 encoded certificate in PEM format. (default: "etc/server.key")
   --bounty value       Send bounty(SlowMist Zone Token) to this address. (default: "0x1234567890123456789012345678901234567800")
   --help, -h           show help
   --version, -v        print the version
```

## 测试

```
$ curl -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":999}' http://localhost:8545
```

  [1]: https://www.docker.com/products/docker "Docker官网"
  [2]: https://golang.org/ "Golang"