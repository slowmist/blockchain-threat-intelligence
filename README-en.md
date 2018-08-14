# Blockchain Threat Intelligence Sharing Platform

> by SlowMist Security Team & Joinsec Team

## [中文](./README.md)

## Introduction

SlowMist Zone threat intelligence sharing platform is a tool to simulate the RPC functions of node clients such as Ethereum and EOS, used to monitor attacks against blockchain systems in global networks.

## Instructions

### 1. Run with Docker
1.1 Install  [Docker][1]

1.2 Download the Source Code

```
$ git clone https://github.com/slowmist/blockchain-threat-intelligence.git --recursive
```

1.3 Use Docker

```
$ cd blockchain-threat-intelligence
$ docker build --rm -t btisp-agent . //Create the container
$ docker run -p 8545:8545 --name="btisp-agent-instance" btisp-agent --bounty 0x1234567890123456789012345678901234567800 //Create the container and specify the ethereum wallet address to receive SLOWMIST incentive.
$ docker start btisp-agent-instance //Activate the container
$ docker stop btisp-agent-instance //Stop the container
$ docker rm btisp-agent-instance //Remove the container
```

### 2. Source Code Compilation Execution
2.1 Install [Golang][2]

2.2 Download the Source Code

```
$ go get -u github.com/slowmist/blockchain-threat-intelligence
```

2.3 Compilation Run

```
$ cd $GOPATH/src/github.com/slowmist/blockchain-threat-intelligence/src
$ mkdir ../bin ../pkg
$ go build -o ../bin/btisp-agent //Compilation
$ ../bin/btisp-agent --bounty 0x1234567890123456789012345678901234567800 //Activate and specify the ethereum wallet address to receive SLOWMIST incentive.
```

## The Command

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

## Test

```
$ curl -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":999}' http://localhost:8545
```

  [1]: https://www.docker.com/products/docker "Docker Website"
  [2]: https://golang.org/ "Golang"
