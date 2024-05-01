module github.com/free5gc/wagf

go 1.14

require (
	git.cs.nctu.edu.tw/calee/sctp v1.1.0
	github.com/antonfisher/nested-logrus-formatter v1.3.1
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d
	github.com/calee0219/fatal v0.0.1
	github.com/davecgh/go-spew v1.1.1
	github.com/free5gc/aper v1.0.4
	github.com/free5gc/nas v1.0.7
	github.com/free5gc/ngap v1.0.6
	github.com/free5gc/openapi v1.0.5
	github.com/free5gc/util v1.0.3
	github.com/google/gopacket v1.1.19
	github.com/insomniacslk/dhcp v0.0.0-20231206064809-8c70d406f6d2
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/u-root/uio v0.0.0-20230305220412-3e8cd9d6bf63
	github.com/urfave/cli v1.22.5
	github.com/vishvananda/netlink v1.1.0
	github.com/wmnsk/go-gtp v0.8.0
	golang.org/x/net v0.17.0
	golang.org/x/sys v0.13.0
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.0
)

replace github.com/free5gc/ngap => /home/tsc/free5gc/ngap

replace github.com/free5gc/util => /home/tsc/free5gc/util

replace github.com/free5gc/openapi => /home/tsc/free5gc/openapi
