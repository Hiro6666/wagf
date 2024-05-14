package util

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	"git.cs.nctu.edu.tw/calee/sctp"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/wagf/internal/logger"
	"github.com/free5gc/wagf/pkg/context"
	"github.com/free5gc/wagf/pkg/factory"
)

var contextLog *logrus.Entry

const RadiusDefaultSecret = "free5GC"

func InitWAGFContext() bool {
	var ok bool
	contextLog = logger.ContextLog

	// check wagf config whether exists
	if factory.WagfConfig.Configuration == nil {
		contextLog.Error("No wagf configuration found")
		return false
	}

	wagfContext := context.WAGFSelf()
	fmt.Println("in my iniContext wagfContext", &wagfContext)

	// wagf NF information
	// wagfContext.NFInfo：get WAGFInformation-> {{{208 93} 135} free5GC_WAGF [{000001 [{{208 93} [{{1 010203}} {{1 112233}}]}]}]}
	wagfContext.NFInfo = factory.WagfConfig.Configuration.WAGFInfo
	// put TAList info into wagfContext TAlist
	if ok = formatSupportedTAList(&wagfContext.NFInfo); !ok {
		return false
	}

	// AMF SCTP addresses
	if len(factory.WagfConfig.Configuration.AMFSCTPAddresses) == 0 {
		contextLog.Error("No AMF specified")
		return false
	} else {
		for _, amfAddress := range factory.WagfConfig.Configuration.AMFSCTPAddresses {
			amfSCTPAddr := new(sctp.SCTPAddr)
			// IP addresses
			for _, ipAddrStr := range amfAddress.IPAddresses {
				if ipAddr, err := net.ResolveIPAddr("ip", ipAddrStr); err != nil {
					contextLog.Errorf("Resolve AMF IP address failed: %+v", err)
					return false
				} else {
					amfSCTPAddr.IPAddrs = append(amfSCTPAddr.IPAddrs, *ipAddr)
				}
			}
			// Port
			if amfAddress.Port == 0 {
				amfSCTPAddr.Port = 38412
			} else {
				amfSCTPAddr.Port = amfAddress.Port
			}
			// Append to context
			wagfContext.AMFSCTPAddresses = append(wagfContext.AMFSCTPAddresses, amfSCTPAddr)
		}
	}

	// IKE bind address
	if factory.WagfConfig.Configuration.IKEBindAddr == "" {
		contextLog.Error("IKE bind address is empty")
		return false
	} else {
		wagfContext.IKEBindAddress = factory.WagfConfig.Configuration.IKEBindAddr
	}

	// Radius bind address
	if factory.WagfConfig.Configuration.RadiusBindAddr == "" {
		contextLog.Error("IKE bind address is empty")
		return false
	} else {
		wagfContext.RadiusBindAddress = factory.WagfConfig.Configuration.RadiusBindAddr
	}

	// DHCP bind adress
	if factory.WagfConfig.Configuration.DHCPBindAddr == "" {
		contextLog.Error("DHCP bind address is empty")
		return false
	} else {
		wagfContext.DHCPBindAddress = factory.WagfConfig.Configuration.DHCPBindAddr
	}

	// IPSec gateway address
	if factory.WagfConfig.Configuration.IPSecGatewayAddr == "" {
		contextLog.Error("IPSec interface address is empty")
		return false
	} else {
		wagfContext.IPSecGatewayAddress = factory.WagfConfig.Configuration.IPSecGatewayAddr
	}

	// GTP bind address
	if factory.WagfConfig.Configuration.GTPBindAddr == "" {
		contextLog.Error("GTP bind address is empty")
		return false
	} else {
		wagfContext.GTPBindAddress = factory.WagfConfig.Configuration.GTPBindAddr
	}

	// TCP port
	if factory.WagfConfig.Configuration.TCPPort == 0 {
		contextLog.Error("TCP port is not defined")
		return false
	} else {
		wagfContext.TCPPort = factory.WagfConfig.Configuration.TCPPort
	}

	// FQDN
	if factory.WagfConfig.Configuration.FQDN == "" {
		contextLog.Error("FQDN is empty")
		return false
	} else {
		wagfContext.FQDN = factory.WagfConfig.Configuration.FQDN
	}

	// Private key
	{
		var keyPath string

		if factory.WagfConfig.Configuration.PrivateKey == "" {
			contextLog.Warn("No private key file path specified, load default key file...")
			keyPath = WagfDefaultKeyPath
		} else {
			keyPath = factory.WagfConfig.Configuration.PrivateKey
		}

		content, err := ioutil.ReadFile(keyPath)
		if err != nil {
			contextLog.Errorf("Cannot read private key data from file: %+v", err)
			return false
		}
		block, _ := pem.Decode(content)
		if block == nil {
			contextLog.Error("Parse pem failed")
			return false
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			contextLog.Warnf("Parse PKCS8 private key failed: %+v", err)
			contextLog.Info("Parse using PKCS1...")

			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				contextLog.Errorf("Parse PKCS1 pricate key failed: %+v", err)
				return false
			}
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			contextLog.Error("Private key is not an rsa private key")
			return false
		}

		wagfContext.WAGFPrivateKey = rsaKey
	}

	// Certificate authority
	{
		var keyPath string

		if factory.WagfConfig.Configuration.CertificateAuthority == "" {
			contextLog.Warn("No certificate authority file path specified, load default CA certificate...")
			keyPath = WagfDefaultPemPath
		} else {
			keyPath = factory.WagfConfig.Configuration.CertificateAuthority
		}

		// Read .pem
		content, err := ioutil.ReadFile(keyPath)
		if err != nil {
			contextLog.Errorf("Cannot read certificate authority data from file: %+v", err)
			return false
		}
		// Decode pem
		block, _ := pem.Decode(content)
		if block == nil {
			contextLog.Error("Parse pem failed")
			return false
		}
		// Parse DER-encoded x509 certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			contextLog.Errorf("Parse certificate authority failed: %+v", err)
			return false
		}
		// Get sha1 hash of subject public key info
		sha1Hash := sha1.New()
		if _, err := sha1Hash.Write(cert.RawSubjectPublicKeyInfo); err != nil {
			contextLog.Errorf("Hash function writing failed: %+v", err)
			return false
		}

		wagfContext.CertificateAuthority = sha1Hash.Sum(nil)
	}

	// Certificate
	{
		var keyPath string

		if factory.WagfConfig.Configuration.Certificate == "" {
			contextLog.Warn("No certificate file path specified, load default certificate...")
			keyPath = WagfDefaultPemPath
		} else {
			keyPath = factory.WagfConfig.Configuration.Certificate
		}

		// Read .pem
		content, err := ioutil.ReadFile(keyPath)
		if err != nil {
			contextLog.Errorf("Cannot read certificate data from file: %+v", err)
			return false
		}
		// Decode pem
		block, _ := pem.Decode(content)
		if block == nil {
			contextLog.Error("Parse pem failed")
			return false
		}

		wagfContext.WAGFCertificate = block.Bytes
	}

	// Radius Secret
	{
		if factory.WagfConfig.Configuration.RadiusSecret == "" {
			contextLog.Warn("No RADIUS secret specified, load default secret...")
			wagfContext.RadiusSecret = RadiusDefaultSecret
		} else {
			wagfContext.RadiusSecret = factory.WagfConfig.Configuration.RadiusSecret
		}
	}

	// UE IP address range
	if factory.WagfConfig.Configuration.UEIPAddressRange == "" {
		contextLog.Error("UE IP address range is empty")
		return false
	} else {
		_, ueIPRange, err := net.ParseCIDR(factory.WagfConfig.Configuration.UEIPAddressRange)
		if err != nil {
			contextLog.Errorf("Parse CIDR failed: %+v", err)
			return false
		}
		wagfContext.Subnet = ueIPRange
	}

	// XFRM related
	ikeBindIfaceName, err := GetInterfaceName(factory.WagfConfig.Configuration.IKEBindAddr)
	if err != nil {
		contextLog.Error(err)
		return false
	} else {
		wagfContext.XfrmParentIfaceName = ikeBindIfaceName
	}

	if factory.WagfConfig.Configuration.XfrmIfaceName == "" {
		contextLog.Error("XFRM interface Name is empty, set to default \"ipsec\"")
		wagfContext.XfrmIfaceName = "ipsec"
	} else {
		wagfContext.XfrmIfaceName = factory.WagfConfig.Configuration.XfrmIfaceName
	}

	if factory.WagfConfig.Configuration.XfrmIfaceId == 0 {
		contextLog.Warn("XFRM interface id is not defined, set to default value 7")
		wagfContext.XfrmIfaceId = 7
	} else {
		wagfContext.XfrmIfaceId = factory.WagfConfig.Configuration.XfrmIfaceId
	}

	return true
}

func formatSupportedTAList(info *context.WAGFNFInfo) bool {
	for taListIndex := range info.SupportedTAList {
		supportedTAItem := &info.SupportedTAList[taListIndex]

		// Checking TAC
		if supportedTAItem.TAC == "" {
			contextLog.Error("TAC is mandatory.")
			return false
		}
		if len(supportedTAItem.TAC) < 6 {
			contextLog.Trace("Detect configuration TAC length < 6")
			supportedTAItem.TAC = strings.Repeat("0", 6-len(supportedTAItem.TAC)) + supportedTAItem.TAC
			contextLog.Tracef("Changed to %s", supportedTAItem.TAC)
		} else if len(supportedTAItem.TAC) > 6 {
			contextLog.Error("Detect configuration TAC length > 6")
			return false
		}

		// Checking SST and SD
		for plmnListIndex := range supportedTAItem.BroadcastPLMNList {
			broadcastPLMNItem := &supportedTAItem.BroadcastPLMNList[plmnListIndex]

			for sliceListIndex := range broadcastPLMNItem.TAISliceSupportList {
				sliceSupportItem := &broadcastPLMNItem.TAISliceSupportList[sliceListIndex]

				// SST
				if sliceSupportItem.SNSSAI.SST == "" {
					contextLog.Error("SST is mandatory.")
				}
				if len(sliceSupportItem.SNSSAI.SST) < 2 {
					contextLog.Trace("Detect configuration SST length < 2")
					sliceSupportItem.SNSSAI.SST = "0" + sliceSupportItem.SNSSAI.SST
					contextLog.Tracef("Change to %s", sliceSupportItem.SNSSAI.SST)
				} else if len(sliceSupportItem.SNSSAI.SST) > 2 {
					contextLog.Error("Detect configuration SST length > 2")
					return false
				}

				// SD
				if sliceSupportItem.SNSSAI.SD != "" {
					if len(sliceSupportItem.SNSSAI.SD) < 6 {
						contextLog.Trace("Detect configuration SD length < 6")
						sliceSupportItem.SNSSAI.SD = strings.Repeat("0", 6-len(sliceSupportItem.SNSSAI.SD)) + sliceSupportItem.SNSSAI.SD
						contextLog.Tracef("Change to %s", sliceSupportItem.SNSSAI.SD)
					} else if len(sliceSupportItem.SNSSAI.SD) > 6 {
						contextLog.Error("Detect configuration SD length > 6")
						return false
					}
				}
			}
		}
	}

	return true
}

func GetInterfaceName(IPAddress string) (interfaceName string, err error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "nil", err
	}

	for _, inter := range interfaces {
		addrs, err := inter.Addrs()
		if err != nil {
			return "nil", err
		}
		for _, addr := range addrs {
			if IPAddress == addr.String()[0:strings.Index(addr.String(), "/")] {
				return inter.Name, nil
			}
		}
	}
	return "", fmt.Errorf("Cannot find interface name")
}
