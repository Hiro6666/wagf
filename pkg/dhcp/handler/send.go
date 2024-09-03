package handler

import (
	"net"
	// dhcpv4msg "github.com/free5gc/wagf/pkg/dhcp/message"
	"github.com/free5gc/wagf/internal/logger"
)

func SendDHCPMessageToUE(udpConn *net.UDPConn, srcAddr, dstAddr *net.UDPAddr, message []byte) {
	dhcpLog.Infoln("Send DHCP message to UE")
	
	if _, err := udpConn.WriteTo(message, dstAddr); err != nil {
		logger.DHCPLog.Fatalf("Cannot reply to client: %v", err)
		return
	}
}