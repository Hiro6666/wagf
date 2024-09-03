package dhcp

import (
	"fmt"
	"net"
	"runtime/debug"

	"github.com/free5gc/wagf/internal/logger"
	"github.com/free5gc/wagf/pkg/dhcp/handler"
	dhcpv4msg "github.com/free5gc/wagf/pkg/dhcp/message"
	"github.com/sirupsen/logrus"
)

var dhcpLog *logrus.Entry

func init() {
	dhcpLog = logger.DHCPLog
}

func Dispatch(udpConn *net.UDPConn, localAddr *net.UDPAddr, remoteAddr *net.Addr, msg []byte) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.DHCPLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	dhcpMessage, err := dhcpv4msg.FromBytes(msg)
	if err != nil {
		logger.DHCPLog.Fatalf("Error parsing DHCPv4 request: %v", err)
		return
	}

	// reply, err := dhcpv4msg.NewReplyFromRequest(dhcpMessage)
	// if err != nil {
	// 	logger.DHCPLog.Fatalf("NewReplyFromRequest failed: %v", err)
	// 	return
	// }

	uremoteAddr, ok := (*remoteAddr).(*net.UDPAddr)
	if !ok {
		logger.DHCPLog.Fatalf("Not a UDP connection? Peer is %s", uremoteAddr)
		return
	}

	// Set peer to broadcast if the client did not have an IP.
	if uremoteAddr.IP == nil || uremoteAddr.IP.To4().Equal(net.IPv4zero) {
		uremoteAddr = &net.UDPAddr{
			IP:   net.IPv4bcast,
			Port: uremoteAddr.Port,
		}
	}

	switch mt := dhcpMessage.MessageType(); mt {
	case dhcpv4msg.MessageTypeDiscover:
		fmt.Println("I'm in MessageTypeDiscover")
		handler.HandleDHCPDiscover(udpConn, localAddr, uremoteAddr, dhcpMessage)
		// reply.UpdateOption(dhcpv4msg.OptMessageType(dhcpv4msg.MessageTypeOffer))
	case dhcpv4msg.MessageTypeRequest:
		handler.HandleDHCPRequest(udpConn, localAddr, uremoteAddr, dhcpMessage)
		// reply.UpdateOption(dhcpv4msg.OptMessageType(dhcpv4msg.MessageTypeAck))
	default:
		logger.DHCPLog.Fatalf("Unhandled message type: %v", mt)
		return
	}

	// if _, err := udpConn.WriteTo(reply.ToBytes(), uremoteAddr); err != nil {
	// 	logger.DHCPLog.Fatalf("Cannot reply to client: %v", err)
	// 	return
	// }

}
