package service

import (
	"context"
	"errors"
	"net"

	"github.com/sirupsen/logrus"
	gtp "github.com/wmnsk/go-gtp/gtpv1"
	gtpMsg "github.com/wmnsk/go-gtp/gtpv1/message"

	"github.com/free5gc/wagf/internal/gtp/handler"
	"github.com/free5gc/wagf/internal/logger"
	wagfContext "github.com/free5gc/wagf/pkg/context"
)

var gtpLog *logrus.Entry

var gtpContext context.Context

func init() {
	gtpLog = logger.GTPLog
	gtpContext = context.TODO()
}

// SetupGTPTunnelWithUPF set up GTP connection with UPF
// return *gtp.UPlaneConn, net.Addr and error
func SetupGTPTunnelWithUPF(upfIPAddr string) (*gtp.UPlaneConn, net.Addr, error) {
	wagfSelf := wagfContext.WAGFSelf()

	// Set up GTP connection
	upfUDPAddr := upfIPAddr + gtp.GTPUPort

	remoteUDPAddr, err := net.ResolveUDPAddr("udp", upfUDPAddr)
	if err != nil {
		gtpLog.Errorf("Resolve UDP address %s failed: %+v", upfUDPAddr, err)
		return nil, nil, errors.New("Resolve Address Failed")
	}

	wagfUDPAddr := wagfSelf.GTPBindAddress + gtp.GTPUPort

	localUDPAddr, err := net.ResolveUDPAddr("udp", wagfUDPAddr)
	if err != nil {
		gtpLog.Errorf("Resolve UDP address %s failed: %+v", wagfUDPAddr, err)
		return nil, nil, errors.New("Resolve Address Failed")
	}

	// Dial to UPF
	userPlaneConnection, err := gtp.DialUPlane(gtpContext, localUDPAddr, remoteUDPAddr)
	if err != nil {
		gtpLog.Errorf("Dial to UPF failed: %+v", err)
		return nil, nil, errors.New("Dial failed")
	}

	// Overwrite T-PDU handler for supporting extension header containing QoS parameters
	userPlaneConnection.AddHandler(gtpMsg.MsgTypeTPDU, handler.HandleQoSTPDU)

	return userPlaneConnection, remoteUDPAddr, nil
}
