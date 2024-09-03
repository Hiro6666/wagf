package service

import (
	"errors"
	"net"
	"runtime/debug"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/wagf/internal/logger"
	"github.com/free5gc/wagf/pkg/context"
	"github.com/free5gc/wagf/pkg/radius"
)

var radiusLog *logrus.Entry

func init() {
	// init logger
	radiusLog = logger.RadiusLog
}

func Run() error {
	// Resolve UDP addresses
	ip := context.WAGFSelf().RadiusBindAddress
	udpAddrPort1812, err := net.ResolveUDPAddr("udp", ip+":1812")
	if err != nil {
		radiusLog.Errorf("Resolve UDP address failed: %+v", err)
		return errors.New("Radius service run failed")
	}

	// Listen and serve
	var errChan chan error

	// Port 1812
	errChan = make(chan error) // cap is 0
	go listenAndServe(udpAddrPort1812, errChan)
	if err, ok := <-errChan; ok {
		radiusLog.Errorln(err)
		return errors.New("Radius service run failed")
	}

	return nil
}

func listenAndServe(localAddr *net.UDPAddr, errChan chan<- error) {
	radiusLog.Infof("Radius packet received")
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.RadiusLog.Fatalf(" panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	listener, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		radiusLog.Errorf("Listen UDP failed: %+v", err)
		errChan <- errors.New("listenAndServe failed")
		return
	}

	close(errChan)

	data := make([]byte, 65535)

	for {
		// receive data from AP
		n, remoteAddr, err := listener.ReadFromUDP(data)
		if err != nil {
			radiusLog.Errorf("ReadFromUDP failed: %+v", err)
			continue
		}

		forwardData := make([]byte, n)
		copy(forwardData, data[:n])

		go radius.Dispatch(listener, localAddr, remoteAddr, forwardData)
	}
}
