package service

import (
	"errors"
	"fmt"
	"net"
	"runtime/debug"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/wagf/internal/logger"
	// "github.com/free5gc/wagf/pkg/context"
	"github.com/free5gc/wagf/pkg/dhcp"
)

var dhcpLog *logrus.Entry

func init() {
	//  init logger
	dhcpLog = logger.DHCPLog
}

func Run() error {
	// Resolve UDP addresses
	// ip := context.WAGFSelf().DHCPBindAddress
	ip := "0.0.0.0"
	fmt.Println("DHCPBindAddress: ", ip)
	udpAddrPort67, err := net.ResolveUDPAddr("udp", ip+":67")
	if err != nil {
		dhcpLog.Errorf("Resolve UDP address failed: %+v", err)
		return errors.New("DHCP service run failed")
	}

	// Listen and serve
	// var errChan chan error

	// Port 67
	errChan := make(chan error)
	go listenAndServe(udpAddrPort67, errChan)
	if err, ok := <-errChan; ok {
		dhcpLog.Errorln(err)
		return errors.New("DHCP service run failed")
	}

	return nil
}

func listenAndServe(localAddr *net.UDPAddr, errChan chan<- error) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.IKELog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	// // listen UDP
	// listener, err := net.ListenUDP("udp", localAddr)
	// if err != nil {
	// 	dhcpLog.Errorf("Listen UDP failed: %+v", err)
	// 	errChan <- errors.New("listenAndServe failed")
	// 	return
	// }

	close(errChan)

	// For listening on specific interface
	listener, err := NewIPv4UDPConn("enp0s8", localAddr)
	if err != nil {
		dhcpLog.Errorf("NewIPv4UDPConn failed: %+v", err)
		return
	}

	data := make([]byte, 65535)

	// inifnite loop to receive UDP data
	for {
		fmt.Println("I'm starting to receive DHCP UDP data...")
		n, remoteAddr, err := listener.ReadFrom(data)
		if err != nil {
			dhcpLog.Errorf("ReadFromUDP failed: %+v", err)
			continue
		}
		fmt.Println("I received DHCP UDP data ...")

		forwardData := make([]byte, n)
		copy(forwardData, data[:n])

		go dhcp.Dispatch(listener, localAddr, &remoteAddr, forwardData)
	}
}
