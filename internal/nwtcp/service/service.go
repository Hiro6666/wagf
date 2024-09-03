package service

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/wagf/internal/logger"
	"github.com/free5gc/wagf/internal/ngap/message"
	"github.com/free5gc/wagf/pkg/context"
)

var nwtcpLog *logrus.Entry

func init() {
	nwtcpLog = logger.NWtCPLog
}

// Run setup wagf NAS for UE to forward NAS message
// to AMF
func Run() error {
	// wagf context
	wagfSelf := context.WAGFSelf()
	tcpAddr := fmt.Sprintf("%s:%d", wagfSelf.IPSecGatewayAddress, wagfSelf.TCPPort)

	tcpListener, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		nwtcpLog.Errorf("Listen TCP address failed: %+v", err)
		return errors.New("Listen failed")
	}

	nwtcpLog.Tracef("Successfully listen %+v", tcpAddr)

	go listenAndServe(tcpListener)

	return nil
}

// listenAndServe handle TCP listener and accept incoming
// requests. It also stores accepted connection into UE
// context, and finally, call serveConn() to serve the messages
// received from the connection.
func listenAndServe(tcpListener net.Listener) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.NWtCPLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		err := tcpListener.Close()
		if err != nil {
			nwtcpLog.Errorf("Error closing tcpListener: %+v", err)
		}
	}()

	for {
		connection, err := tcpListener.Accept()
		if err != nil {
			nwtcpLog.Error("TCP server accept failed. Close the listener...")
			return
		}

		nwtcpLog.Tracef("Accepted one UE from %+v", connection.RemoteAddr())

		// Find UE context and store this connection in to it, then check if
		// there is any cached NAS message for this UE. If yes, send to it.
		wagfSelf := context.WAGFSelf()

		ueIP := strings.Split(connection.RemoteAddr().String(), ":")[0]
		ue, ok := wagfSelf.AllocatedUEIPAddressLoad(ueIP)
		if !ok {
			nwtcpLog.Errorf("UE context not found for peer %+v", ueIP)
			continue
		}

		// Store connection
		ue.TCPConnection = connection

		if ue.TemporaryCachedNASMessage != nil {
			// Send to UE
			if n, err := connection.Write(ue.TemporaryCachedNASMessage); err != nil {
				nwtcpLog.Errorf("Writing via IPSec signalling SA failed: %+v", err)
			} else {
				nwtcpLog.Trace("Forward NWt <- N2")
				nwtcpLog.Tracef("Wrote %d bytes", n)
			}
			// Clean the cached message
			ue.TemporaryCachedNASMessage = nil
		}

		go serveConn(ue, connection)
	}
}

func decapNasMsgFromEnvelope(envelop []byte) []byte {
	// According to TS 24.502 8.2.4,
	// in order to transport a NAS message over the non-3GPP access between the UE and the wagf,
	// the NAS message shall be framed in a NAS message envelope as defined in subclause 9.4.
	// According to TS 24.502 9.4,
	// a NAS message envelope = Length | NAS Message

	// Get NAS Message Length
	nasLen := binary.BigEndian.Uint16(envelop[:2])
	nasMsg := make([]byte, nasLen)
	copy(nasMsg, envelop[2:2+nasLen])

	return nasMsg
}

// serveConn handle accepted TCP connection. It reads NAS packets
// from the connection and call forward() to forward NAS messages
// to AMF
func serveConn(ue *context.WAGFUe, connection net.Conn) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.NWtCPLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		err := connection.Close()
		if err != nil {
			nwtcpLog.Errorf("Error closing connection: %+v", err)
		}
	}()

	data := make([]byte, 65535)
	for {
		n, err := connection.Read(data)
		if err != nil {
			if err.Error() == "EOF" {
				nwtcpLog.Warn("Connection close by peer")
				ue.TCPConnection = nil
				return
			} else {
				nwtcpLog.Errorf("Read TCP connection failed: %+v", err)
			}
		}
		nwtcpLog.Tracef("Get NAS PDU from UE:\nNAS length: %d\nNAS content:\n%s", n, hex.Dump(data[:n]))

		// Decap Nas envelope
		forwardData := decapNasMsgFromEnvelope(data)

		go forward(ue, forwardData)
	}
}

// forward forwards NAS messages sent from UE to the
// associated AMF
func forward(ue *context.WAGFUe, packet []byte) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.NWtCPLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	nwtcpLog.Trace("Forward NWt -> N2")
	message.SendUplinkNASTransport(ue.AMF, ue, packet)
}
