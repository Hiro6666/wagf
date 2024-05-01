package handler

import (
	"fmt"
	"net"
	"strconv"
	"time"
	"github.com/sirupsen/logrus"
	

	"github.com/free5gc/wagf/internal/logger"
	dhcpv4msg "github.com/free5gc/wagf/pkg/dhcp/message"
	wagfContext "github.com/free5gc/wagf/pkg/context"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/wagf/pkg/dhcp/packet/ngapPacket"
	"github.com/free5gc/wagf/pkg/dhcp/packet/nasPacket"
	// "github.com/vishvananda/netlink"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	ngap_message "github.com/free5gc/wagf/internal/ngap/message"

)

// Log
var dhcpLog *logrus.Entry

func init() {
	dhcpLog = logger.DHCPLog
}


func HandleDHCPDiscover(udpConn *net.UDPConn, wagfAddr, ueAddr *net.UDPAddr, message *dhcpv4msg.DHCPv4) {
	reply, err := dhcpv4msg.NewReplyFromRequest(message)
	if err != nil {
		logger.DHCPLog.Fatalf("NewReplyFromRequest failed: %v", err)
		return
	}
	wagfSelf := wagfContext.WAGFSelf()
	// var ifaces []netlink.Link

	// Build S-NSSA
	sst, err := strconv.ParseInt(wagfSelf.N5CWInfo.SmPolicy[0].SNSSAI.SST, 16, 0)
	if err != nil {
		logger.DHCPLog.Fatalf("Parse SST Fail:%+v", err)
		return
	}

	sNssai := models.Snssai{
		Sst: int32(sst),
		Sd:  wagfSelf.N5CWInfo.SmPolicy[0].SNSSAI.SD,
	}

	// PDU session establishment request
	// TS 24.501 9.11.3.47.1 Request type
	var pduSessionId uint8 = 5
	wagfUe, ok := wagfSelf.UePoolLoad(0) // Fixme: hard-patch UePoolLoad RanUENGAPID
	if !ok {
		dhcpLog.Errorf("Unknown local UE NGAP ID. RanUENGAPID: %d", 0)
		// TODO: build cause and handle error
		// Cause: Unknown local UE NGAP ID
		return
	} 

	fmt.Println("wagfUe: ", wagfUe)
	fmt.Println("wagfUe.ULCount: ", wagfUe.ULCount)
	fmt.Println("wagfUe.KnasEnc: ", wagfUe.KnasEnc)
	fmt.Println("wagfUe.Guami: ", wagfUe.Guami)
	fmt.Println("wagfUe.CipheringAlg: ", wagfUe.CipheringAlg)

	pdu := nasPacket.GetUlNasTransport_PduSessionEstablishmentRequest(pduSessionId, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	fmt.Println("pdu bytes: ", pdu)
	pdu, err = ngapPacket.EncodeNasPduInEnvelopeWithSecurity(wagfUe, pdu, nas.SecurityHeaderTypeIntegrityProtected, true, false)
	fmt.Println("pdu encode bytes: ", pdu)
	// pdu = pdu[2:]
	if err != nil {
		logger.DHCPLog.Fatalf("Encode NAS PDU In Envelope Fail:%+v", err)
		return
	}
	ngap_message.SendUplinkNASTransport(wagfUe.AMF, wagfUe, pdu)

	if _, err = wagfUe.AMF.SCTPConn.Write(pdu); err != nil {
		logger.DHCPLog.Fatalf("Send NAS Message Fail:%+v", err)
		return 
	}

	// buffer := make([]byte, 65535)

	dhcpLog.Warn("Waiting for AMF reply")
	reply.YourIPAddr = net.IPv4(10, 60, 0, 1)
	reply.UpdateOption(dhcpv4msg.OptMessageType(dhcpv4msg.MessageTypeOffer))
	reply.UpdateOption(dhcpv4msg.OptSubnetMask(net.IPMask{255, 255, 255, 0}))
	reply.UpdateOption(dhcpv4msg.OptIPAddressLeaseTime(600 * time.Second))
	reply.UpdateOption(dhcpv4msg.OptServerIdentifier(net.IPv4(10, 60, 0, 254)))
	MsgToByte := reply.ToBytes()
	SendDHCPMessageToUE(udpConn, wagfAddr, ueAddr, MsgToByte)
}

func HandleDHCPRequest(udpConn *net.UDPConn, wagfAddr, ueAddr *net.UDPAddr, message *dhcpv4msg.DHCPv4) {
	reply, err := dhcpv4msg.NewReplyFromRequest(message)
	if err != nil {
		logger.DHCPLog.Fatalf("NewReplyFromRequest failed: %v", err)
		return
	}

	reply.YourIPAddr = net.IPv4(10, 60, 0, 1)
	reply.UpdateOption(dhcpv4msg.OptMessageType(dhcpv4msg.MessageTypeAck))
	reply.UpdateOption(dhcpv4msg.OptSubnetMask(net.IPMask{255, 255, 255, 0}))
	reply.UpdateOption(dhcpv4msg.OptIPAddressLeaseTime(600 * time.Second))
	reply.UpdateOption(dhcpv4msg.OptServerIdentifier(net.IPv4(10, 60, 0, 254)))
	MsgToByte := reply.ToBytes()
	SendDHCPMessageToUE(udpConn, wagfAddr, ueAddr, MsgToByte)
}

// func pduSessionEstablishmentRequest(
// 	pduSessionId uint8,
// 	ue *wagfContext.WAGFUe,
// 	n3Info *context.N3IWFUe,
// 	ikeSA *context.IKESecurityAssociation,
// 	ikeConn *net.UDPConn,
// 	nasConn *net.TCPConn) ([]netlink.Link, error) {

// 	var ifaces []netlink.Link
// 	wagfSelf := wagfContext.WAGFSelf()

// 	// Build S-NSSA
// 	sst, err := strconv.ParseInt(wagfSelf.N5CWInfo.SmPolicy[0].SNSSAI.SST, 16, 0)
// 	if err != nil {
// 		return ifaces, fmt.Errorf("Parse SST Fail:%+v", err)
// 	}

// 	sNssai := models.Snssai{
// 		Sst: int32(sst),
// 		Sd:  wagfSelf.N5CWInfo.SmPolicy[0].SNSSAI.SD,
// 	}

// 	// PDU session establishment request
// 	// TS 24.501 9.11.3.47.1 Request type
// 	pdu := nasPacket.GetUlNasTransport_PduSessionEstablishmentRequest(pduSessionId, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
// 	pdu, err = ngapPacket.EncodeNasPduInEnvelopeWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
// 	if err != nil {
// 		return ifaces, fmt.Errorf("Encode NAS PDU In Envelope Fail:%+v", err)
// 	}
// 	if _, err = nasConn.Write(pdu); err != nil {
// 		return ifaces, fmt.Errorf("Send NAS Message Fail:%+v", err)
// 	}

// 	// buffer := make([]byte, 65535)

// 	dhcpLog.Warn("Waiting for AMF reply")

// 	// // Receive AMF reply
// 	// n, _, err := ikeConn.ReadFromUDP(buffer)
// 	// if err != nil {
// 	// 	return ifaces, fmt.Errorf("Read IKE Message Fail:%+v", err)
// 	// }

// 	// ikeMessage := new(message.IKEMessage)
// 	// ikeMessage.Payloads.Reset()
// 	// err = ikeMessage.Decode(buffer[:n])
// 	// if err != nil {
// 	// 	return ifaces, fmt.Errorf("Decode IKE Message Fail:%+v", err)
// 	// }
// 	// dhcpLog.Infof("IKE message exchange type: %d", ikeMessage.ExchangeType)
// 	// dhcpLog.Infof("IKE message ID: %d", ikeMessage.MessageID)

// 	// encryptedPayload, ok := ikeMessage.Payloads[0].(*message.Encrypted)
// 	// if !ok {
// 	// 	return ifaces, errors.New("Received pakcet is not and encrypted payload")
// 	// }
// 	// decryptedIKEPayload, err := decryptProcedure(ikeSA, ikeMessage, encryptedPayload)
// 	// if err != nil {
// 	// 	return ifaces, fmt.Errorf("Decrypt IKE Message Fail:%+v", err)
// 	// }

// 	// var qoSInfo *PDUQoSInfo

// 	// var responseSecurityAssociation *message.SecurityAssociation
// 	// var responseTrafficSelectorInitiator *message.TrafficSelectorInitiator
// 	// var responseTrafficSelectorResponder *message.TrafficSelectorResponder
// 	// var outboundSPI uint32
// 	// var upIPAddr net.IP
// 	// for _, ikePayload := range decryptedIKEPayload {
// 	// 	switch ikePayload.Type() {
// 	// 	case message.TypeSA:
// 	// 		responseSecurityAssociation = ikePayload.(*message.SecurityAssociation)
// 	// 		outboundSPI = binary.BigEndian.Uint32(responseSecurityAssociation.Proposals[0].SPI)
// 	// 	case message.TypeTSi:
// 	// 		responseTrafficSelectorInitiator = ikePayload.(*message.TrafficSelectorInitiator)
// 	// 	case message.TypeTSr:
// 	// 		responseTrafficSelectorResponder = ikePayload.(*message.TrafficSelectorResponder)
// 	// 	case message.TypeN:
// 	// 		notification := ikePayload.(*message.Notification)
// 	// 		if notification.NotifyMessageType == message.Vendor3GPPNotifyType5G_QOS_INFO {
// 	// 			dhcpLog.Info("Received Qos Flow settings")
// 	// 			if info, err := parse5GQoSInfoNotify(notification); err == nil {
// 	// 				qoSInfo = info
// 	// 				dhcpLog.Infof("NotificationData:%+v", notification.NotificationData)
// 	// 				if qoSInfo.isDSCPSpecified {
// 	// 					dhcpLog.Infof("DSCP is specified but test not support")
// 	// 				}
// 	// 			} else {
// 	// 				dhcpLog.Infof("%+v", err)
// 	// 			}
// 	// 		}
// 	// 		if notification.NotifyMessageType == message.Vendor3GPPNotifyTypeUP_IP4_ADDRESS {
// 	// 			upIPAddr = notification.NotificationData[:4]
// 	// 			dhcpLog.Infof("UP IP Address: %+v\n", upIPAddr)
// 	// 		}
// 	// 	case message.TypeNiNr:
// 	// 		responseNonce := ikePayload.(*message.Nonce)
// 	// 		ikeSA.ConcatenatedNonce = responseNonce.NonceData
// 	// 	}
// 	// }

// 	// // IKE CREATE_CHILD_SA response
// 	// ikeMessage.Payloads.Reset()
// 	// ikeMessage.BuildIKEHeader(ikeMessage.InitiatorSPI, ikeMessage.ResponderSPI,
// 	// 	message.CREATE_CHILD_SA, message.ResponseBitCheck|message.InitiatorBitCheck,
// 	// 	n3Info.N3IWFIKESecurityAssociation.ResponderMessageID)

// 	// var ikePayload message.IKEPayloadContainer
// 	// ikePayload.Reset()

// 	// // SA
// 	// inboundSPI := generateSPI(n3Info)
// 	// responseSecurityAssociation.Proposals[0].SPI = inboundSPI
// 	// ikePayload = append(ikePayload, responseSecurityAssociation)

// 	// // TSi
// 	// ikePayload = append(ikePayload, responseTrafficSelectorInitiator)

// 	// // TSr
// 	// ikePayload = append(ikePayload, responseTrafficSelectorResponder)

// 	// // Nonce
// 	// localNonce := handler.GenerateRandomNumber().Bytes()
// 	// ikeSA.ConcatenatedNonce = append(ikeSA.ConcatenatedNonce, localNonce...)
// 	// ikePayload.BuildNonce(localNonce)

// 	// if err := encryptProcedure(ikeSA, ikePayload, ikeMessage); err != nil {
// 	// 	dhcpLog.Error(err)
// 	// 	return ifaces, err
// 	// }

// 	// // Send to N3IWF
// 	// ikeMessageData, err := ikeMessage.Encode()
// 	// if err != nil {
// 	// 	return ifaces, fmt.Errorf("Encode IKE Message Fail:%+v", err)
// 	// }

// 	// n3iwfUDPAddr, err := net.ResolveUDPAddr("udp", n3iwfInfo.IPSecIfaceAddr+":500")

// 	// if err != nil {
// 	// 	return ifaces, fmt.Errorf("Resolve N3IWF IPSec IP Addr Fail:%+v", err)
// 	// }

// 	// _, err = ikeConn.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
// 	// if err != nil {
// 	// 	dhcpLog.Error(err)
// 	// 	return ifaces, err
// 	// }

// 	// n3Info.CreateHalfChildSA(n3Info.N3IWFIKESecurityAssociation.ResponderMessageID, binary.BigEndian.Uint32(inboundSPI))
// 	// childSecurityAssociationContextUserPlane, err := n3Info.CompleteChildSA(
// 	// 	n3Info.N3IWFIKESecurityAssociation.ResponderMessageID, outboundSPI, responseSecurityAssociation)
// 	// if err != nil {
// 	// 	return ifaces, fmt.Errorf("Create child security association context failed: %+v", err)
// 	// }

// 	// err = parseIPAddressInformationToChildSecurityAssociation(
// 	// 	childSecurityAssociationContextUserPlane,
// 	// 	responseTrafficSelectorResponder.TrafficSelectors[0],
// 	// 	responseTrafficSelectorInitiator.TrafficSelectors[0])

// 	// if err != nil {
// 	// 	return ifaces, fmt.Errorf("Parse IP address to child security association failed: %+v", err)
// 	// }
// 	// // Select GRE traffic
// 	// childSecurityAssociationContextUserPlane.SelectedIPProtocol = unix.IPPROTO_GRE

// 	// if err := generateKeyForChildSA(ikeSA, childSecurityAssociationContextUserPlane); err != nil {
// 	// 	return ifaces, fmt.Errorf("Generate key for child SA failed: %+v", err)
// 	// }

// 	// // ====== Inbound ======
// 	// dhcpLog.Debugln("====== IPSec/Child SA for 3GPP UP Inbound =====")
// 	// dhcpLog.Debugf("[UE:%+v] <- [N3IWF:%+v]",
// 	// 	childSecurityAssociationContextUserPlane.LocalPublicIPAddr, childSecurityAssociationContextUserPlane.PeerPublicIPAddr)
// 	// dhcpLog.Debugf("IPSec SPI: 0x%016x", childSecurityAssociationContextUserPlane.InboundSPI)
// 	// dhcpLog.Debugf("IPSec Encryption Algorithm: %d", childSecurityAssociationContextUserPlane.EncryptionAlgorithm)
// 	// dhcpLog.Debugf("IPSec Encryption Key: 0x%x", childSecurityAssociationContextUserPlane.InitiatorToResponderEncryptionKey)
// 	// dhcpLog.Debugf("IPSec Integrity  Algorithm: %d", childSecurityAssociationContextUserPlane.IntegrityAlgorithm)
// 	// dhcpLog.Debugf("IPSec Integrity  Key: 0x%x", childSecurityAssociationContextUserPlane.InitiatorToResponderIntegrityKey)
// 	// // ====== Outbound ======
// 	// dhcpLog.Debugln("====== IPSec/Child SA for 3GPP UP Outbound =====")
// 	// dhcpLog.Debugf("[UE:%+v] -> [N3IWF:%+v]",
// 	// 	childSecurityAssociationContextUserPlane.LocalPublicIPAddr, childSecurityAssociationContextUserPlane.PeerPublicIPAddr)
// 	// dhcpLog.Debugf("IPSec SPI: 0x%016x", childSecurityAssociationContextUserPlane.OutboundSPI)
// 	// dhcpLog.Debugf("IPSec Encryption Algorithm: %d", childSecurityAssociationContextUserPlane.EncryptionAlgorithm)
// 	// dhcpLog.Debugf("IPSec Encryption Key: 0x%x", childSecurityAssociationContextUserPlane.ResponderToInitiatorEncryptionKey)
// 	// dhcpLog.Debugf("IPSec Integrity  Algorithm: %d", childSecurityAssociationContextUserPlane.IntegrityAlgorithm)
// 	// dhcpLog.Debugf("IPSec Integrity  Key: 0x%x", childSecurityAssociationContextUserPlane.ResponderToInitiatorIntegrityKey)
// 	// dhcpLog.Debugf("State function: encr: %d, auth: %d", childSecurityAssociationContextUserPlane.EncryptionAlgorithm, childSecurityAssociationContextUserPlane.IntegrityAlgorithm)

// 	// // Aplly XFRM rules
// 	// n3ueInfo.XfrmiId++
// 	// err = applyXFRMRule(false, n3ueInfo.XfrmiId, childSecurityAssociationContextUserPlane)

// 	// if err != nil {
// 	// 	dhcpLog.Errorf("Applying XFRM rules failed: %+v", err)
// 	// 	return ifaces, err
// 	// }

// 	// var linkIPSec netlink.Link

// 	// // Setup interface for ipsec
// 	// newXfrmiName := fmt.Sprintf("%s-%d", n3ueInfo.XfrmiName, n3ueInfo.XfrmiId)
// 	// if linkIPSec, err = setupIPsecXfrmi(newXfrmiName, n3ueInfo.IPSecIfaceName, n3ueInfo.XfrmiId, ueInnerAddr); err != nil {
// 	// 	return ifaces, fmt.Errorf("Setup XFRMi interface %s fail: %+v", newXfrmiName, err)
// 	// }

// 	// ifaces = append(ifaces, linkIPSec)

// 	// AppLog.Infof("Setup XFRM interface %s successfully", newXfrmiName)

// 	// var pduAddr net.IP

// 	// // Read NAS from N3IWF
// 	// if n, err := nasConn.Read(buffer); err != nil {
// 	// 	return ifaces, fmt.Errorf("Read NAS Message Fail:%+v", err)
// 	// } else {
// 	// 	nasMsg, err := nasPacket.DecodePDUSessionEstablishmentAccept(ue, n, buffer)
// 	// 	if err != nil {
// 	// 		NASLog.Errorf("DecodePDUSessionEstablishmentAccept Fail: %+v", err)
// 	// 	}
// 	// 	spew.Config.Indent = "\t"
// 	// 	nasStr := spew.Sdump(nasMsg)
// 	// 	NASLog.Trace("Dump DecodePDUSessionEstablishmentAccept:\n", nasStr)

// 	// 	pduAddr, err = nasPacket.GetPDUAddress(nasMsg.GsmMessage.PDUSessionEstablishmentAccept)
// 	// 	if err != nil {
// 	// 		NASLog.Errorf("GetPDUAddress Fail: %+v", err)
// 	// 	}

// 	// 	NASLog.Infof("PDU Address: %s", pduAddr.String())
// 	// }

// 	// var linkGRE netlink.Link

// 	// newGREName := fmt.Sprintf("%s-id-%d", n3ueInfo.GreIfaceName, n3ueInfo.XfrmiId)

// 	// if linkGRE, err = setupGreTunnel(newGREName, newXfrmiName, ueInnerAddr.IP, upIPAddr, pduAddr, qoSInfo); err != nil {
// 	// 	return ifaces, fmt.Errorf("Setup GRE tunnel %s Fail %+v", newGREName, err)
// 	// }

// 	// ifaces = append(ifaces, linkGRE)

// 	return ifaces, nil
// }

