package handler

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/aper"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
	gmm_message "github.com/free5gc/wagf/internal/gmm/message"
	"github.com/free5gc/wagf/internal/logger"
	ngap_message "github.com/free5gc/wagf/internal/ngap/message"
	"github.com/free5gc/wagf/pkg/context"
	dhcpv4msg "github.com/free5gc/wagf/pkg/dhcp/message"
	"github.com/free5gc/wagf/pkg/factoryN5CW"
	// "github.com/vishvananda/netlink"
)

// Log
var dhcpLog *logrus.Entry

func init() {
	dhcpLog = logger.DHCPLog
}

// SUPI represents the Subscriber Permanent Identifier
type SUPI struct {
	GLI   string
	MNC   string
	MCC   string
	Realm string
}

// NewSUPI creates a new SUPI instance
func NewSUPI(gli, mnc, mcc string) *SUPI {
	return &SUPI{
		GLI:   gli,
		MNC:   mnc,
		MCC:   mcc,
		Realm: fmt.Sprintf("5gc.mnc%s.mcc%s.3gppnetwork.org", mnc, mcc),
	}
}

// GenerateGLI generates a GLI based on the given parameters
func GenerateGLI(lineIDSource byte, circuitID string, remoteID string) (string, error) {
	if lineIDSource < 0x30 || lineIDSource > 0x39 {
		return "", fmt.Errorf("invalid Line ID Source, must be between 0x30 and 0x39")
	}

	var buffer bytes.Buffer

	// Append Line ID Source
	buffer.WriteByte(lineIDSource)

	// Append Circuit ID if present
	if len(circuitID) > 0 {
		circuitIDBytes, err := hex.DecodeString(circuitID)
		if err != nil {
			return "", fmt.Errorf("invalid Circuit ID, must be a hex string: %v", err)
		}
		buffer.WriteByte(0x01)                      // Circuit ID Indicator
		buffer.WriteByte(byte(len(circuitIDBytes))) // Length of Circuit ID
		buffer.Write(circuitIDBytes)
	}

	// Append Remote ID if present
	if len(remoteID) > 0 {
		remoteIDBytes, err := hex.DecodeString(remoteID)
		if err != nil {
			return "", fmt.Errorf("invalid Remote ID, must be a hex string: %v", err)
		}
		buffer.WriteByte(0x02)                     // Remote ID Indicator
		buffer.WriteByte(byte(len(remoteIDBytes))) // Length of Remote ID
		buffer.Write(remoteIDBytes)
	}

	// Convert buffer to hex string
	gli := hex.EncodeToString(buffer.Bytes())
	return gli, nil
}

func HandleDHCPDiscover(udpConn *net.UDPConn, wagfAddr, ueAddr *net.UDPAddr, message *dhcpv4msg.DHCPv4) {

	// Insert Relay Agent Information (Option 82), Agent Circuit ID (Sub-option 1) into DHCP message
	var CircuitID uint64 = 25
	agentCircuitID := dhcpv4msg.Option{
		Code:  dhcpv4msg.AgentCircuitIDSubOption,
		Value: &dhcpv4msg.SimpleOptionValue{Data: []byte(strconv.Itoa(int(CircuitID)))},
	}
	relayAgentInfoOption := dhcpv4msg.OptRelayAgentInfo(agentCircuitID)
	message.UpdateOption(relayAgentInfoOption)

	// Check for the options in the DHCP message
	fmt.Println(message.Options.String())

	// Step1: Send DHCP Discover message to AGF-CP
	// abandon, just for checking
	// messageBytes := message.ToBytes()
	// _, err := udpConn.WriteToUDP(messageBytes, ueAddr)
	// if err != nil {
	// 	fmt.Println("Error sending DHCP message:", err)
	// 	return
	// }

	// TODO: AGF will associate the SRC IPv4 Address of the first packet from the FN-RG with the configured or dynamically generated Line ID and generates the SUCI and SUPI.
	// Ref : BBF TR-456-2-0-1, clause 8.1.14, page 107
	// lineIDSource := 0x50
	// fmt.Println("lineIDSource:", lineIDSource)
	// circuitID := strconv.Itoa(int(CircuitID))
	// fmt.Println("circuitID:", circuitID)

	// remoteID := ""
	// gli, err := GenerateGLI(byte(lineIDSource), circuitID, remoteID)
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// 	return
	// }
	// fmt.Printf("====================\n")
	// gli = strings.TrimPrefix(gli, "0x")
	// fmt.Println("GLI:", gli)
	// nai := "type2.rid0.schid0.userid" + gli
	// fmt.Println("nai:", nai)

	// clientIDBytes := message.ClientIdentifier()
	// clientIDStr := string(clientIDBytes)
	// fmt.Println("Client ID as string:", clientIDStr)

	wagfSelf := context.WAGFSelf()

	var session *context.DHCPSession
	session, ok := wagfSelf.DHCPSessionPoolLoad(CircuitID)
	if !ok {
		session = wagfSelf.NewDHCPSession(CircuitID)
	}

	// Step2: Check registration state

	// TODO: get rm state to determine flow
	// rm_state := models.RmState_REGISTERED
	rm_state := models.RmState_DEREGISTERED
	switch rm_state {
	case models.RmState_DEREGISTERED:
		// TODO: 3a ~ 3d

		// 3a: store equipment identifier, line identification, TCI, and port identification metadata
		// Use client identifier as equipment identifier. Ref : BBF TR-456-2-0-1, clause 6.10, page 70
		// TODO: TCI
		ue := wagfSelf.NewWagfUe()
		ue.LineId = CircuitID
		ue.PortNumber = int32(wagfAddr.Port)
		// clientIDInt, err := strconv.Atoi(clientIDStr)
		// if err != nil {
		// 	fmt.Println("Error converting string to int:", err)
		// 	return
		// }
		// ue.EquipmentId = uint64(clientIDInt)

		// 3b: AMF selection
		guami := make([]byte, 6)
		// wagfSelf.N5CWConfig = factoryN5CW.N5cwConfig
		amfID, err := wagfSelf.N5CWConfig.GetAMFID()
		if err != nil {
			dhcpLog.Fatalf("GetAMFID: %+v", err)
		}
		copy(guami[:3], wagfSelf.N5CWConfig.BuildPLMN())
		copy(guami[3:], amfID)
		guamiField := make([]byte, 1)
		guamiField = append(guamiField, guami...)
		ngapGUAMI := new(ngapType.GUAMI)
		err = aper.UnmarshalWithParams(guamiField, ngapGUAMI, "valueExt")
		if err != nil {
			dhcpLog.Errorf("APER unmarshal with parameter failed: %+v", err)
		}
		// PLMN = MCC + MNC
		ngapPLMN := new(ngapType.PLMNIdentity)
		PLMNField := make([]byte, 1)
		PLMNField = append(PLMNField, wagfSelf.N5CWConfig.BuildPLMN()...)
		err = aper.UnmarshalWithParams(PLMNField, ngapPLMN, "valueExt")
		if err != nil {
			dhcpLog.Errorf("APER unmarshal with parameter failed: %v", err)
		}

		selectedAMF := wagfSelf.AMFSelection(ngapGUAMI, ngapPLMN)
		if selectedAMF == nil {
			dhcpLog.Warn("No avalible AMF for this UE")

			return
		}
		dhcpLog.Infof("Selected AMF Name: %s", selectedAMF.AMFName.Value)

		// Create UE context

		// Relative context
		session.ThisUE = ue
		ue.DHCPSession = session
		ue.AMF = selectedAMF

		// 3GPP TS 23.003, clause 28.16.5
		nai := "type0.rid1695.schid0.userid000000000006"
		// nai := "type2.rid0.schid0.userid000000000006"

		dhcpLog.Infof("hardcode nai Name: %s", nai)
		r := regexp.MustCompile(`type(\d)\.rid([0-9]+)\.schid0\.userid([0-9]+)`)
		reRes := r.FindStringSubmatch(nai)
		rid, _ := strconv.Atoi(reRes[2])
		ridByte, _ := hex.DecodeString(strconv.FormatInt(int64(rid), 16))
		var msinBytes []byte
		for i := 0; i < len(reRes[3]); i += 2 {
			msinBytes = append(msinBytes, 0x0)
			j := len(msinBytes) - 1
			if i+1 == len(reRes[3]) {
				msinBytes[j] = 0xf<<4 | (reRes[3][i] - '0')
			} else {
				msinBytes[j] = (reRes[3][i+1]-'0')<<4 | (reRes[3][i] - '0')
			}
		}
		suci := buildSUCI(wagfSelf.N5CWConfig.BuildPLMN(), ridByte, 0x00, 0x00, msinBytes)

		ue.UEIdentity = &nasType.MobileIdentity5GS{
			Len:    uint16(len(suci)),
			Buffer: suci,
		}

		ue.RadiusConnection = &context.UDPSocketInfo{
			Conn:     udpConn,
			WAGFAddr: wagfAddr,
			UEAddr:   ueAddr,
		}

		// Store some information in conext
		ue.IPAddrv4 = ueAddr.IP.To4().String()
		ue.PortNumber = int32(ueAddr.Port)
		ue.RRCEstablishmentCause = int16(nasMessage.RegistrationType5GSInitialRegistration)
		ue.UserName = nai

		// Build NAS
		ue.Supi = factoryN5CW.N5cwConfig.GetSUPI()
		ue.CipheringAlg = security.AlgCiphering128NEA0
		ue.IntegrityAlg = security.AlgIntegrity128NIA2
		ue.AnType = models.AccessType_NON_3_GPP_ACCESS
		registrationRequest := gmm_message.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
			*(ue.UEIdentity), nil, ue.GetUESecurityCapability(), nil, nil, nil)

		// Send Initial UE Message
		ngap_message.SendInitialUEMessage(selectedAMF, ue, registrationRequest)
	case models.RmState_REGISTERED:
		// if clientIDStr != "" {
		// fmt.Println("Found client identifier.")
		// device, found := wagfRegistedPool.GetByClientID(clientID)
		// if !found {
		// 	fmt.Println("FN-RG is not in REGISTERED pool.")
		// }
		// if macAddress != device.MAC {
		// 	// TODO: If the gleaned information identifying the FN-RG is different than that recorded for the current registration,
		// 	// 		 the AGF interprets this as an equipment change and executes the AGF-CP initiated FN-RG Deregistration Procedure
		// 	fmt.Println("Do deregistration process, means the equipment is changed.")
		// }
		// }
		// TODO: get cm state to determine flow
		cm_state := models.CmState_IDLE
		switch cm_state {
		case models.CmState_IDLE:
			// TODO: 3A
		case models.CmState_CONNECTED:
			// TODO: 3i ~ 3ii
		}
	}

	// check client id to specific it is registed or not

	// check mac address to confirm the process

	// TODO: 如果識別 FN-RG 與目前的註冊記錄不同 這作為設備變更並執行 AGF-CP 發起的 FN-RG 註銷程序

	// classID := message.ClassIdentifier()
	// if classID != "" {
	// 	fmt.Printf("Class Identifier found: %x\n", classID)
	// }
	// fmt.Printf("Class Identifier: %x\n", classID)

	// reply, err := dhcpv4msg.NewReplyFromRequest(message)
	// if err != nil {
	// 	logger.DHCPLog.Fatalf("NewReplyFromRequest failed: %v", err)
	// 	return
	// }
	// wagfSelf := wagfContext.WAGFSelf()
	// // var ifaces []netlink.Link

	// // Build S-NSSA
	// sst, err := strconv.ParseInt(wagfSelf.N5CWInfo.SmPolicy[0].SNSSAI.SST, 16, 0)
	// if err != nil {
	// 	logger.DHCPLog.Fatalf("Parse SST Fail:%+v", err)
	// 	return
	// }

	// sNssai := models.Snssai{
	// 	Sst: int32(sst),
	// 	Sd:  wagfSelf.N5CWInfo.SmPolicy[0].SNSSAI.SD,
	// }

	// // PDU session establishment request
	// // TS 24.501 9.11.3.47.1 Request type
	// var pduSessionId uint8 = 5
	// wagfUe, ok := wagfSelf.UePoolLoad(0) // Fixme: hard-patch UePoolLoad RanUENGAPID
	// if !ok {
	// 	dhcpLog.Errorf("Unknown local UE NGAP ID. RanUENGAPID: %d", 0)
	// 	// TODO: build cause and handle error
	// 	// Cause: Unknown local UE NGAP ID
	// 	return
	// }

	// fmt.Println("wagfUe: ", wagfUe)
	// fmt.Println("wagfUe.ULCount: ", wagfUe.ULCount)
	// fmt.Println("wagfUe.KnasEnc: ", wagfUe.KnasEnc)
	// fmt.Println("wagfUe.Guami: ", wagfUe.Guami)
	// fmt.Println("wagfUe.CipheringAlg: ", wagfUe.CipheringAlg)

	// pdu := nasPacket.GetUlNasTransport_PduSessionEstablishmentRequest(pduSessionId, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	// fmt.Println("pdu bytes: ", pdu)
	// pdu, err = ngapPacket.EncodeNasPduInEnvelopeWithSecurity(wagfUe, pdu, nas.SecurityHeaderTypeIntegrityProtected, true, false)
	// fmt.Println("pdu encode bytes: ", pdu)
	// // pdu = pdu[2:]
	// if err != nil {
	// 	logger.DHCPLog.Fatalf("Encode NAS PDU In Envelope Fail:%+v", err)
	// 	return
	// }
	// ngap_message.SendUplinkNASTransport(wagfUe.AMF, wagfUe, pdu)

	// if _, err = wagfUe.AMF.SCTPConn.Write(pdu); err != nil {
	// 	logger.DHCPLog.Fatalf("Send NAS Message Fail:%+v", err)
	// 	return
	// }

	// // buffer := make([]byte, 65535)

	// dhcpLog.Warn("Waiting for AMF reply")
	// reply.YourIPAddr = net.IPv4(10, 60, 0, 1)
	// reply.UpdateOption(dhcpv4msg.OptMessageType(dhcpv4msg.MessageTypeOffer))
	// reply.UpdateOption(dhcpv4msg.OptSubnetMask(net.IPMask{255, 255, 255, 0}))
	// reply.UpdateOption(dhcpv4msg.OptIPAddressLeaseTime(600 * time.Second))
	// reply.UpdateOption(dhcpv4msg.OptServerIdentifier(net.IPv4(10, 60, 0, 254)))
	// MsgToByte := reply.ToBytes()
	// SendDHCPMessageToUE(udpConn, wagfAddr, ueAddr, MsgToByte)
}

func HandleDHCPRequest(udpConn *net.UDPConn, wagfAddr, ueAddr *net.UDPAddr, message *dhcpv4msg.DHCPv4) {
	reply, err := dhcpv4msg.NewReplyFromRequest(message)
	if err != nil {
		logger.DHCPLog.Fatalf("NewReplyFromRequest failed: %v", err)
		return
	}
	fmt.Println("HandleDHCPRequest")
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

func buildSUCI(plmn []byte, routingIndicator []byte, protectionSchemeId byte, HomeNetworkPublickeyId byte, msin []byte) []byte {
	var suci []byte
	suci = append(suci, 0x01) // SUCI type
	suci = append(suci, plmn...)
	suci = append(suci, routingIndicator...)
	suci = append(suci, protectionSchemeId)
	suci = append(suci, HomeNetworkPublickeyId)
	suci = append(suci, msin...)

	return suci
}
