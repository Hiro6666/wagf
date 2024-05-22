package handler

import (
	"bytes"
	// "encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/aper"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/wagf/internal/logger"
	ngap_message "github.com/free5gc/wagf/internal/ngap/message"
	"github.com/free5gc/wagf/pkg/context"
	radius_message "github.com/free5gc/wagf/pkg/radius/message"

	// "github.com/free5gc/util/ueauth"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
	gmm_message "github.com/free5gc/wagf/internal/gmm/message"
	"github.com/free5gc/wagf/pkg/factoryN5CW"
)

// Log
var radiusLog *logrus.Entry

func init() {
	radiusLog = logger.RadiusLog
}

// Radius state
const (
	RegistrationRequest = iota
	Authentication
	AuthenticationVerify
)

func HandleRadiusAccessRequest(udpConn *net.UDPConn, wagfAddr, ueAddr *net.UDPAddr,
	message *radius_message.RadiusMessage) {
	radiusLog.Infoln("Handle Radius Access Request")
	responseRadiusMessage := new(radius_message.RadiusMessage)
	var responseRadiusPayload radius_message.RadiusPayloadContainer

	wagfSelf := context.WAGFSelf()

	// var userName string
	var callingStationId string
	var calledStationId string
	var eapMessage []byte
	var requestMessageAuthenticator []byte
	var twapId uint64
	var err error
	var nai string
	for i, radiusPayload := range message.Payloads {
		switch radiusPayload.Type {
		// RFC 4282 Clause 2.2: NAI is transmitted in username
		case radius_message.TypeUserName:
			nai = string(radiusPayload.Val)
		case radius_message.TypeCallingStationId:
			callingStationId = string(radiusPayload.Val)
		case radius_message.TypeEAPMessage:
			fmt.Println("my radius_message.TypeEAPMessage", radiusPayload.Val)
			eapMessage = radiusPayload.Val
		case radius_message.TypeCalledStationId:
			calledStationId = string(radiusPayload.Val)
			calledStationId = strings.ReplaceAll(calledStationId[:17], "-", "")
			twapId, err = strconv.ParseUint(calledStationId, 16, 64)
			if err != nil {
				radiusLog.Errorln("Request Message CalledStationId error", err)
				return
			}
		case radius_message.TypeMessageAuthenticator:
			requestMessageAuthenticator = radiusPayload.Val
			radiusLog.Debugln("Message Authenticator:\n", hex.Dump(requestMessageAuthenticator))

			message.Payloads[i].Val = make([]byte, 16)
			exRequestMessageAuthenticator := GetMessageAuthenticator(message)
			radiusLog.Debugln("expected authenticator:\n", hex.Dump(exRequestMessageAuthenticator))
			if !bytes.Equal(requestMessageAuthenticator, exRequestMessageAuthenticator) {
				radiusLog.Errorln("Request Message Authenticator error")
				return
			}
		}
	}

	var session *context.RadiusSession
	session, ok := wagfSelf.RadiusSessionPoolLoad(callingStationId)
	if !ok {
		session = wagfSelf.NewRadiusSession(callingStationId)
	}

	switch session.State {
	case RegistrationRequest:
		// TS 23.502 2c. AAA Request NAI
		radiusLog.Infoln("Handle AAA NAI for registration to AMF")

		// AMF selection
		// TODO: ref. TS 23003 Clause 28.7.8: 5G-GUTI type: use that to select AMF
		// Else choose from default value
		// if strings.HasPrefix(nai, "tmsi")
		guami := make([]byte, 6)
		// wagfSelf.N5CWConfig = factoryN5CW.N5cwConfig
		amfID, err := wagfSelf.N5CWConfig.GetAMFID()
		if err != nil {
			radiusLog.Fatalf("GetAMFID: %+v", err)
		}
		copy(guami[:3], wagfSelf.N5CWConfig.BuildPLMN())
		copy(guami[3:], amfID)
		guamiField := make([]byte, 1)
		guamiField = append(guamiField, guami...)
		ngapGUAMI := new(ngapType.GUAMI)
		err = aper.UnmarshalWithParams(guamiField, ngapGUAMI, "valueExt")
		if err != nil {
			radiusLog.Errorf("APER unmarshal with parameter failed: %+v", err)
		}
		// PLMN = MCC + MNC
		ngapPLMN := new(ngapType.PLMNIdentity)
		PLMNField := make([]byte, 1)
		PLMNField = append(PLMNField, wagfSelf.N5CWConfig.BuildPLMN()...)
		err = aper.UnmarshalWithParams(PLMNField, ngapPLMN, "valueExt")
		if err != nil {
			radiusLog.Errorf("APER unmarshal with parameter failed: %v", err)
		}

		selectedAMF := wagfSelf.AMFSelection(ngapGUAMI, ngapPLMN)
		if selectedAMF == nil {
			radiusLog.Warn("No avalible AMF for this UE")

			// Send EAP failure
			// Build Radius message
			responseRadiusMessage.BuildRadiusHeader(radius_message.AccessChallenge, message.PktID, message.Auth)
			responseRadiusMessage.Payloads.Reset()

			// EAP
			identifier, err := GenerateRandomUint8()
			if err != nil {
				radiusLog.Errorf("Generate random uint8 failed: %+v", err)
				return
			}
			responseRadiusPayload.BuildEAPfailure(identifier)

			if requestMessageAuthenticator != nil {
				tmpRadiusMessage := *responseRadiusMessage
				payload := new(radius_message.RadiusPayload)
				payload.Type = radius_message.TypeMessageAuthenticator
				payload.Length = uint8(18)
				payload.Val = make([]byte, 16)

				tmpResponseRadiusPayload := append(responseRadiusPayload, *payload)
				tmpRadiusMessage.Payloads = tmpResponseRadiusPayload

				payload.Val = GetMessageAuthenticator(&tmpRadiusMessage)
				responseRadiusPayload = append(responseRadiusPayload, *payload)
			}
			responseRadiusMessage.Payloads = responseRadiusPayload

			// Send Radius message to UE
			SendRadiusMessageToUE(udpConn, wagfAddr, ueAddr, responseRadiusMessage)
			return
		}
		radiusLog.Infof("Selected AMF Name: %s", selectedAMF.AMFName.Value)

		// Create UE context
		ue := wagfSelf.NewWagfUe()

		// Relative context
		session.ThisUE = ue
		session.Auth = message.Auth
		session.PktId = message.PktID
		ue.RadiusSession = session
		ue.AMF = selectedAMF
		radiusLog.Infof("nai Name: %s", nai)
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
		ue.TWAPID = twapId
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

	case Authentication:
		radiusLog.Infoln("Handle AAA TWAP")
		eap := new(radius_message.EAP)
		eap.Unmarshal(eapMessage)
		if eap != nil {
			if eap.Code != radius_message.EAPCodeResponse {
				radiusLog.Error("[EAP] Received an EAP payload with code other than response. Drop the payload.")
				return
			}

			eapTypeData := eap.EAPTypeData[0]
			// var eapAKAPrime *radius_message.EAPAKAPrime

			switch eapTypeData.Type() {
			case radius_message.EAPTypeEAPAKAPrime:
				// eapAKAPrime = eapTypeData.(*radius_message.EAPAKAPrime)
				break
			default:
				radiusLog.Errorf("[EAP] Received EAP packet with type other than EAP AKA' type: %d", eapTypeData.Type())
				return
			}

			session.Auth = message.Auth
			session.PktId = message.PktID
			ue := session.ThisUE
			amf := ue.AMF

			ue.RadiusConnection = &context.UDPSocketInfo{
				Conn:     udpConn,
				WAGFAddr: wagfAddr,
				UEAddr:   ueAddr,
			}

			pdu := gmm_message.GetAuthenticationResponse(eapMessage)
			// Send Uplink NAS Transport
			ngap_message.SendUplinkNASTransport(amf, ue, pdu)
		} else {
			radiusLog.Error("EAP is nil")
		}
		// case AuthenticationVerify:
		// radiusLog.Infoln("Handle ")
		// identifier := eapMessage[1]
		// responseRadiusMessage.BuildRadiusHeader(radius_message.AccessAccept, message.PktID, message.Auth)
		// responseRadiusPayload.BuildEAPSuccess(identifier)

		// // Derivate Ktwap
		// thisUE := session.ThisUE
		// p0 := []byte{0x2}
		// thisUE.Ktwap, _ = ueauth.GetKDFValue(thisUE.Kwagf, ueauth.FC_FOR_KTIPSEC_KTWAP_DERIVATION, p0, ueauth.KDFLen(p0))
		// salt, _ := GenerateSalt()

		// mppeRecvKey, _ := EncryptMppeKey(thisUE.Ktwap, []byte(wagfSelf.RadiusSecret), message.Auth, salt)
		// vendorSpecificData := make([]byte, 2)
		// binary.BigEndian.PutUint16(vendorSpecificData, salt)
		// vendorSpecificData = append(vendorSpecificData, mppeRecvKey...)

		// responseRadiusPayload.BuildMicrosoftVendorSpecific(0x11, vendorSpecificData)
		// responseRadiusPayload.BuildMicrosoftVendorSpecific(0x10, vendorSpecificData)
		// responseRadiusPayload.BuildTLVPayload(1, []byte(thisUE.UserName))

		// if requestMessageAuthenticator != nil {
		// 	tmpRadiusMessage := *responseRadiusMessage
		// 	payload := new(radius_message.RadiusPayload)
		// 	payload.Type = radius_message.TypeMessageAuthenticator
		// 	payload.Length = uint8(18)
		// 	payload.Val = make([]byte, 16)

		// 	tmpResponseRadiusPayload := append(responseRadiusPayload, *payload)
		// 	tmpRadiusMessage.Payloads = tmpResponseRadiusPayload

		// 	payload.Val = GetMessageAuthenticator(&tmpRadiusMessage)
		// 	responseRadiusPayload = append(responseRadiusPayload, *payload)
		// }
		// responseRadiusMessage.Payloads = responseRadiusPayload
		// SendRadiusMessageToUE(udpConn, wagfAddr, ueAddr, responseRadiusMessage)
	}
}

func buildSUCI(plmn []byte, routingIndicator []byte, protectionSchemeId byte, HomeNetworkPublickeyId byte, msin []byte) []byte {
	var suci []byte
	fmt.Println("plmn: ", plmn)
	fmt.Println("routingIndicator: ", routingIndicator)
	fmt.Println("protectionSchemeId: ", protectionSchemeId)
	fmt.Println("HomeNetworkPublickeyId: ", HomeNetworkPublickeyId)
	fmt.Println("msin: ", msin)
	suci = append(suci, 0x01) // SUCI type
	suci = append(suci, plmn...)
	suci = append(suci, routingIndicator...)
	suci = append(suci, protectionSchemeId)
	suci = append(suci, HomeNetworkPublickeyId)
	suci = append(suci, msin...)

	return suci
}
