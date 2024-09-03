package message

import (
	"encoding/binary"
	// "net"
	// "fmt"
	// "encoding/hex"
	"math/big"
	"net"
)

func (radiusMessage *RadiusMessage) BuildRadiusHeader(
	code uint8,
	pktID uint8,
	auth []byte) {
	radiusMessage.Code = code
	radiusMessage.PktID = pktID
	radiusMessage.Auth = auth
}

func (container *RadiusPayloadContainer) Reset() {
	*container = nil
}

func (container *RadiusPayloadContainer) BuildEAP(code uint8, identifier uint8) *EAP {
	eap := new(EAP)
	eap.Code = code
	eap.Identifier = identifier
	eapPayload, _ := eap.Marshal()

	payload := new(RadiusPayload)
	payload.Type = TypeEAPMessage
	payload.Val = eapPayload
	*container = append(*container, *payload)
	return eap
}

func (container *RadiusPayloadContainer) BuildEAPSuccess(identifier uint8) {
	eap := new(EAP)
	eap.Code = EAPCodeSuccess
	eap.Identifier = identifier
	eapPayload, _ := eap.Marshal()

	payload := new(RadiusPayload)
	payload.Type = TypeEAPMessage
	payload.Val = eapPayload

	*container = append(*container, *payload)
}

func (container *RadiusPayloadContainer) BuildEAPfailure(identifier uint8) {
	eap := new(EAP)
	eap.Code = EAPCodeFailure
	eap.Identifier = identifier
	eapPayload, _ := eap.Marshal()

	payload := new(RadiusPayload)
	payload.Type = TypeEAPMessage
	payload.Val = eapPayload
	*container = append(*container, *payload)
}

func (container *EAPTypeDataContainer) BuildEAPExpanded(vendorID uint32, vendorType uint32, vendorData []byte) {
	eapExpanded := new(EAPExpanded)
	eapExpanded.VendorID = vendorID
	eapExpanded.VendorType = vendorType
	eapExpanded.VendorData = append(eapExpanded.VendorData, vendorData...)
	*container = append(*container, eapExpanded)
}

func (container *EAPTypeDataContainer) BuildEAPAKAPrime(TypeData uint8, SubType uint8) {
	eapAKAPrime := new(EAPAKAPrime)
	eapAKAPrime.TypeData = TypeData
	eapAKAPrime.SubType = SubType
	*container = append(*container, eapAKAPrime)
}

func (container *RadiusPayloadContainer) BuildEAP5GStart(identifier uint8) {
	eap := new(EAP)
	eap.Code = EAPCodeRequest
	eap.Identifier = identifier
	eap.EAPTypeData.BuildEAPExpanded(VendorID3GPP, VendorTypeEAP5G, []byte{EAP5GType5GStart, EAP5GSpareValue})
	eapPayload, _ := eap.Marshal()

	payload := new(RadiusPayload)
	payload.Type = TypeEAPMessage
	payload.Val = eapPayload

	*container = append(*container, *payload)
}

func (container *RadiusPayloadContainer) BuildEAP5GNAS(identifier uint8, nasPDU []byte) {
	if len(nasPDU) == 0 {
		radiusLog.Error("BuildEAP5GNAS(): NASPDU is nil")
		return
	}

	header := make([]byte, 4)

	// Message ID
	header[0] = EAP5GType5GNAS
	// NASPDU length (2 octets)
	binary.BigEndian.PutUint16(header[2:4], uint16(len(nasPDU)))
	// vendorData := append(header, nasPDU...)

	eap := new(EAP)
	eap.Code = EAPCodeRequest
	eap.Identifier = identifier
	eap.EAPTypeData.BuildEAPAKAPrime(EAPTypeEAPAKAPrime, AKA_CHALLENGE_SUBTYPE)
	eapPayload, _ := eap.Marshal()

	payload := new(RadiusPayload)
	payload.Type = TypeEAPMessage
	payload.Val = eapPayload

	*container = append(*container, *payload)
}

func (container *RadiusPayloadContainer) BuildEAP5GNotification(identifier uint8, ip string) {
	ipInt := big.NewInt(0)
	ipv4ContactInfo := ipInt.SetBytes(net.ParseIP(ip).To4()).Uint64()
	anParameters := make([]byte, 6)
	// wagf IPv4 contace info
	anParameters[0] = 1
	// wagf IPv4 length
	anParameters[1] = 4
	binary.BigEndian.PutUint32(anParameters[2:6], uint32(ipv4ContactInfo))

	header := make([]byte, 4)
	// Message ID
	header[0] = EAP5GType5GNotification
	// AN-Parameter length (2 octets)
	binary.BigEndian.PutUint16(header[2:4], uint16(len(anParameters)))
	vendorData := append(header, anParameters...)

	eap := new(EAP)
	eap.Code = EAPCodeRequest
	eap.Identifier = identifier
	eap.EAPTypeData.BuildEAPExpanded(VendorID3GPP, VendorTypeEAP5G, vendorData)
	eapPayload, _ := eap.Marshal()

	payload := new(RadiusPayload)
	payload.Type = TypeEAPMessage
	payload.Val = eapPayload

	*container = append(*container, *payload)
}

func (container *RadiusPayloadContainer) BuildMicrosoftVendorSpecific(vendorType uint8, data []byte) {
	vendorSpecific := new(RadiusMicrosoftVendorSpecific)
	vendorSpecific.Type = vendorType
	vendorSpecific.String = append(vendorSpecific.String, data...)
	vendorSpecificPayload, _ := vendorSpecific.marshal()

	vendorID := make([]byte, 4)
	binary.BigEndian.PutUint32(vendorID, uint32(311))
	vendorSpecificPayload = append(vendorID, vendorSpecificPayload...)

	payload := new(RadiusPayload)
	payload.Type = TypeVendorSpecific
	payload.Val = vendorSpecificPayload

	*container = append(*container, *payload)
}

func (container *RadiusPayloadContainer) BuildTLVPayload(attType uint8, val []byte) {
	payload := new(RadiusPayload)
	payload.Type = attType
	payload.Val = val

	*container = append(*container, *payload)
}
