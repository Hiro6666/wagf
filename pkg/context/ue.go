package context

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	gtpv1 "github.com/wmnsk/go-gtp/gtpv1"

	"encoding/hex"
	"regexp"

	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/milenage"
	"github.com/free5gc/util/ueauth"
	ike_message "github.com/free5gc/wagf/pkg/ike/message"
	"golang.org/x/net/ipv4"
)

const (
	AmfUeNgapIdUnspecified int64 = 0xffffffffff
)

type RadiusSession struct {
	CallingStationID string
	State            uint8

	// UE context
	ThisUE *WAGFUe

	// RADIUS Info
	Auth  []byte
	PktId uint8
}

type DHCPSession struct {
	LineId uint64
	State  uint8

	// UE context
	ThisUE *WAGFUe
}

type WAGFUe struct {
	/* UE identity */
	RanUeNgapId      int64
	AmfUeNgapId      int64
	IPAddrv4         string
	IPAddrv6         string
	PortNumber       int32
	TWAPID           uint64
	MaskedIMEISV     *ngapType.MaskedIMEISV // TS 38.413 9.3.1.54
	Guti             string
	IPSecInnerIP     net.IP
	IPSecInnerIPAddr *net.IPAddr // Used to send UP packets to UE
	EquipmentId      uint64
	LineId           uint64

	/* Relative Context */
	AMF *WAGFAMF

	/* PDU Session */
	PduSessionList map[int64]*PDUSession // pduSessionId as key

	/* PDU Session Setup Temporary Data */
	TemporaryPDUSessionSetupData *PDUSessionSetupTemporaryData

	/* Temporary cached NAS message */
	// Used when NAS registration accept arrived before
	// UE setup NAS TCP connection with wagf, and
	// Forward pduSessionEstablishmentAccept to UE after
	// UE send CREATE_CHILD_SA response
	TemporaryCachedNASMessage []byte

	/* NAS TCP Connection Established */
	IsSMCRequest         bool
	IsInitialCtxRequest  bool
	IsRegistrationAccept bool

	/* Security */
	Kwagf                []uint8                          // 32 bytes (256 bits), value is from NGAP IE "Security Key"
	Ktwap                []uint8                          // 32 bytes (256 bits), value is computed from Kwagf
	Ktipsec              []uint8                          // 32 bytes (256 bits), value is computed from Kwagf
	SecurityCapabilities *ngapType.UESecurityCapabilities // TS 38.413 9.3.1.86
	// Security Capability
	CipheringAlg uint8
	IntegrityAlg uint8
	ULCount      security.Count
	DLCount      security.Count
	KnasEnc      [16]uint8
	KnasInt      [16]uint8
	Kamf         []uint8
	AnType       models.AccessType
	Supi         string
	EAPSuccessID uint8

	/* IKE Security Association */
	WAGFIKESecurityAssociation   *IKESecurityAssociation
	WAGFChildSecurityAssociation map[uint32]*ChildSecurityAssociation // inbound SPI as key
	SignallingIPsecSAEstablished bool

	// RADIUS Session
	RadiusSession *RadiusSession

	// DHCP Session
	DHCPSession *DHCPSession

	/* Temporary Mapping of two SPIs */
	// Exchange Message ID(including a SPI) and ChildSA(including a SPI)
	// Mapping of Message ID of exchange in IKE and Child SA when creating new child SA
	TemporaryExchangeMsgIDChildSAMapping map[uint32]*ChildSecurityAssociation // Message ID as a key

	/* NAS IKE Connection */
	IKEConnection *UDPSocketInfo
	/* NAS TCP Connection */
	TCPConnection net.Conn
	// RADIUS Connection
	RadiusConnection *UDPSocketInfo

	/* Others */
	Guami                            *ngapType.GUAMI
	IndexToRfsp                      int64
	Ambr                             *ngapType.UEAggregateMaximumBitRate
	AllowedNssai                     *ngapType.AllowedNSSAI
	RadioCapability                  *ngapType.UERadioCapability                // TODO: This is for RRC, can be deleted
	CoreNetworkAssistanceInformation *ngapType.CoreNetworkAssistanceInformation // TS 38.413 9.3.1.15
	IMSVoiceSupported                int32
	RRCEstablishmentCause            int16
	UserName                         string
	UEIdentity                       *nasType.MobileIdentity5GS
}

type PDUSession struct {
	Id                               int64 // PDU Session ID
	Type                             *ngapType.PDUSessionType
	Ambr                             *ngapType.PDUSessionAggregateMaximumBitRate
	Snssai                           ngapType.SNSSAI
	NetworkInstance                  *ngapType.NetworkInstance
	SecurityCipher                   bool
	SecurityIntegrity                bool
	MaximumIntegrityDataRateUplink   *ngapType.MaximumIntegrityProtectedDataRate
	MaximumIntegrityDataRateDownlink *ngapType.MaximumIntegrityProtectedDataRate
	GTPConnection                    *GTPConnectionInfo
	QFIList                          []uint8
	QosFlows                         map[int64]*QosFlow // QosFlowIdentifier as key
}

type PDUSessionSetupTemporaryData struct {
	// Slice of unactivated PDU session
	UnactivatedPDUSession []int64 // PDUSessionID as content
	// NGAPProcedureCode is used to identify which type of
	// response shall be used
	NGAPProcedureCode ngapType.ProcedureCode
	// PDU session setup list response
	SetupListCxtRes  *ngapType.PDUSessionResourceSetupListCxtRes
	FailedListCxtRes *ngapType.PDUSessionResourceFailedToSetupListCxtRes
	SetupListSURes   *ngapType.PDUSessionResourceSetupListSURes
	FailedListSURes  *ngapType.PDUSessionResourceFailedToSetupListSURes
}

type QosFlow struct {
	Identifier int64
	Parameters ngapType.QosFlowLevelQosParameters
}

type GTPConnectionInfo struct {
	UPFIPAddr           string
	UPFUDPAddr          net.Addr
	IncomingTEID        uint32
	OutgoingTEID        uint32
	UserPlaneConnection *gtpv1.UPlaneConn
}

type IKESecurityAssociation struct {
	// SPI
	RemoteSPI uint64
	LocalSPI  uint64

	// Message ID
	InitiatorMessageID uint32
	ResponderMessageID uint32

	// Transforms for IKE SA
	EncryptionAlgorithm    *ike_message.Transform
	PseudorandomFunction   *ike_message.Transform
	IntegrityAlgorithm     *ike_message.Transform
	DiffieHellmanGroup     *ike_message.Transform
	ExpandedSequenceNumber *ike_message.Transform

	// Used for key generating
	ConcatenatedNonce      []byte
	DiffieHellmanSharedKey []byte

	// Keys
	SK_d  []byte // used for child SA key deriving
	SK_ai []byte // used by initiator for integrity checking
	SK_ar []byte // used by responder for integrity checking
	SK_ei []byte // used by initiator for encrypting
	SK_er []byte // used by responder for encrypting
	SK_pi []byte // used by initiator for IKE authentication
	SK_pr []byte // used by responder for IKE authentication

	// State for IKE_AUTH
	State uint8

	// Temporary data stored for the use in later exchange
	InitiatorID              *ike_message.IdentificationInitiator
	InitiatorCertificate     *ike_message.Certificate
	IKEAuthResponseSA        *ike_message.SecurityAssociation
	TrafficSelectorInitiator *ike_message.TrafficSelectorInitiator
	TrafficSelectorResponder *ike_message.TrafficSelectorResponder
	LastEAPIdentifier        uint8

	// Authentication data
	ResponderSignedOctets []byte
	InitiatorSignedOctets []byte

	// NAT detection
	// If UEIsBehindNAT == true, wagf should enable NAT traversal and
	// TODO: should support dynamic updating network address (MOBIKE)
	UEIsBehindNAT bool
	// If WAGFIsBehindNAT == true, wagf should send UDP keepalive periodically
	WAGFIsBehindNAT bool

	// UE context
	ThisUE *WAGFUe
}

type ChildSecurityAssociation struct {
	// SPI
	InboundSPI  uint32 // wagf Specify
	OutboundSPI uint32 // Non-3GPP UE Specify

	// Associated XFRM interface
	XfrmIface netlink.Link

	// IP address
	PeerPublicIPAddr  net.IP
	LocalPublicIPAddr net.IP

	// Traffic selector
	SelectedIPProtocol    uint8
	TrafficSelectorLocal  net.IPNet
	TrafficSelectorRemote net.IPNet

	// Security
	EncryptionAlgorithm               uint16
	InitiatorToResponderEncryptionKey []byte
	ResponderToInitiatorEncryptionKey []byte
	IntegrityAlgorithm                uint16
	InitiatorToResponderIntegrityKey  []byte
	ResponderToInitiatorIntegrityKey  []byte
	ESN                               bool

	// Encapsulate
	EnableEncapsulate bool
	WAGFPort          int
	NATPort           int

	// PDU Session IDs associated with this child SA
	PDUSessionIds []int64

	// UE context
	ThisUE *WAGFUe
}

type UDPSocketInfo struct {
	Conn     *net.UDPConn
	WAGFAddr *net.UDPAddr
	UEAddr   *net.UDPAddr
}

func (ue *WAGFUe) init(ranUeNgapId int64) {
	ue.RanUeNgapId = ranUeNgapId
	ue.AmfUeNgapId = AmfUeNgapIdUnspecified
	ue.PduSessionList = make(map[int64]*PDUSession)
	ue.WAGFChildSecurityAssociation = make(map[uint32]*ChildSecurityAssociation)
	ue.TemporaryExchangeMsgIDChildSAMapping = make(map[uint32]*ChildSecurityAssociation)
}

func (ue *WAGFUe) Remove() {
	// remove from AMF context
	ue.DetachAMF()
	// remove from wagf context
	wagfSelf := WAGFSelf()
	wagfSelf.DeleteWagfUe(ue.RanUeNgapId)
	wagfSelf.DeleteIKESecurityAssociation(ue.WAGFIKESecurityAssociation.LocalSPI)
	wagfSelf.DeleteInternalUEIPAddr(ue.IPSecInnerIP.String())
	for _, pduSession := range ue.PduSessionList {
		wagfSelf.DeleteTEID(pduSession.GTPConnection.IncomingTEID)
	}
}

func (ue *WAGFUe) FindPDUSession(pduSessionID int64) *PDUSession {
	if pduSession, ok := ue.PduSessionList[pduSessionID]; ok {
		return pduSession
	} else {
		return nil
	}
}

func (ue *WAGFUe) CreatePDUSession(pduSessionID int64, snssai ngapType.SNSSAI) (*PDUSession, error) {
	if _, exists := ue.PduSessionList[pduSessionID]; exists {
		return nil, fmt.Errorf("PDU Session[ID:%d] is already exists", pduSessionID)
	}
	pduSession := &PDUSession{
		Id:       pduSessionID,
		Snssai:   snssai,
		QosFlows: make(map[int64]*QosFlow),
	}
	ue.PduSessionList[pduSessionID] = pduSession
	return pduSession, nil
}

// When wagf send CREATE_CHILD_SA request to N5CW, the inbound SPI of childSA will be only stored first until
// receive response and call CompleteChildSAWithProposal to fill the all data of childSA
func (ue *WAGFUe) CreateHalfChildSA(msgID, inboundSPI uint32, pduSessionID int64) {
	childSA := new(ChildSecurityAssociation)
	childSA.InboundSPI = inboundSPI
	childSA.PDUSessionIds = append(childSA.PDUSessionIds, pduSessionID)
	// Link UE context
	childSA.ThisUE = ue
	// Map Exchange Message ID and Child SA data until get paired response
	ue.TemporaryExchangeMsgIDChildSAMapping[msgID] = childSA
}

func (ue *WAGFUe) CompleteChildSA(msgID uint32, outboundSPI uint32,
	chosenSecurityAssociation *ike_message.SecurityAssociation) (*ChildSecurityAssociation, error) {
	childSA, ok := ue.TemporaryExchangeMsgIDChildSAMapping[msgID]

	if !ok {
		return nil, fmt.Errorf("There's not a half child SA created by the exchange with message ID %d.", msgID)
	}

	// Remove mapping of exchange msg ID and child SA
	delete(ue.TemporaryExchangeMsgIDChildSAMapping, msgID)

	if chosenSecurityAssociation == nil {
		return nil, errors.New("chosenSecurityAssociation is nil")
	}

	if len(chosenSecurityAssociation.Proposals) == 0 {
		return nil, errors.New("No proposal")
	}

	childSA.OutboundSPI = outboundSPI

	if len(chosenSecurityAssociation.Proposals[0].EncryptionAlgorithm) != 0 {
		childSA.EncryptionAlgorithm = chosenSecurityAssociation.Proposals[0].EncryptionAlgorithm[0].TransformID
	}
	if len(chosenSecurityAssociation.Proposals[0].IntegrityAlgorithm) != 0 {
		childSA.IntegrityAlgorithm = chosenSecurityAssociation.Proposals[0].IntegrityAlgorithm[0].TransformID
	}
	if len(chosenSecurityAssociation.Proposals[0].ExtendedSequenceNumbers) != 0 {
		if chosenSecurityAssociation.Proposals[0].ExtendedSequenceNumbers[0].TransformID == 0 {
			childSA.ESN = false
		} else {
			childSA.ESN = true
		}
	}

	// Record to UE context with inbound SPI as key
	ue.WAGFChildSecurityAssociation[childSA.InboundSPI] = childSA
	// Record to wagf context with inbound SPI as key
	wagfContext.ChildSA.Store(childSA.InboundSPI, childSA)

	return childSA, nil
}

func (ue *WAGFUe) AttachAMF(sctpAddr string) bool {
	if amf, ok := wagfContext.AMFPoolLoad(sctpAddr); ok {
		amf.WagfUeList[ue.RanUeNgapId] = ue
		ue.AMF = amf
		return true
	} else {
		return false
	}
}

func (ue *WAGFUe) DetachAMF() {
	if ue.AMF == nil {
		return
	}
	delete(ue.AMF.WagfUeList, ue.RanUeNgapId)
}

func CalculateIpv4HeaderChecksum(hdr *ipv4.Header) uint32 {
	var Checksum uint32
	Checksum += uint32((hdr.Version<<4|(20>>2&0x0f))<<8 | hdr.TOS)
	Checksum += uint32(hdr.TotalLen)
	Checksum += uint32(hdr.ID)
	Checksum += uint32((hdr.FragOff & 0x1fff) | (int(hdr.Flags) << 13))
	Checksum += uint32((hdr.TTL << 8) | (hdr.Protocol))

	src := hdr.Src.To4()
	Checksum += uint32(src[0])<<8 | uint32(src[1])
	Checksum += uint32(src[2])<<8 | uint32(src[3])
	dst := hdr.Dst.To4()
	Checksum += uint32(dst[0])<<8 | uint32(dst[1])
	Checksum += uint32(dst[2])<<8 | uint32(dst[3])
	return ^(Checksum&0xffff0000>>16 + Checksum&0xffff)
}

func (ue *WAGFUe) GetAuthSubscription() (authSubs models.AuthenticationSubscription) {
	var wagfSelf *WAGFContext = WAGFSelf()
	authSubs.PermanentKey = &models.PermanentKey{
		PermanentKeyValue: wagfSelf.N5CWInfo.Security.K,
	}
	authSubs.Opc = &models.Opc{
		OpcValue: wagfSelf.N5CWInfo.Security.OPC,
	}
	authSubs.Milenage = &models.Milenage{
		Op: &models.Op{
			OpValue: wagfSelf.N5CWInfo.Security.OP,
		},
	}
	authSubs.AuthenticationManagementField = wagfSelf.N5CWInfo.Security.AMF

	authSubs.SequenceNumber = wagfSelf.N5CWInfo.Security.SQN
	authSubs.AuthenticationMethod = models.AuthMethod_EAP_AKA_PRIME
	return
}

func (ue *WAGFUe) DeriveResEAPMessageAndSetKey(
	authSubs models.AuthenticationSubscription, eAPMessage []byte, rand []byte, snName string, autn []byte) []byte {

	sqn, err := hex.DecodeString(authSubs.SequenceNumber)
	if err != nil {
		fmt.Printf("DecodeString error: %+v", err)
	}

	amf, err := hex.DecodeString(authSubs.AuthenticationManagementField)
	if err != nil {
		fmt.Printf("DecodeString error: %+v", err)
	}

	// Run milenage
	macA, macS := make([]byte, 8), make([]byte, 8)
	ck, ik := make([]byte, 16), make([]byte, 16)
	res := make([]byte, 8)
	ak, akStar := make([]byte, 6), make([]byte, 6)

	opc := make([]byte, 16)
	_ = opc
	k, err := hex.DecodeString(authSubs.PermanentKey.PermanentKeyValue)
	if err != nil {
		fmt.Printf("DecodeString error: %+v", err)
	}

	if authSubs.Opc.OpcValue == "" {
		opStr := authSubs.Milenage.Op.OpValue
		var op []byte
		op, err = hex.DecodeString(opStr)
		if err != nil {
			fmt.Printf("DecodeString error: %+v", err)
		}

		opc, err = milenage.GenerateOPC(k, op)
		if err != nil {
			fmt.Printf("milenage GenerateOPC error: %+v", err)
		}
	} else {
		opc, err = hex.DecodeString(authSubs.Opc.OpcValue)
		if err != nil {
			fmt.Printf("DecodeString error: %+v", err)
		}
	}
	fmt.Println("in wagf ue k, opc, rand, amf", k, opc, rand, amf)
	// Generate MAC_A, MAC_S
	err = milenage.F1(opc, k, rand, sqn, amf, macA, macS)
	if err != nil {
		fmt.Printf("regexp Compile error: %+v", err)
	}

	// Generate RES, CK, IK, AK, AKstar
	err = milenage.F2345(opc, k, rand, res, ck, ik, ak, akStar)
	if err != nil {
		fmt.Printf("regexp Compile error: %+v", err)
	}

	// derive CK' IK'
	key := append(ck, ik...)
	FC := ueauth.FC_FOR_CK_PRIME_IK_PRIME_DERIVATION
	P0 := []byte(snName)
	P1 := autn[:6]
	kdfVal, err := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1))
	if err != nil {
		fmt.Printf("GetKDFValue error: %+v", err)
	}
	ckPrime := kdfVal[:len(kdfVal)/2]
	ikPrime := kdfVal[len(kdfVal)/2:]

	// derive Kaut Kausf Kseaf
	key = append(ikPrime, ckPrime...)
	// omit "imsi-" part in supi
	sBase := []byte("EAP-AKA'" + ue.Supi[5:])
	var MK, prev []byte
	prfRounds := 208/32 + 1
	for i := 0; i < prfRounds; i++ {
		// Create a new HMAC by defining the hash type and the key (as byte array)
		h := hmac.New(sha256.New, key)

		hexNum := (byte)(i + 1)
		ap := append(sBase, hexNum)
		s := append(prev, ap...)

		// Write Data to it
		if _, err = h.Write(s); err != nil {
			fmt.Printf("EAP-AKA' prf error: %+v", err)
		}

		// Get result
		sha := h.Sum(nil)
		MK = append(MK, sha...)
		prev = sha
	}
	Kaut := MK[16:48]
	Kausf := MK[144:176]
	P0 = []byte(snName)
	Kseaf, err := ueauth.GetKDFValue(Kausf, ueauth.FC_FOR_KSEAF_DERIVATION, P0, ueauth.KDFLen(P0))
	if err != nil {
		fmt.Printf("GetKDFValue error: %+v", err)
	}

	// fill response EAP packet
	resEAPMessage := make([]byte, 40)
	copy(resEAPMessage, eAPMessage[:8])
	resEAPMessage[0] = 2
	resEAPMessage[2] = 0
	resEAPMessage[3] = 40
	resEAPMessage[8] = 3 // AT_RES
	resEAPMessage[9] = 3
	resEAPMessage[11] = 64
	copy(resEAPMessage[12:20], res[:])
	resEAPMessage[20] = 11 // AT_MAC
	resEAPMessage[21] = 5

	// calculate MAC
	h := hmac.New(sha256.New, Kaut)
	if _, err = h.Write(resEAPMessage); err != nil {
		fmt.Printf("MAC calculate error: %+v", err)
	}
	sum := h.Sum(nil)
	copy(resEAPMessage[24:], sum[:16])

	// derive Kamf
	supiRegexp, err := regexp.Compile("(?:imsi|supi)-([0-9]{5,15})")
	if err != nil {
		fmt.Printf("regexp Compile error: %+v", err)
	}
	groups := supiRegexp.FindStringSubmatch(ue.Supi)

	fmt.Println("in wagf supi", ue.Supi)

	P0 = []byte(groups[1])
	L0 := ueauth.KDFLen(P0)
	P1 = []byte{0x00, 0x00}
	L1 := ueauth.KDFLen(P1)

	ue.Kamf, err = ueauth.GetKDFValue(Kseaf, ueauth.FC_FOR_KAMF_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		fmt.Printf("GetKDFValue error: %+v", err)
	}

	ue.DerivateAlgKey()
	return resEAPMessage

}

func (ue *WAGFUe) DerivateKamf(key []byte, snName string, SQN, AK []byte) {

	FC := ueauth.FC_FOR_KAUSF_DERIVATION
	P0 := []byte(snName)
	SQNxorAK := make([]byte, 6)
	for i := 0; i < len(SQN); i++ {
		SQNxorAK[i] = SQN[i] ^ AK[i]
	}
	P1 := SQNxorAK
	Kausf, err := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1))
	if err != nil {
		fmt.Printf("GetKDFValue error: %+v", err)
	}
	P0 = []byte(snName)
	Kseaf, err := ueauth.GetKDFValue(Kausf, ueauth.FC_FOR_KSEAF_DERIVATION, P0, ueauth.KDFLen(P0))
	if err != nil {
		fmt.Printf("GetKDFValue error: %+v", err)
	}

	supiRegexp, err := regexp.Compile("(?:imsi|supi)-([0-9]{5,15})")
	if err != nil {
		fmt.Printf("regexp Compile error: %+v", err)
	}
	groups := supiRegexp.FindStringSubmatch(ue.Supi)

	P0 = []byte(groups[1])
	L0 := ueauth.KDFLen(P0)
	P1 = []byte{0x00, 0x00}
	L1 := ueauth.KDFLen(P1)

	ue.Kamf, err = ueauth.GetKDFValue(Kseaf, ueauth.FC_FOR_KAMF_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		fmt.Printf("GetKDFValue error: %+v", err)
	}
}

// Algorithm key Derivation function defined in TS 33.501 Annex A.9
func (ue *WAGFUe) DerivateAlgKey() {
	// Security Key
	P0 := []byte{security.NNASEncAlg}
	L0 := ueauth.KDFLen(P0)
	P1 := []byte{ue.CipheringAlg}
	L1 := ueauth.KDFLen(P1)

	kenc, err := ueauth.GetKDFValue(ue.Kamf, ueauth.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		fmt.Printf("GetKDFValue error: %+v", err)
	}
	copy(ue.KnasEnc[:], kenc[16:32])

	// Integrity Key
	P0 = []byte{security.NNASIntAlg}
	L0 = ueauth.KDFLen(P0)
	P1 = []byte{ue.IntegrityAlg}
	L1 = ueauth.KDFLen(P1)

	kint, err := ueauth.GetKDFValue(ue.Kamf, ueauth.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		fmt.Printf("GetKDFValue error: %+v", err)
	}
	copy(ue.KnasInt[:], kint[16:32])
}

func (ue *WAGFUe) GetUESecurityCapability() (UESecurityCapability *nasType.UESecurityCapability) {
	UESecurityCapability = &nasType.UESecurityCapability{
		Iei:    nasMessage.RegistrationRequestUESecurityCapabilityType,
		Len:    2,
		Buffer: []uint8{0x00, 0x00},
	}
	switch ue.CipheringAlg {
	case security.AlgCiphering128NEA0:
		UESecurityCapability.SetEA0_5G(1)
	case security.AlgCiphering128NEA1:
		UESecurityCapability.SetEA1_128_5G(1)
	case security.AlgCiphering128NEA2:
		UESecurityCapability.SetEA2_128_5G(1)
	case security.AlgCiphering128NEA3:
		UESecurityCapability.SetEA3_128_5G(1)
	}

	switch ue.IntegrityAlg {
	case security.AlgIntegrity128NIA0:
		UESecurityCapability.SetIA0_5G(1)
	case security.AlgIntegrity128NIA1:
		UESecurityCapability.SetIA1_128_5G(1)
	case security.AlgIntegrity128NIA2:
		UESecurityCapability.SetIA2_128_5G(1)
	case security.AlgIntegrity128NIA3:
		UESecurityCapability.SetIA3_128_5G(1)
	}

	return
}

func (ue *WAGFUe) Get5GMMCapability() (capability5GMM *nasType.Capability5GMM) {
	return &nasType.Capability5GMM{
		Iei:   nasMessage.RegistrationRequestCapability5GMMType,
		Len:   1,
		Octet: [13]uint8{0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
}

func (ue *WAGFUe) GetBearerType() uint8 {
	if ue.AnType == models.AccessType__3_GPP_ACCESS {
		return security.Bearer3GPP
	} else if ue.AnType == models.AccessType_NON_3_GPP_ACCESS {
		return security.BearerNon3GPP
	} else {
		return security.OnlyOneBearer
	}
}
