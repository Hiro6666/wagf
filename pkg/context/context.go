package context

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"net"
	"sync"

	"git.cs.nctu.edu.tw/calee/sctp"
	"github.com/sirupsen/logrus"
	gtpv1 "github.com/wmnsk/go-gtp/gtpv1"
	"golang.org/x/net/ipv4"

	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/util/idgenerator"
	"github.com/free5gc/wagf/internal/logger"
	"github.com/free5gc/wagf/pkg/factoryN5CW"
)

var contextLog *logrus.Entry

var wagfContext = WAGFContext{}

type WAGFContext struct {
	NFInfo           WAGFNFInfo
	AMFSCTPAddresses []*sctp.SCTPAddr

	// ID generator
	RANUENGAPIDGenerator *idgenerator.IDGenerator
	TEIDGenerator        *idgenerator.IDGenerator

	// Pools
	UePool                 sync.Map // map[int64]*WAGFUe, RanUeNgapID as key
	AMFPool                sync.Map // map[string]*WAGFAMF, SCTPAddr as key
	AMFReInitAvailableList sync.Map // map[string]bool, SCTPAddr as key
	IKESA                  sync.Map // map[uint64]*IKESecurityAssociation, SPI as key
	ChildSA                sync.Map // map[uint32]*ChildSecurityAssociation, inboundSPI as key
	GTPConnectionWithUPF   sync.Map // map[string]*gtpv1.UPlaneConn, UPF address as key
	AllocatedUEIPAddress   sync.Map // map[string]*WAGFUe, IPAddr as key
	AllocatedUETEID        sync.Map // map[uint32]*WAGFUe, TEID as key
	RadiusSessionPool      sync.Map // map[string]*RadiusSession, Calling Station ID as key
	DHCPSessionPool        sync.Map // map[uint64]*DHCPSession, LineId as key

	// wagf FQDN
	FQDN string

	// Security data
	CertificateAuthority []byte
	WAGFCertificate      []byte
	WAGFPrivateKey       *rsa.PrivateKey
	RadiusSecret         string

	// UEIPAddressRange
	Subnet *net.IPNet

	// XFRM interface
	XfrmIfaceId         uint32
	XfrmIfaces          sync.Map // map[uint32]*netlink.Link, XfrmIfaceId as key
	XfrmIfaceName       string
	XfrmParentIfaceName string

	// Every UE's first UP IPsec will use default XFRM interface, additoinal UP IPsec will offset its XFRM id
	XfrmIfaceIdOffsetForUP uint32

	// wagf local address
	IKEBindAddress      string
	RadiusBindAddress   string
	DHCPBindAddress     string
	IPSecGatewayAddress string
	GTPBindAddress      string
	TCPPort             uint16

	// wagf NWt interface IPv4 packet connection
	NWtIPv4PacketConn *ipv4.PacketConn

	// default UE content
	N5CWConfig factoryN5CW.Config
	N5CWInfo   factoryN5CW.N5CWInfo
}

func init() {
	// init log
	contextLog = logger.ContextLog

	// init ID generator
	wagfContext.RANUENGAPIDGenerator = idgenerator.NewGenerator(0, math.MaxInt64)
	wagfContext.TEIDGenerator = idgenerator.NewGenerator(1, math.MaxUint32)

	if err := factoryN5CW.InitConfigFactory("./config/wagfcfg.yaml"); err != nil {
		contextLog.Errorf("factoryN5CW.InitConfigFactory: %+v", err)
	}
	if _, err := factoryN5CW.N5cwConfig.Validate(); err != nil {
		contextLog.Errorf("Validate config fail: %+v", err)
	}
	wagfContext.N5CWConfig = factoryN5CW.N5cwConfig
	wagfContext.N5CWInfo = (wagfContext.N5CWConfig).Configuration.N5CWInfo

	wagfContext.N5CWConfig.Print()
}

// Create new wagf context
func WAGFSelf() *WAGFContext {
	return &wagfContext
}

func (context *WAGFContext) NewRadiusSession(callingStationID string) *RadiusSession {
	radiusSession := new(RadiusSession)
	radiusSession.CallingStationID = callingStationID
	context.RadiusSessionPool.Store(callingStationID, radiusSession)
	return radiusSession
}

func (context *WAGFContext) DeleteRadiusSession(ranUeNgapId string) {
	context.RadiusSessionPool.Delete(ranUeNgapId)
}

func (context *WAGFContext) RadiusSessionPoolLoad(ranUeNgapId string) (*RadiusSession, bool) {
	ue, ok := context.RadiusSessionPool.Load(ranUeNgapId)
	if ok {
		return ue.(*RadiusSession), ok
	} else {
		return nil, ok
	}
}

func (context *WAGFContext) NewDHCPSession(LineId uint64) *DHCPSession {
	dhcpSession := new(DHCPSession)
	dhcpSession.LineId = LineId
	context.DHCPSessionPool.Store(LineId, dhcpSession)
	return dhcpSession
}

func (context *WAGFContext) DeleteDHCPSession(LineId uint64) {
	context.DHCPSessionPool.Delete(LineId)
}

func (context *WAGFContext) DHCPSessionPoolLoad(LineId uint64) (*DHCPSession, bool) {
	ue, ok := context.DHCPSessionPool.Load(LineId)
	if ok {
		return ue.(*DHCPSession), ok
	} else {
		return nil, ok
	}
}

func (context *WAGFContext) NewWagfUe() *WAGFUe {
	ranUeNgapId, err := context.RANUENGAPIDGenerator.Allocate()
	fmt.Println("NewWagfUe")
	if err != nil {
		contextLog.Errorf("New wagf UE failed: %+v", err)
		return nil
	}
	wagfUe := new(WAGFUe)
	wagfUe.init(ranUeNgapId)
	context.UePool.Store(ranUeNgapId, wagfUe)
	return wagfUe
}

func (context *WAGFContext) DeleteWagfUe(ranUeNgapId int64) {
	context.UePool.Delete(ranUeNgapId)
}

func (context *WAGFContext) UePoolLoad(ranUeNgapId int64) (*WAGFUe, bool) {
	ue, ok := context.UePool.Load(ranUeNgapId)
	if ok {
		return ue.(*WAGFUe), ok
	} else {
		return nil, ok
	}
}

func (context *WAGFContext) NewWagfAmf(sctpAddr string, conn *sctp.SCTPConn) *WAGFAMF {
	amf := new(WAGFAMF)
	amf.init(sctpAddr, conn)
	if item, loaded := context.AMFPool.LoadOrStore(sctpAddr, amf); loaded {
		contextLog.Warn("[Context] NewWagfAmf(): AMF entry already exists.")
		return item.(*WAGFAMF)
	} else {
		return amf
	}
}

func (context *WAGFContext) DeleteWagfAmf(sctpAddr string) {
	context.AMFPool.Delete(sctpAddr)
}

func (context *WAGFContext) AMFPoolLoad(sctpAddr string) (*WAGFAMF, bool) {
	amf, ok := context.AMFPool.Load(sctpAddr)
	if ok {
		return amf.(*WAGFAMF), ok
	} else {
		return nil, ok
	}
}

func (context *WAGFContext) DeleteAMFReInitAvailableFlag(sctpAddr string) {
	context.AMFReInitAvailableList.Delete(sctpAddr)
}

func (context *WAGFContext) AMFReInitAvailableListLoad(sctpAddr string) (bool, bool) {
	flag, ok := context.AMFReInitAvailableList.Load(sctpAddr)
	if ok {
		return flag.(bool), ok
	} else {
		return true, ok
	}
}

func (context *WAGFContext) AMFReInitAvailableListStore(sctpAddr string, flag bool) {
	context.AMFReInitAvailableList.Store(sctpAddr, flag)
}

func (context *WAGFContext) NewIKESecurityAssociation() *IKESecurityAssociation {
	ikeSecurityAssociation := new(IKESecurityAssociation)

	var maxSPI *big.Int = new(big.Int).SetUint64(math.MaxUint64)
	var localSPIuint64 uint64

	for {
		localSPI, err := rand.Int(rand.Reader, maxSPI)
		if err != nil {
			contextLog.Error("[Context] Error occurs when generate new IKE SPI")
			return nil
		}
		localSPIuint64 = localSPI.Uint64()
		if _, duplicate := context.IKESA.LoadOrStore(localSPIuint64, ikeSecurityAssociation); !duplicate {
			break
		}
	}

	ikeSecurityAssociation.LocalSPI = localSPIuint64

	return ikeSecurityAssociation
}

func (context *WAGFContext) DeleteIKESecurityAssociation(spi uint64) {
	context.IKESA.Delete(spi)
}

func (context *WAGFContext) UELoadbyIDi(idi []byte) *WAGFUe {
	var ue *WAGFUe
	context.UePool.Range(func(_, thisUE interface{}) bool {
		strIdi := hex.EncodeToString(idi)
		strSuci := hex.EncodeToString(thisUE.(*WAGFUe).UEIdentity.Buffer)
		contextLog.Debugln("Idi", strIdi)
		contextLog.Debugln("SUCI", strSuci)
		if strIdi == strSuci {
			ue = thisUE.(*WAGFUe)
			return false
		}
		return true
	})
	return ue
}

func (context *WAGFContext) IKESALoad(spi uint64) (*IKESecurityAssociation, bool) {
	securityAssociation, ok := context.IKESA.Load(spi)
	if ok {
		return securityAssociation.(*IKESecurityAssociation), ok
	} else {
		return nil, ok
	}
}

func (context *WAGFContext) DeleteGTPConnection(upfAddr string) {
	context.GTPConnectionWithUPF.Delete(upfAddr)
}

func (context *WAGFContext) GTPConnectionWithUPFLoad(upfAddr string) (*gtpv1.UPlaneConn, bool) {
	conn, ok := context.GTPConnectionWithUPF.Load(upfAddr)
	if ok {
		return conn.(*gtpv1.UPlaneConn), ok
	} else {
		return nil, ok
	}
}

func (context *WAGFContext) GTPConnectionWithUPFStore(upfAddr string, conn *gtpv1.UPlaneConn) {
	context.GTPConnectionWithUPF.Store(upfAddr, conn)
}

func (context *WAGFContext) NewInternalUEIPAddr(ue *WAGFUe) net.IP {
	var ueIPAddr net.IP

	// TODO: Check number of allocated IP to detect running out of IPs
	for {
		ueIPAddr = generateRandomIPinRange(context.Subnet)
		if ueIPAddr != nil {
			if ueIPAddr.String() == context.IPSecGatewayAddress {
				continue
			}
			if _, ok := context.AllocatedUEIPAddress.LoadOrStore(ueIPAddr.String(), ue); !ok {
				break
			}
		}
	}

	return ueIPAddr
}

func (context *WAGFContext) DeleteInternalUEIPAddr(ipAddr string) {
	context.AllocatedUEIPAddress.Delete(ipAddr)
}

func (context *WAGFContext) AllocatedUEIPAddressLoad(ipAddr string) (*WAGFUe, bool) {
	ue, ok := context.AllocatedUEIPAddress.Load(ipAddr)
	if ok {
		return ue.(*WAGFUe), ok
	} else {
		return nil, ok
	}
}

func (context *WAGFContext) NewTEID(ue *WAGFUe) uint32 {
	teid64, err := context.TEIDGenerator.Allocate()
	if err != nil {
		contextLog.Errorf("New TEID failed: %+v", err)
		return 0
	}
	teid32 := uint32(teid64)

	context.AllocatedUETEID.Store(teid32, ue)

	return teid32
}

func (context *WAGFContext) DeleteTEID(teid uint32) {
	context.AllocatedUETEID.Delete(teid)
}

func (context *WAGFContext) AllocatedUETEIDLoad(teid uint32) (*WAGFUe, bool) {
	ue, ok := context.AllocatedUETEID.Load(teid)
	if ok {
		return ue.(*WAGFUe), ok
	} else {
		return nil, ok
	}
}

func (context *WAGFContext) AMFSelection(ueSpecifiedGUAMI *ngapType.GUAMI,
	ueSpecifiedPLMNId *ngapType.PLMNIdentity) *WAGFAMF {
	var availableAMF *WAGFAMF
	context.AMFPool.Range(func(key, value interface{}) bool {
		amf := value.(*WAGFAMF)
		if amf.FindAvalibleAMFByCompareGUAMI(ueSpecifiedGUAMI) {
			availableAMF = amf
			return false
		} else {
			// Fail to find through GUAMI served by UE.
			// Try again using SelectedPLMNId
			if amf.FindAvalibleAMFByCompareSelectedPLMNId(ueSpecifiedPLMNId) {
				availableAMF = amf
				return false
			} else {
				return true
			}
		}
	})
	return availableAMF
}

func generateRandomIPinRange(subnet *net.IPNet) net.IP {
	ipAddr := make([]byte, 4)
	randomNumber := make([]byte, 4)

	_, err := rand.Read(randomNumber)
	if err != nil {
		contextLog.Errorf("Generate random number for IP address failed: %+v", err)
		return nil
	}

	// TODO: elimenate network name, gateway, and broadcast
	for i := 0; i < 4; i++ {
		alter := randomNumber[i] & (subnet.Mask[i] ^ 255)
		ipAddr[i] = subnet.IP[i] + alter
	}

	return net.IPv4(ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3])
}
