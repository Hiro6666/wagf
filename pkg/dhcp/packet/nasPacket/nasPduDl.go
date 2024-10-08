package nasPacket

import (
	"fmt"
	"net"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/wagf/internal/ngap/security"
	"github.com/free5gc/wagf/pkg/context"
	"github.com/free5gc/wagf/pkg/dhcp/packet/ngapPacket"
)

func DecodePDUSessionEstablishmentAccept(ue *context.WAGFUe, length int, buffer []byte) (*nas.Message, error) {

	if length == 0 {
		return nil, fmt.Errorf("Empty buffer")
	}

	nasEnv, n := ngapPacket.DecapNasPduFromEnvelope(buffer[:length])
	nasMsg, err := security.NASDecode(ue, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, nasEnv[:n])
	if err != nil {
		return nil, fmt.Errorf("NAS Decode Fail: %+v", err)
	}

	// Retrieve GSM from GmmMessage.DLNASTransport.PayloadContainer and decode
	payloadContainer := nasMsg.GmmMessage.DLNASTransport.PayloadContainer
	byteArray := payloadContainer.Buffer[:payloadContainer.Len]
	if err := nasMsg.GsmMessageDecode(&byteArray); err != nil {
		return nil, fmt.Errorf("NAS Decode Fail: %+v", err)
	}

	return nasMsg, nil
}

func GetPDUAddress(accept *nasMessage.PDUSessionEstablishmentAccept) (net.IP, error) {
	if addr := accept.PDUAddress; addr != nil {
		PDUSessionTypeValue := addr.GetPDUSessionTypeValue()
		if PDUSessionTypeValue == nasMessage.PDUSessionTypeIPv4 {
			ip := net.IP(addr.Octet[1:5])
			return ip, nil
		}
	}

	return nil, fmt.Errorf("PDUAddress is nil")
}
