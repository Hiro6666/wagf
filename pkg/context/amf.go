package context

import (
	"bytes"

	"git.cs.nctu.edu.tw/calee/sctp"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapConvert"
	"github.com/free5gc/ngap/ngapType"
)

type WAGFAMF struct {
	SCTPAddr              string
	SCTPConn              *sctp.SCTPConn
	AMFName               *ngapType.AMFName
	ServedGUAMIList       *ngapType.ServedGUAMIList
	RelativeAMFCapacity   *ngapType.RelativeAMFCapacity
	PLMNSupportList       *ngapType.PLMNSupportList
	AMFTNLAssociationList map[string]*AMFTNLAssociationItem // v4+v6 as key
	// Overload related
	AMFOverloadContent *AMFOverloadContent
	// Relative Context
	WagfUeList map[int64]*WAGFUe // ranUeNgapId as key
}

type AMFTNLAssociationItem struct {
	Ipv4                   string
	Ipv6                   string
	TNLAssociationUsage    *ngapType.TNLAssociationUsage
	TNLAddressWeightFactor *int64
}

type AMFOverloadContent struct {
	Action     *ngapType.OverloadAction
	TrafficInd *int64
	NSSAIList  []SliceOverloadItem
}

type SliceOverloadItem struct {
	SNssaiList []ngapType.SNSSAI
	Action     *ngapType.OverloadAction
	TrafficInd *int64
}

func (amf *WAGFAMF) init(sctpAddr string, conn *sctp.SCTPConn) {
	amf.SCTPAddr = sctpAddr
	amf.SCTPConn = conn
	amf.AMFTNLAssociationList = make(map[string]*AMFTNLAssociationItem)
	amf.WagfUeList = make(map[int64]*WAGFUe)
}

func (amf *WAGFAMF) FindUeByAmfUeNgapID(id int64) *WAGFUe {
	for _, wagfUe := range amf.WagfUeList {
		if wagfUe.AmfUeNgapId == id {
			return wagfUe
		}
	}
	return nil
}

func (amf *WAGFAMF) RemoveAllRelatedUe() {
	for _, ue := range amf.WagfUeList {
		ue.Remove()
	}
}

func (amf *WAGFAMF) AddAMFTNLAssociationItem(info ngapType.CPTransportLayerInformation) *AMFTNLAssociationItem {
	item := &AMFTNLAssociationItem{}
	item.Ipv4, item.Ipv6 = ngapConvert.IPAddressToString(*info.EndpointIPAddress)
	amf.AMFTNLAssociationList[item.Ipv4+item.Ipv6] = item
	return item
}

func (amf *WAGFAMF) FindAMFTNLAssociationItem(info ngapType.CPTransportLayerInformation) *AMFTNLAssociationItem {
	v4, v6 := ngapConvert.IPAddressToString(*info.EndpointIPAddress)
	return amf.AMFTNLAssociationList[v4+v6]
}

func (amf *WAGFAMF) DeleteAMFTNLAssociationItem(info ngapType.CPTransportLayerInformation) {
	v4, v6 := ngapConvert.IPAddressToString(*info.EndpointIPAddress)
	delete(amf.AMFTNLAssociationList, v4+v6)
}

func (amf *WAGFAMF) StartOverload(
	resp *ngapType.OverloadResponse, trafloadInd *ngapType.TrafficLoadReductionIndication,
	nssai *ngapType.OverloadStartNSSAIList) *AMFOverloadContent {
	if resp == nil && trafloadInd == nil && nssai == nil {
		return nil
	}
	content := AMFOverloadContent{}
	if resp != nil {
		content.Action = resp.OverloadAction
	}
	if trafloadInd != nil {
		content.TrafficInd = &trafloadInd.Value
	}
	if nssai != nil {
		for _, item := range nssai.List {
			sliceItem := SliceOverloadItem{}
			for _, item2 := range item.SliceOverloadList.List {
				sliceItem.SNssaiList = append(sliceItem.SNssaiList, item2.SNSSAI)
			}
			if item.SliceOverloadResponse != nil {
				sliceItem.Action = item.SliceOverloadResponse.OverloadAction
			}
			if item.SliceTrafficLoadReductionIndication != nil {
				sliceItem.TrafficInd = &item.SliceTrafficLoadReductionIndication.Value
			}
			content.NSSAIList = append(content.NSSAIList, sliceItem)
		}
	}
	amf.AMFOverloadContent = &content
	return amf.AMFOverloadContent
}

func (amf *WAGFAMF) StopOverload() {
	amf.AMFOverloadContent = nil
}

// FindAvalibleAMFByCompareGUAMI compares the incoming GUAMI with AMF served GUAMI
// and return if this AMF is avalible for UE
func (amf *WAGFAMF) FindAvalibleAMFByCompareGUAMI(ueSpecifiedGUAMI *ngapType.GUAMI) bool {
	for _, amfServedGUAMI := range amf.ServedGUAMIList.List {
		codedAMFServedGUAMI, err := aper.MarshalWithParams(&amfServedGUAMI.GUAMI, "valueExt")
		if err != nil {
			return false
		}
		codedUESpecifiedGUAMI, err := aper.MarshalWithParams(ueSpecifiedGUAMI, "valueExt")
		if err != nil {
			return false
		}
		if !bytes.Equal(codedAMFServedGUAMI, codedUESpecifiedGUAMI) {
			continue
		}
		return true
	}
	return false
}

func (amf *WAGFAMF) FindAvalibleAMFByCompareSelectedPLMNId(ueSpecifiedSelectedPLMNId *ngapType.PLMNIdentity) bool {
	for _, amfServedPLMNId := range amf.PLMNSupportList.List {
		if !bytes.Equal(amfServedPLMNId.PLMNIdentity.Value, ueSpecifiedSelectedPLMNId.Value) {
			continue
		}
		return true
	}
	return false
}
