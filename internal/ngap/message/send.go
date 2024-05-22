package message

import (
	"runtime/debug"

	"git.cs.nctu.edu.tw/calee/sctp"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/wagf/internal/logger"
	"github.com/free5gc/wagf/pkg/context"
)

var ngaplog *logrus.Entry

func init() {
	ngaplog = logger.NgapLog
}

func SendToAmf(amf *context.WAGFAMF, pkt []byte) {
	if amf == nil {
		ngaplog.Errorf("[WAGF] AMF Context is nil ")
	} else {
		if n, err := amf.SCTPConn.Write(pkt); err != nil {
			ngaplog.Errorf("Write to SCTP socket failed: %+v", err)
		} else {
			ngaplog.Tracef("Wrote %d bytes", n)
		}
	}
}

func SendNGSetupRequest(conn *sctp.SCTPConn) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.NgapLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	ngaplog.Infoln("[WAGF] Send NG Setup Request")

	sctpAddr := conn.RemoteAddr().String()

	if available, _ := context.WAGFSelf().AMFReInitAvailableListLoad(sctpAddr); !available {
		ngaplog.Warnf("[WAGF] Please Wait at least for the indicated time before reinitiating toward same AMF[%s]", sctpAddr)
		return
	}
	pkt, err := BuildNGSetupRequest()
	if err != nil {
		ngaplog.Errorf("Build NGSetup Request failed: %+v\n", err)
		return
	}

	if n, err := conn.Write(pkt); err != nil {
		ngaplog.Errorf("Write to SCTP socket failed: %+v", err)
	} else {
		ngaplog.Tracef("Wrote %d bytes", n)
	}
}

// partOfNGInterface: if reset type is "reset all", set it to nil TS 38.413 9.2.6.11
func SendNGReset(
	amf *context.WAGFAMF,
	cause ngapType.Cause,
	partOfNGInterface *ngapType.UEAssociatedLogicalNGConnectionList) {
	ngaplog.Infoln("[WAGF] Send NG Reset")

	pkt, err := BuildNGReset(cause, partOfNGInterface)
	if err != nil {
		ngaplog.Errorf("Build NGReset failed : %s", err.Error())
		return
	}

	SendToAmf(amf, pkt)
}

func SendNGResetAcknowledge(
	amf *context.WAGFAMF,
	partOfNGInterface *ngapType.UEAssociatedLogicalNGConnectionList,
	diagnostics *ngapType.CriticalityDiagnostics) {
	ngaplog.Infoln("[WAGF] Send NG Reset Acknowledge")

	if partOfNGInterface != nil && len(partOfNGInterface.List) == 0 {
		ngaplog.Error("length of partOfNGInterface is 0")
		return
	}

	pkt, err := BuildNGResetAcknowledge(partOfNGInterface, diagnostics)
	if err != nil {
		ngaplog.Errorf("Build NGReset Acknowledge failed : %s", err.Error())
		return
	}

	SendToAmf(amf, pkt)
}

func SendInitialContextSetupResponse(
	amf *context.WAGFAMF,
	ue *context.WAGFUe,
	responseList *ngapType.PDUSessionResourceSetupListCxtRes,
	failedList *ngapType.PDUSessionResourceFailedToSetupListCxtRes,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics) {
	ngaplog.Infoln("[WAGF] Send Initial Context Setup Response")

	if responseList != nil && len(responseList.List) > context.MaxNumOfPDUSessions {
		ngaplog.Errorln("Pdu List out of range")
		return
	}

	if failedList != nil && len(failedList.List) > context.MaxNumOfPDUSessions {
		ngaplog.Errorln("Pdu List out of range")
		return
	}

	pkt, err := BuildInitialContextSetupResponse(ue, responseList, failedList, criticalityDiagnostics)
	if err != nil {
		ngaplog.Errorf("Build Initial Context Setup Response failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendInitialContextSetupFailure(
	amf *context.WAGFAMF,
	ue *context.WAGFUe,
	cause ngapType.Cause,
	failedList *ngapType.PDUSessionResourceFailedToSetupListCxtFail,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics) {
	ngaplog.Infoln("[WAGF] Send Initial Context Setup Failure")

	if failedList != nil && len(failedList.List) > context.MaxNumOfPDUSessions {
		ngaplog.Errorln("Pdu List out of range")
		return
	}

	pkt, err := BuildInitialContextSetupFailure(ue, cause, failedList, criticalityDiagnostics)
	if err != nil {
		ngaplog.Errorf("Build Initial Context Setup Failure failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendUEContextModificationResponse(
	amf *context.WAGFAMF,
	ue *context.WAGFUe,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics) {
	ngaplog.Infoln("[WAGF] Send UE Context Modification Response")

	pkt, err := BuildUEContextModificationResponse(ue, criticalityDiagnostics)
	if err != nil {
		ngaplog.Errorf("Build UE Context Modification Response failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendUEContextModificationFailure(
	amf *context.WAGFAMF,
	ue *context.WAGFUe,
	cause ngapType.Cause,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics) {
	ngaplog.Infoln("[WAGF] Send UE Context Modification Failure")

	pkt, err := BuildUEContextModificationFailure(ue, cause, criticalityDiagnostics)
	if err != nil {
		ngaplog.Errorf("Build UE Context Modification Failure failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendUEContextReleaseComplete(
	amf *context.WAGFAMF,
	ue *context.WAGFUe,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics) {
	ngaplog.Infoln("[WAGF] Send UE Context Release Complete")

	pkt, err := BuildUEContextReleaseComplete(ue, criticalityDiagnostics)
	if err != nil {
		ngaplog.Errorf("Build UE Context Release Complete failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendUEContextReleaseRequest(
	amf *context.WAGFAMF,
	ue *context.WAGFUe, cause ngapType.Cause) {
	ngaplog.Infoln("[WAGF] Send UE Context Release Request")

	pkt, err := BuildUEContextReleaseRequest(ue, cause)
	if err != nil {
		ngaplog.Errorf("Build UE Context Release Request failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendInitialUEMessage(amf *context.WAGFAMF,
	ue *context.WAGFUe, nasPdu []byte) {
	ngaplog.Infoln("[WAGF] Send Initial UE Message")
	// Attach To AMF

	pkt, err := BuildInitialUEMessage(ue, nasPdu, nil)
	if err != nil {
		ngaplog.Errorf("Build Initial UE Message failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
	// ue.AttachAMF()
}

func SendUplinkNASTransport(
	amf *context.WAGFAMF,
	ue *context.WAGFUe,
	nasPdu []byte) {
	ngaplog.Infoln("[WAGF] Send Uplink NAS Transport")

	if len(nasPdu) == 0 {
		ngaplog.Errorln("NAS Pdu is nil")
		return
	}

	pkt, err := BuildUplinkNASTransport(ue, nasPdu)
	if err != nil {
		ngaplog.Errorf("Build Uplink NAS Transport failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendNASNonDeliveryIndication(
	amf *context.WAGFAMF,
	ue *context.WAGFUe,
	nasPdu []byte,
	cause ngapType.Cause) {
	ngaplog.Infoln("[WAGF] Send NAS NonDelivery Indication")

	if len(nasPdu) == 0 {
		ngaplog.Errorln("NAS Pdu is nil")
		return
	}

	pkt, err := BuildNASNonDeliveryIndication(ue, nasPdu, cause)
	if err != nil {
		ngaplog.Errorf("Build Uplink NAS Transport failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendRerouteNASRequest() {
	ngaplog.Infoln("[WAGF] Send Reroute NAS Request")
}

func SendPDUSessionResourceSetupResponse(
	amf *context.WAGFAMF,
	ue *context.WAGFUe,
	responseList *ngapType.PDUSessionResourceSetupListSURes,
	failedListSURes *ngapType.PDUSessionResourceFailedToSetupListSURes,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics) {
	ngaplog.Infoln("[WAGF] Send PDU Session Resource Setup Response")

	if ue == nil {
		ngaplog.Error("UE context is nil, this information is mandatory.")
		return
	}

	pkt, err := BuildPDUSessionResourceSetupResponse(ue, responseList, failedListSURes, criticalityDiagnostics)
	if err != nil {
		ngaplog.Errorf("Build PDU Session Resource Setup Response failed : %+v", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendPDUSessionResourceModifyResponse(
	amf *context.WAGFAMF,
	ue *context.WAGFUe,
	responseList *ngapType.PDUSessionResourceModifyListModRes,
	failedList *ngapType.PDUSessionResourceFailedToModifyListModRes,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics) {
	ngaplog.Infoln("[WAGF] Send PDU Session Resource Modify Response")

	if ue == nil && criticalityDiagnostics == nil {
		ngaplog.Error("UE context is nil, this information is mandatory")
		return
	}

	pkt, err := BuildPDUSessionResourceModifyResponse(ue, responseList, failedList, criticalityDiagnostics)
	if err != nil {
		ngaplog.Errorf("Build PDU Session Resource Modify Response failed : %+v", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendPDUSessionResourceModifyIndication(
	amf *context.WAGFAMF,
	ue *context.WAGFUe,
	modifyList []ngapType.PDUSessionResourceModifyItemModInd) {
	ngaplog.Infoln("[WAGF] Send PDU Session Resource Modify Indication")

	if ue == nil {
		ngaplog.Error("UE context is nil, this information is mandatory")
		return
	}
	if modifyList == nil {
		ngaplog.Errorln("PDU Session Resource Modify Indication List is nil. This message shall contain at least one Item")
		return
	}

	pkt, err := BuildPDUSessionResourceModifyIndication(ue, modifyList)
	if err != nil {
		ngaplog.Errorf("Build PDU Session Resource Modify Indication failed : %+v", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendPDUSessionResourceNotify(
	amf *context.WAGFAMF,
	ue *context.WAGFUe,
	notiList *ngapType.PDUSessionResourceNotifyList,
	relList *ngapType.PDUSessionResourceReleasedListNot) {
	ngaplog.Infoln("[WAGF] Send PDU Session Resource Notify")

	if ue == nil {
		ngaplog.Error("UE context is nil, this information is mandatory")
		return
	}

	pkt, err := BuildPDUSessionResourceNotify(ue, notiList, relList)
	if err != nil {
		ngaplog.Errorf("Build PDUSession Resource Notify failed : %+v", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendPDUSessionResourceReleaseResponse(
	amf *context.WAGFAMF,
	ue *context.WAGFUe,
	relList ngapType.PDUSessionResourceReleasedListRelRes,
	diagnostics *ngapType.CriticalityDiagnostics) {
	ngaplog.Infoln("[WAGF] Send PDU Session Resource Release Response")

	if ue == nil {
		ngaplog.Error("UE context is nil, this information is mandatory")
		return
	}
	if len(relList.List) < 1 {
		ngaplog.Errorln("PDUSessionResourceReleasedListRelRes is nil. This message shall contain at least one Item")
		return
	}

	pkt, err := BuildPDUSessionResourceReleaseResponse(ue, relList, diagnostics)
	if err != nil {
		ngaplog.Errorf("Build PDU Session Resource Release Response failed : %+v", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendErrorIndication(
	amf *context.WAGFAMF,
	amfUENGAPID *int64,
	ranUENGAPID *int64,
	cause *ngapType.Cause,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics) {
	ngaplog.Infoln("[WAGF] Send Error Indication")

	if (cause == nil) && (criticalityDiagnostics == nil) {
		ngaplog.Errorln("Both cause and criticality is nil. This message shall contain at least one of them.")
		return
	}

	pkt, err := BuildErrorIndication(amfUENGAPID, ranUENGAPID, cause, criticalityDiagnostics)
	if err != nil {
		ngaplog.Errorf("Build Error Indication failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendErrorIndicationWithSctpConn(
	sctpConn *sctp.SCTPConn,
	amfUENGAPID *int64,
	ranUENGAPID *int64,
	cause *ngapType.Cause,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics) {
	ngaplog.Infoln("[WAGF] Send Error Indication")

	if (cause == nil) && (criticalityDiagnostics == nil) {
		ngaplog.Errorln("Both cause and criticality is nil. This message shall contain at least one of them.")
		return
	}

	pkt, err := BuildErrorIndication(amfUENGAPID, ranUENGAPID, cause, criticalityDiagnostics)
	if err != nil {
		ngaplog.Errorf("Build Error Indication failed : %+v\n", err)
		return
	}

	if n, err := sctpConn.Write(pkt); err != nil {
		ngaplog.Errorf("Write to SCTP socket failed: %+v", err)
	} else {
		ngaplog.Tracef("Wrote %d bytes", n)
	}
}

func SendUERadioCapabilityInfoIndication() {
	ngaplog.Infoln("[WAGF] Send UE Radio Capability Info Indication")
}

func SendUERadioCapabilityCheckResponse(
	amf *context.WAGFAMF,
	ue *context.WAGFUe,
	diagnostics *ngapType.CriticalityDiagnostics) {
	ngaplog.Infoln("[WAGF] Send UE Radio Capability Check Response")

	pkt, err := BuildUERadioCapabilityCheckResponse(ue, diagnostics)
	if err != nil {
		ngaplog.Errorf("Build UERadio Capability Check Response failed : %+v\n", err)
		return
	}
	SendToAmf(amf, pkt)
}

func SendAMFConfigurationUpdateAcknowledge(
	amf *context.WAGFAMF,
	setupList *ngapType.AMFTNLAssociationSetupList,
	failList *ngapType.TNLAssociationList,
	diagnostics *ngapType.CriticalityDiagnostics) {
	ngaplog.Infoln("[WAGF] Send AMF Configuration Update Acknowledge")

	pkt, err := BuildAMFConfigurationUpdateAcknowledge(setupList, failList, diagnostics)
	if err != nil {
		ngaplog.Errorf("Build AMF Configuration Update Acknowledge failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendAMFConfigurationUpdateFailure(
	amf *context.WAGFAMF,
	ngCause ngapType.Cause,
	time *ngapType.TimeToWait,
	diagnostics *ngapType.CriticalityDiagnostics) {
	ngaplog.Infoln("[WAGF] Send AMF Configuration Update Failure")
	pkt, err := BuildAMFConfigurationUpdateFailure(ngCause, time, diagnostics)
	if err != nil {
		ngaplog.Errorf("Build AMF Configuration Update Failure failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendRANConfigurationUpdate(amf *context.WAGFAMF) {
	ngaplog.Infoln("[WAGF] Send RAN Configuration Update")

	if available, _ := context.WAGFSelf().AMFReInitAvailableListLoad(amf.SCTPAddr); !available {
		ngaplog.Warnf(
			"[WAGF] Please Wait at least for the indicated time before reinitiating toward same AMF[%s]", amf.SCTPAddr)
		return
	}

	pkt, err := BuildRANConfigurationUpdate()
	if err != nil {
		ngaplog.Errorf("Build AMF Configuration Update Failure failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendUplinkRANConfigurationTransfer() {
	ngaplog.Infoln("[WAGF] Send Uplink RAN Configuration Transfer")
}

func SendUplinkRANStatusTransfer() {
	ngaplog.Infoln("[WAGF] Send Uplink RAN Status Transfer")
}

func SendLocationReportingFailureIndication() {
	ngaplog.Infoln("[WAGF] Send Location Reporting Failure Indication")
}

func SendLocationReport() {
	ngaplog.Infoln("[WAGF] Send Location Report")
}

func SendRRCInactiveTransitionReport() {
	ngaplog.Infoln("[WAGF] Send RRC Inactive Transition Report")
}
