package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"

	radius_message "github.com/free5gc/wagf/pkg/radius/message"

)

func KDF5gAka(param ...string) hash.Hash {
	s := param[0]
	s += param[1]
	if p0len, err := strconv.Atoi(param[2]); err != nil {
		ngapLog.Warnf("atoi failed: %+v", err)
	} else {
		s += strconv.FormatInt(int64(p0len), 16)
	}
	h := hmac.New(sha256.New, []byte(s))

	return h
}

func intToByteArray(i int) []byte {
	r := make([]byte, 2)
	binary.BigEndian.PutUint16(r, uint16(i))
	return r
}

func padZeros(byteArray []byte, size int) []byte {
	l := len(byteArray)
	if l == size {
		return byteArray
	}
	r := make([]byte, size)
	copy(r[size-l:], byteArray)
	return r
}

func CalculateAtMAC(key []byte, input []byte) []byte {
	// keyed with K_aut
	h := hmac.New(sha256.New, key)
	if _, err := h.Write(input); err != nil {
		ngapLog.Errorln(err.Error())
	}
	sum := h.Sum(nil)
	return sum[:16]
}

// func EapEncodeAttribute(attributeType string, data string) (returnStr string, err error) {
func EapEncodeAttribute(attributeType string, data string) (string, error) {
	var attribute string
	var length int

	switch attributeType {
	case "AT_RAND":
		length = len(data)/8 + 1
		if length != 5 {
			return "", fmt.Errorf("[eapEncodeAttribute] AT_RAND Length Error")
		}
		attrNum := fmt.Sprintf("%02x", radius_message.AT_RAND_ATTRIBUTE)
		attribute = attrNum + "05" + "0000" + data

	case "AT_AUTN":
		length = len(data)/8 + 1
		if length != 5 {
			return "", fmt.Errorf("[eapEncodeAttribute] AT_AUTN Length Error")
		}
		attrNum := fmt.Sprintf("%02x", radius_message.AT_AUTN_ATTRIBUTE)
		attribute = attrNum + "05" + "0000" + data

	case "AT_KDF_INPUT":
		var byteName []byte
		nLength := len(data)
		length := (nLength+3)/4 + 1
		b := make([]byte, length*4)
		byteNameLength := intToByteArray(nLength)
		byteName = []byte(data)
		pad := padZeros(byteName, (length-1)*4)
		b[0] = 23
		b[1] = byte(length)
		copy(b[2:4], byteNameLength)
		copy(b[4:], pad)
		return string(b[:]), nil

	case "AT_KDF":
		// Value 1 default key derivation function for EAP-AKA'
		attrNum := fmt.Sprintf("%02x", radius_message.AT_KDF_ATTRIBUTE)
		attribute = attrNum + "01" + "0001"

	case "AT_MAC":
		// Pad MAC value with 16 bytes of 0 since this is just for the calculation of MAC
		attrNum := fmt.Sprintf("%02x", radius_message.AT_MAC_ATTRIBUTE)
		attribute = attrNum + "05" + "0000" + "00000000000000000000000000000000"

	case "AT_RES":
		var byteName []byte
		nLength := len(data)
		length := (nLength+3)/4 + 1
		b := make([]byte, length*4)
		byteNameLength := intToByteArray(nLength)
		byteName = []byte(data)
		pad := padZeros(byteName, (length-1)*4)
		b[0] = 3
		b[1] = byte(length)
		copy(b[2:4], byteNameLength)
		copy(b[4:], pad)
		return string(b[:]), nil

	default:
		ngapLog.Errorf("UNKNOWN attributeType %s\n", attributeType)
		return "", nil
	}

	if r, err := hex.DecodeString(attribute); err != nil {
		return "", err
	} else {
		return string(r), nil
	}
}

// func eapAkaPrimePrf(ikPrime string, ckPrime string, identity string) (K_encr string, K_aut string, K_re string,
//    MSK string, EMSK string) {
func eapAkaPrimePrf(ikPrime string, ckPrime string, identity string) ([]byte, []byte, []byte, []byte, []byte) {
	keyAp := ikPrime + ckPrime

	var key []byte
	if keyTmp, err := hex.DecodeString(keyAp); err != nil {
		ngapLog.Warnf("Decode key AP failed: %+v", err)
	} else {
		key = keyTmp
	}
	sBase := []byte("EAP-AKA'" + identity)

	MK := []byte("")
	prev := []byte("")
	//_ = prev
	prfRounds := 208/32 + 1
	for i := 0; i < prfRounds; i++ {
		// Create a new HMAC by defining the hash type and the key (as byte array)
		h := hmac.New(sha256.New, key)

		hexNum := (byte)(i + 1)
		ap := append(sBase, hexNum)
		s := append(prev, ap...)

		// Write Data to it
		if _, err := h.Write(s); err != nil {
			ngapLog.Errorln(err.Error())
		}

		// Get result
		sha := h.Sum(nil)
		MK = append(MK, sha...)
		prev = sha
	}

	K_encr := MK[0:16]  // 0..127
	K_aut := MK[16:48]  // 128..383
	K_re := MK[48:80]   // 384..639
	MSK := MK[80:144]   // 640..1151
	EMSK := MK[144:208] // 1152..1663
	return K_encr, K_aut, K_re, MSK, EMSK
}

func decodeEapAkaPrime(eapPkt []byte) (*radius_message.EapAkaPrimePkt, error) {
	var decodePkt radius_message.EapAkaPrimePkt
	var attrLen int
	var decodeAttr radius_message.EapAkaPrimeAttribute
	attributes := make(map[uint8]radius_message.EapAkaPrimeAttribute)
	fmt.Println("eapPkt",eapPkt)
	data := eapPkt[5:]
	decodePkt.Subtype = data[0]
	fmt.Println("Subtype", decodePkt.Subtype)
	dataLen := len(data)

	// decode attributes
	for i := 3; i < dataLen; i += attrLen {
		attrType := data[i]
		attrLen = int(data[i+1]) * 4
		if attrLen == 0 {
			return nil, fmt.Errorf("attribute length equal to zero")
		}
		if i+attrLen > dataLen {
			return nil, fmt.Errorf("packet length out of range")
		}
		switch attrType {
		case radius_message.AT_RAND_ATTRIBUTE:
			ngapLog.Tracef("Decoding AT_RAND\n")
			if attrLen != 20 {
				return nil, fmt.Errorf("attribute AT_RAND decode err")
			}
			decodeAttr.Type = attrType
			decodeAttr.Length = data[i+1]
			decodeAttr.Value = data[i+4 : i+attrLen]
			attributes[attrType] = decodeAttr
		case radius_message.AT_AUTN_ATTRIBUTE:
			ngapLog.Tracef("Decoding AT_AUTN\n")
			if attrLen != 20 {
				return nil, fmt.Errorf("attribute AT_AUTN decode err")
			}
			decodeAttr.Type = attrType
			decodeAttr.Length = data[i+1]
			decodeAttr.Value = data[i+4 : i+attrLen]
			attributes[attrType] = decodeAttr
		case radius_message.AT_RES_ATTRIBUTE:
			ngapLog.Tracef("Decoding AT_RES\n")
			accLen := int(data[i+3] >> 3)
			if accLen > 16 || accLen < 4 || accLen+4 > attrLen {
				return nil, fmt.Errorf("attribute AT_RES decode err")
			}

			decodeAttr.Type = attrType
			decodeAttr.Length = data[i+1]
			decodeAttr.Value = data[i+4 : i+4+accLen]
			attributes[attrType] = decodeAttr
		case radius_message.AT_MAC_ATTRIBUTE:
			ngapLog.Tracef("Decoding AT_MAC\n")
			if attrLen != 20 {
				return nil, fmt.Errorf("attribute AT_MAC decode err")
			}
			decodeAttr.Type = attrType
			decodeAttr.Length = data[i+1]
			Mac := make([]byte, attrLen-4)
			copy(Mac, data[i+4:i+attrLen])
			decodeAttr.Value = Mac
			attributes[attrType] = decodeAttr

			// clean AT_MAC value for integrity check later
			zeros := make([]byte, attrLen-4)
			copy(data[i+4:i+attrLen], zeros)
			decodePkt.MACInput = eapPkt
		case radius_message.AT_KDF_ATTRIBUTE:
			ngapLog.Tracef("Decoding AT_KDF\n")
			if attrLen != 4 {
				return nil, fmt.Errorf("attribute AT_KDF decode err")
			}
			decodeAttr.Type = attrType
			decodeAttr.Length = data[i+1]
			decodeAttr.Value = data[i+2 : i+attrLen]
			attributes[attrType] = decodeAttr
		case radius_message.AT_KDF_INPUT_ATTRIBUTE:
			ngapLog.Tracef("Decoding AT_KDF_INPUT\n")
			decodeAttr.Type = attrType
			decodeAttr.Length = data[i+1]
			snnLen := int(data[i+3])
			decodeAttr.Value = data[i+4 : i+4+snnLen]
			attributes[attrType] = decodeAttr
		case radius_message.AT_AUTS_ATTRIBUTE:
			ngapLog.Tracef("Decoding AT_AUTS\n")
			if attrLen != 16 {
				return nil, fmt.Errorf("attribute AT_AUTS decode err")
			}
			decodeAttr.Type = attrType
			decodeAttr.Length = data[i+1]
			decodeAttr.Value = data[i+2 : i+attrLen]
			attributes[attrType] = decodeAttr
		case radius_message.AT_CLIENT_ERROR_CODE_ATTRIBUTE:
			ngapLog.Tracef("Decoding AT_CLIENT_ERROR_CODE\n")
			if attrLen != 4 {
				return nil, fmt.Errorf("attribute AT_CLIENT_ERROR_CODE decode err")
			}
			decodeAttr.Type = attrType
			decodeAttr.Length = data[i+1]
			decodeAttr.Value = data[i+2 : i+attrLen]
			attributes[attrType] = decodeAttr
		default:
			ngapLog.Tracef("attribute type %x skipped\n", attrType)
		}
	}

	switch decodePkt.Subtype {
	case radius_message.AKA_CHALLENGE_SUBTYPE:
		ngapLog.Tracef("Subtype AKA-Challenge\n")
		if _, ok := attributes[radius_message.AT_MAC_ATTRIBUTE]; !ok {
			fmt.Println("I am in ngap handler aka challenge error 1")
			return nil, fmt.Errorf("AKA-Challenge attributes error")
		} else if _, ok := attributes[radius_message.AT_RAND_ATTRIBUTE]; !ok {
			fmt.Println("I am in ngap handler aka challenge error")
			return nil, fmt.Errorf("AKA-Challenge attributes error")
		} else if _, ok := attributes[radius_message.AT_AUTN_ATTRIBUTE]; !ok {
			fmt.Println("I am in ngap handler aka challenge error")
			return nil, fmt.Errorf("AKA-Challenge attributes error")
		}
	case radius_message.AKA_AUTHENTICATION_REJECT_SUBTYPE:
		ngapLog.Tracef("Subtype AKA-Authentication-Reject\n")
		if len(attributes) != 0 {
			return nil, fmt.Errorf("AKA-Authentication-Reject attributes error")
		}
	case radius_message.AKA_SYNCHRONIZATION_FAILURE_SUBTYPE:
		ngapLog.Tracef("Subtype AKA-Synchronization-Failure\n")
		if len(attributes) != 2 {
			return nil, fmt.Errorf("AKA-Synchornization-Failure attributes error")
		} else if _, ok := attributes[radius_message.AT_AUTS_ATTRIBUTE]; !ok {
			return nil, fmt.Errorf("AKA-Synchornization-Failure attributes error")
		} else if _, ok := attributes[radius_message.AT_KDF_ATTRIBUTE]; !ok {
			return nil, fmt.Errorf("AKA-Synchornization-Failure attributes error")
		} else if kdfVal := attributes[radius_message.AT_KDF_ATTRIBUTE].Value; !(kdfVal[0] == 0 && kdfVal[1] == 1) {
			return nil, fmt.Errorf("AKA-Synchornization-Failure attributes error")
		}
	case radius_message.AKA_NOTIFICATION_SUBTYPE:
		ngapLog.Tracef("Subtype AKA-Notification\n")
	case radius_message.AKA_CLIENT_ERROR_SUBTYPE:
		ngapLog.Tracef("Subtype AKA-Client-Error\n")
		if len(attributes) != 1 {
			return nil, fmt.Errorf("AKA-Client-Error attributes error")
		} else if _, ok := attributes[radius_message.AT_CLIENT_ERROR_CODE_ATTRIBUTE]; !ok {
			return nil, fmt.Errorf("AKA-Client-Error attributes error")
		}
	default:
		ngapLog.Tracef("subtype %x skipped\n", decodePkt.Subtype)
	}

	decodePkt.Attributes = attributes

	return &decodePkt, nil
}




