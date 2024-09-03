package factoryN5CW

import (
	"encoding/hex"
	"fmt"
	"math/bits"
	"reflect"

	"github.com/asaskevich/govalidator"
	"github.com/davecgh/go-spew/spew"
	"github.com/free5gc/wagf/internal/logger"
	"github.com/sirupsen/logrus"
)

const (
	N5cwExpectedConfigVersion = "1.0.1"
)

type Config struct {
	Info          *Info          `yaml:"info" valid:"required"`
	Configuration *Configuration `yaml:"configuration" valid:"required"`
	Logger        *Logger        `yaml:"logger" valid:"optional"`
}

func (c *Config) Validate() (bool, error) {
	if info := c.Info; info != nil {
		if result, err := info.validate(); err != nil {
			return result, err
		}
	}

	if configuration := c.Configuration; configuration != nil {
		if result, err := configuration.validate(); err != nil {
			return result, err
		}
	}

	if logger := c.Logger; logger != nil {
		if result, err := logger.validate(); err != nil {
			return result, err
		}
	}

	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

func (c *Config) Print() {
	spew.Config.Indent = "\t"
	str := spew.Sdump(c.Configuration)
	logger.CfgLog.Infof("==================================================")
	logger.CfgLog.Infof("%s", str)
	logger.CfgLog.Infof("==================================================")
}

type Info struct {
	Version     string `yaml:"version" valid:"type(string),required"`
	Description string `yaml:"description" valid:"type(string),optional"`
}

func (i *Info) validate() (bool, error) {
	result, err := govalidator.ValidateStruct(i)
	return result, appendInvalid(err)
}

type Configuration struct {
	WAGFInfo WAGFInfo `yaml:"WAGFInformation" valid:"required"`
	N5CWInfo N5CWInfo `yaml:"N5CWInformation" valid:"required"`
}

func (c *Configuration) validate() (bool, error) {
	if result, err := c.N5CWInfo.validate(); err != nil {
		return result, err
	}
	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

type Logger struct {
	N5CW *LogSetting `yaml:"N5CW" valid:"optional"`
}

func (l *Logger) validate() (bool, error) {
	logger := reflect.ValueOf(l).Elem()
	for i := 0; i < logger.NumField(); i++ {
		if logSetting := logger.Field(i).Interface().(*LogSetting); logSetting != nil {
			result, err := logSetting.validate()
			return result, err
		}
	}

	result, err := govalidator.ValidateStruct(l)
	return result, err
}

type LogSetting struct {
	DebugLevel   string `yaml:"debugLevel" valid:"debugLevel"`
	ReportCaller bool   `yaml:"ReportCaller" valid:"type(bool)"`
}

func (l *LogSetting) validate() (bool, error) {
	govalidator.TagMap["debugLevel"] = govalidator.Validator(func(str string) bool {
		if str == "panic" || str == "fatal" || str == "error" || str == "warn" ||
			str == "info" || str == "debug" || str == "trace" {
			return true
		} else {
			return false
		}
	})

	result, err := govalidator.ValidateStruct(l)
	return result, err
}

type WAGFInfo struct {
	IPSecIfaceAddr string `yaml:"IPSecIfaceAddr" valid:"host,required"`
	IPsecInnerAddr string `yaml:"IPsecInnerAddr" valid:"host,required"`
}

type N5CWInfo struct {
	IMSI           IMSI         `yaml:"IMSI" valid:"required"`
	AMFID          string       `yaml:"AMFID" valid:"hexadecimal,required"`
	IPSecIfaceName string       `yaml:"IPSecIfaceName" valid:"stringlength(1|10),required"`
	IPSecIfaceAddr string       `yaml:"IPSecIfaceAddr" valid:"host,required"`
	DnIPAddr       string       `yaml:"DnIPAddr" valid:"host,optional"`
	XfrmiId        uint32       `yaml:"XfrmiId" valid:"numeric,required"`
	XfrmiName      string       `yaml:"XfrmiName" valid:"stringlength(1|10),required"`
	GreIfaceName   string       `yaml:"GreIfaceName" valid:"stringlength(1|10),required"`
	IkeSaSPI       uint64       `yaml:"IkeSaSPI" valid:"hexadecimal,required"`
	IPSecSaCpSPI   uint32       `yaml:"IPSecSA3gppControlPlaneSPI" valid:"hexadecimal,required"`
	SmPolicy       []PolicyItem `yaml:"SmPolicy" valid:"required"`
	Security       Security     `yaml:"Security" valid:"required"`
}

func (i *N5CWInfo) validate() (bool, error) {
	for _, policyItem := range i.SmPolicy {
		if result, err := policyItem.validate(); err != nil {
			return result, err
		}
	}
	result, err := govalidator.ValidateStruct(i)
	return result, appendInvalid(err)
}

type PLMN struct {
	MCC string `yaml:"MCC" valid:"numeric,stringlength(3|3),required"`
	MNC string `yaml:"MNC" valid:"numeric,stringlength(2|3),required"`
}

type IMSI struct {
	PLMN PLMN   `yaml:"PLMNID" valid:"required"`
	MSIN string `yaml:"MSIN" valid:"numeric,stringlength(1|10),required"`
}

type Security struct {
	K    string `yaml:"K" valid:"hexadecimal,required"`
	RAND string `yaml:"RAND" valid:"hexadecimal,required"`
	SQN  string `yaml:"SQN" valid:"hexadecimal,required"`
	AMF  string `yaml:"AMF" valid:"hexadecimal,required"`
	OP   string `yaml:"OP" valid:"hexadecimal,required"`
	OPC  string `yaml:"OPC" valid:"hexadecimal,required"`
}

type PolicyItem struct {
	DNN    string `yaml:"DNN" valid:"type(string),required"`
	SNSSAI SNSSAI `yaml:"SNSSAI" valid:"required"`
}

func (p *PolicyItem) validate() (bool, error) {
	result, err := govalidator.ValidateStruct(p)
	return result, appendInvalid(err)
}

type SNSSAI struct {
	SST string `yaml:"SST" valid:"hexadecimal,stringlength(1|1),required"`
	SD  string `yaml:"SD,omitempty" valid:"hexadecimal,stringlength(6|6),required"`
}

func (s *SNSSAI) ToBytes() ([]byte, error) {
	bytes := make([]byte, 4)
	bytes[0] = hexCharToByte(s.SST[0])
	sd, err := hex.DecodeString(s.SD)
	if err != nil {
		return nil, err
	}
	copy(bytes[1:], sd)
	return bytes, nil
}

func (c *Config) GetAMFID() ([]byte, error) {
	amfId := c.Configuration.N5CWInfo.AMFID
	amfIdBytes, err := hex.DecodeString(amfId)
	if err != nil {
		return nil, err
	}
	return amfIdBytes, nil
}

func (c *Config) GetSNN() string {
	mcc := c.Configuration.N5CWInfo.IMSI.PLMN.MCC
	mnc := c.Configuration.N5CWInfo.IMSI.PLMN.MNC
	if len(c.Configuration.N5CWInfo.IMSI.PLMN.MNC) == 2 {
		mnc = "0" + mnc
	}

	return fmt.Sprintf("5G:mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
}

func (c *Config) GetSUPI() string {
	imsi := c.Configuration.N5CWInfo.IMSI
	return fmt.Sprintf("imsi-%s%s%s", imsi.PLMN.MCC, imsi.PLMN.MNC, imsi.MSIN)
}

// TS 24.501 9.11.3.4
func (c *Config) BuildMSIN() []byte {

	var msinBytes []byte
	msin := c.Configuration.N5CWInfo.IMSI.MSIN

	for i := 0; i < len(msin); i += 2 {
		msinBytes = append(msinBytes, 0x0)
		j := len(msinBytes) - 1
		if i+1 == len(msin) {
			msinBytes[j] = 0xf<<4 | hexCharToByte(msin[i])
		} else {
			msinBytes[j] = hexCharToByte(msin[i+1])<<4 | hexCharToByte(msin[i])
		}
	}

	return msinBytes
}

func (c *Config) BuildPLMN() []byte {
	plmn := c.Configuration.N5CWInfo.IMSI.PLMN
	plmnBytes := make([]byte, 3)

	plmnBytes[0] = hexCharToByte(plmn.MCC[0]) | bits.RotateLeft8(hexCharToByte(plmn.MCC[1]), 4)

	if len(plmn.MNC) == 2 {
		plmnBytes[1] = hexCharToByte(plmn.MCC[2]) | 0xf0
		plmnBytes[2] = hexCharToByte(plmn.MNC[0]) | bits.RotateLeft8(hexCharToByte(plmn.MNC[1]), 4)
	} else {
		plmnBytes[1] = hexCharToByte(plmn.MCC[2]) | bits.RotateLeft8(hexCharToByte(plmn.MNC[0]), 4)
		plmnBytes[2] = hexCharToByte(plmn.MNC[1]) | hexCharToByte(plmn.MNC[2])
	}

	return plmnBytes
}

func hexCharToByte(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}

	return 0
}

func (c *Config) SetLogLevel() {
	if c.Logger == nil {
		logger.CfgLog.Warnln("N5CW config without log level setting!!!")
		return
	}

	if c.Logger.N5CW != nil {
		if c.Logger.N5CW.DebugLevel != "" {
			if level, err := logrus.ParseLevel(c.Logger.N5CW.DebugLevel); err != nil {
				logger.CfgLog.Warnf("N5CW Log level [%s] is invalid, set to [info] level",
					c.Logger.N5CW.DebugLevel)
				logger.SetLogLevel(logrus.InfoLevel)
			} else {
				logger.CfgLog.Infof("N5CW Log level is set to [%s] level", level)
				logger.SetLogLevel(level)
			}
		} else {
			logger.CfgLog.Warnln("N5CW Log level not set. Default set to [info] level")
			logger.SetLogLevel(logrus.InfoLevel)
		}
		logger.SetReportCaller(c.Logger.N5CW.ReportCaller)
	}
}

func appendInvalid(err error) error {
	var errs govalidator.Errors

	if err == nil {
		return nil
	}

	es := err.(govalidator.Errors).Errors()
	for _, e := range es {
		errs = append(errs, fmt.Errorf("Invalid %w", e))
	}

	return error(errs)
}

func (c *Config) GetVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}
