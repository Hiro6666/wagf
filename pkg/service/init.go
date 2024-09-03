package service

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"github.com/vishvananda/netlink"

	aperLogger "github.com/free5gc/aper/logger"
	ngapLogger "github.com/free5gc/ngap/logger"
	"github.com/free5gc/wagf/internal/logger"
	ngap_service "github.com/free5gc/wagf/internal/ngap/service"
	nwtcp_service "github.com/free5gc/wagf/internal/nwtcp/service"
	nwtup_service "github.com/free5gc/wagf/internal/nwtup/service"
	"github.com/free5gc/wagf/internal/util"
	"github.com/free5gc/wagf/pkg/context"
	dhcp_service "github.com/free5gc/wagf/pkg/dhcp/service"
	"github.com/free5gc/wagf/pkg/factory"
	ike_service "github.com/free5gc/wagf/pkg/ike/service"
	"github.com/free5gc/wagf/pkg/ike/xfrm"
	radius_service "github.com/free5gc/wagf/pkg/radius/service"
)

type WAGF struct{}

type (
	// Commands information.
	Commands struct {
		config string
	}
)

var commands Commands

var cliCmd = []cli.Flag{
	cli.StringFlag{
		Name:  "config, c",
		Usage: "Load configuration from `FILE`",
	},
	cli.StringFlag{
		Name:  "log, l",
		Usage: "Output NF log to `FILE`",
	},
	cli.StringFlag{
		Name:  "log5gc, lc",
		Usage: "Output free5gc log to `FILE`",
	},
}

func (*WAGF) GetCliCmd() (flags []cli.Flag) {
	return cliCmd
}

func (wagf *WAGF) Initialize(c *cli.Context) error {
	commands = Commands{
		config: c.String("config"),
	}

	// if cmd line params contain 'config', then go to InitConfigFactory
	if commands.config != "" {
		if err := factory.InitConfigFactory(commands.config); err != nil {
			return err
		}
	} else { // if cmd line params doesn't contain 'config', then use default config path = './config/wagfcfg.yaml'
		if err := factory.InitConfigFactory(util.WagfDefaultConfigPath); err != nil {
			return err
		}
	}
	wagf.SetLogLevel()

	if err := factory.CheckConfigVersion(); err != nil {
		return err
	}

	// verify config file validation
	if _, err := factory.WagfConfig.Validate(); err != nil {
		return err
	}

	return nil
}

// set log level
// DebugLevel: how detailed to output, value: trace, debug, info, warn, error, fatal, panic
// ReportCaller: enable the caller report or not, value: true or false
func (wagf *WAGF) SetLogLevel() {
	if factory.WagfConfig.Logger == nil {
		logger.InitLog.Warnln("wagf config without log level setting!!!")
		return
	}

	if factory.WagfConfig.Logger.WAGF != nil {
		// Set DebugLevel, default: infolevel
		if factory.WagfConfig.Logger.WAGF.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.WagfConfig.Logger.WAGF.DebugLevel); err != nil {
				logger.InitLog.Warnf("wagf Log level [%s] is invalid, set to [info] level",
					factory.WagfConfig.Logger.WAGF.DebugLevel)
				logger.SetLogLevel(logrus.InfoLevel)
			} else {
				logger.InitLog.Infof("wagf Log level is set to [%s] level", level)
				logger.SetLogLevel(level)
			}
		} else {
			logger.InitLog.Infoln("wagf Log level is default set to [info] level")
			logger.SetLogLevel(logrus.InfoLevel)
		}
		// Set report caller
		logger.SetReportCaller(factory.WagfConfig.Logger.WAGF.ReportCaller)
	}

	if factory.WagfConfig.Logger.NGAP != nil {
		if factory.WagfConfig.Logger.NGAP.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.WagfConfig.Logger.NGAP.DebugLevel); err != nil {
				ngapLogger.NgapLog.Warnf("NGAP Log level [%s] is invalid, set to [info] level",
					factory.WagfConfig.Logger.NGAP.DebugLevel)
				ngapLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				ngapLogger.SetLogLevel(level)
			}
		} else {
			ngapLogger.NgapLog.Warnln("NGAP Log level not set. Default set to [info] level")
			ngapLogger.SetLogLevel(logrus.InfoLevel)
		}
		ngapLogger.SetReportCaller(factory.WagfConfig.Logger.NGAP.ReportCaller)
	}

	if factory.WagfConfig.Logger.Aper != nil {
		if factory.WagfConfig.Logger.Aper.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.WagfConfig.Logger.Aper.DebugLevel); err != nil {
				aperLogger.AperLog.Warnf("Aper Log level [%s] is invalid, set to [info] level",
					factory.WagfConfig.Logger.Aper.DebugLevel)
				aperLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				aperLogger.SetLogLevel(level)
			}
		} else {
			aperLogger.AperLog.Warnln("Aper Log level not set. Default set to [info] level")
			aperLogger.SetLogLevel(logrus.InfoLevel)
		}
		aperLogger.SetReportCaller(factory.WagfConfig.Logger.Aper.ReportCaller)
	}
}

func (wagf *WAGF) FilterCli(c *cli.Context) (args []string) {
	for _, flag := range wagf.GetCliCmd() {
		name := flag.GetName()
		value := fmt.Sprint(c.Generic(name))
		if value == "" {
			continue
		}

		args = append(args, "--"+name, value)
	}
	return args
}

func (wagf *WAGF) Start() {
	logger.InitLog.Infoln("Server started")

	// set wagf basic info
	if !util.InitWAGFContext() {
		logger.InitLog.Error("Initicating context failed")
		return
	}

	// create XFRM interface
	// if err := wagf.InitDefaultXfrmInterface(); err != nil {
	// 	logger.InitLog.Errorf("Initicating XFRM interface for control plane failed: %+v", err)
	// 	return
	// }

	// Graceful Shutdown
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		<-signalChannel // if receive os.Interrupt, syscall.SIGTERM, wagf terminate
		wagf.Terminate()
		// Waiting for negotiatioon with netlink for deleting interfaces
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()

	wg := sync.WaitGroup{}

	// NGAP
	if err := ngap_service.Run(); err != nil {
		logger.InitLog.Errorf("Start NGAP service failed: %+v", err)
		return
	}
	logger.InitLog.Info("NGAP service running.")
	wg.Add(1)

	// Relay listeners
	// Control plane
	if err := nwtcp_service.Run(); err != nil {
		logger.InitLog.Errorf("Listen NWt control plane traffic failed: %+v", err)
		return
	}
	logger.InitLog.Info("NAS TCP server successfully started.")
	wg.Add(1)

	// User plane
	if err := nwtup_service.Run(); err != nil {
		logger.InitLog.Errorf("Listen NWt user plane traffic failed: %+v", err)
		return
	}
	logger.InitLog.Info("Listening NWt user plane traffic")
	wg.Add(1)

	// IKE
	if err := ike_service.Run(); err != nil {
		logger.InitLog.Errorf("Start IKE service failed: %+v", err)
		return
	}
	logger.InitLog.Info("IKE service running.")
	wg.Add(1)

	// Radius
	if err := radius_service.Run(); err != nil {
		logger.InitLog.Errorf("Start Radius service failed: %+v", err)
		return
	}
	logger.InitLog.Info("Radius service running.")
	wg.Add(1)

	// DHCP
	if err := dhcp_service.Run(); err != nil {
		logger.InitLog.Errorf("Start DHCP service failed: %+v", err)
		return
	}
	logger.InitLog.Info("DHCP service running.")
	wg.Add(1)

	logger.InitLog.Info("WAGF running...")

	wg.Wait()
}

func (wagf *WAGF) InitDefaultXfrmInterface() error {
	wagfContext := context.WAGFSelf()
	fmt.Println("in my init.go wagfContext", &wagfContext)

	// Setup default IPsec interface for Control Plane
	var linkIPSec netlink.Link
	var err error
	wagfIPAddr := net.ParseIP(wagfContext.IPSecGatewayAddress).To4()
	wagfIPAddrAndSubnet := net.IPNet{IP: wagfIPAddr, Mask: wagfContext.Subnet.Mask}
	newXfrmiName := fmt.Sprintf("%s-default", wagfContext.XfrmIfaceName)

	if linkIPSec, err = xfrm.SetupIPsecXfrmi(newXfrmiName, wagfContext.XfrmParentIfaceName,
		wagfContext.XfrmIfaceId, wagfIPAddrAndSubnet); err != nil {
		logger.InitLog.Errorf("Setup XFRM interface %s fail: %+v", newXfrmiName, err)
		return err
	}

	route := &netlink.Route{
		LinkIndex: linkIPSec.Attrs().Index,
		Dst:       wagfContext.Subnet,
	}

	// Add new rule to linux OS
	if err := netlink.RouteAdd(route); err != nil {
		logger.InitLog.Warnf("netlink.RouteAdd: %+v", err)
	}

	logger.InitLog.Infof("Setup XFRM interface %s ", newXfrmiName)

	wagfContext.XfrmIfaces.LoadOrStore(wagfContext.XfrmIfaceId, linkIPSec)
	wagfContext.XfrmIfaceIdOffsetForUP = 1

	return nil
}

func (wagf *WAGF) RemoveIPsecInterfaces() {
	wagfSelf := context.WAGFSelf()
	wagfSelf.XfrmIfaces.Range(
		func(key, value interface{}) bool {
			iface := value.(netlink.Link)
			if err := netlink.LinkDel(iface); err != nil {
				logger.InitLog.Errorf("Delete interface %s fail: %+v", iface.Attrs().Name, err)
			} else {
				logger.InitLog.Infof("Delete interface: %s", iface.Attrs().Name)
			}
			return true
		})
}

func (wagf *WAGF) Terminate() {
	logger.InitLog.Info("Terminating wagf...")
	logger.InitLog.Info("Deleting interfaces created by wagf")
	wagf.RemoveIPsecInterfaces()
	logger.InitLog.Info("wagf terminated")
}

func (wagf *WAGF) Exec(c *cli.Context) error {
	// wagf.Initialize(cfgPath, c)

	logger.InitLog.Traceln("args:", c.String("wagfcfg"))
	args := wagf.FilterCli(c)
	logger.InitLog.Traceln("filter: ", args)
	command := exec.Command("./wagf", args...)

	wg := sync.WaitGroup{}
	wg.Add(3)

	stdout, err := command.StdoutPipe()
	if err != nil {
		logger.InitLog.Fatalln(err)
	}
	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		in := bufio.NewScanner(stdout)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	stderr, err := command.StderrPipe()
	if err != nil {
		logger.InitLog.Fatalln(err)
	}
	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		in := bufio.NewScanner(stderr)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		if errCom := command.Start(); errCom != nil {
			logger.InitLog.Errorf("wagf start error: %v", errCom)
		}
		wg.Done()
	}()

	wg.Wait()

	return err
}
