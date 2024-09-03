package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/asaskevich/govalidator"
	"github.com/urfave/cli"

	"github.com/free5gc/util/version"
	"github.com/free5gc/wagf/internal/logger"
	"github.com/free5gc/wagf/pkg/service"
)

var wagf = &service.WAGF{}

func main() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.AppLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	app := cli.NewApp()
	app.Name = "WAGF"
	app.Usage = "Wireline Access Gateway Function (WAGF)"
	app.Action = action
	app.Flags = wagf.GetCliCmd()
	if err := app.Run(os.Args); err != nil {
		logger.AppLog.Errorf("WAGF Run Error: %v\n", err)
	}
}

func action(c *cli.Context) error {
	// if err := initLogFile(c.String("log"), c.String("log5gc")); err != nil {
	if err := initLogFile(c.String("log"), "log5gc.log"); err != nil {
		logger.AppLog.Errorf("%+v", err)
		return err
	}

	if err := wagf.Initialize(c); err != nil { // read yaml file and turn the params to struct
		switch errType := err.(type) {
		case govalidator.Errors:
			validErrs := err.(govalidator.Errors).Errors()
			for _, validErr := range validErrs {
				logger.CfgLog.Errorf("%+v", validErr)
			}
		default:
			logger.CfgLog.Errorf("%+v", errType)
		}
		logger.CfgLog.Errorf("[-- PLEASE REFER TO SAMPLE CONFIG FILE COMMENTS --]")
		return fmt.Errorf("Failed to initialize !!")
	}

	logger.AppLog.Infoln(c.App.Name)
	logger.AppLog.Infoln("wagf version: ", version.GetVersion())

	wagf.Start() // wagf server started!

	return nil
}

func initLogFile(logNfPath string, log5gcPath string) error {
	if err := logger.LogFileHook(logNfPath, log5gcPath); err != nil {
		return err
	}
	return nil
}
