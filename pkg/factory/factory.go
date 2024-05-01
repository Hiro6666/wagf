/*
 * wagf Configuration Factory
 */

package factory

import (
	"fmt"
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"

	"github.com/free5gc/wagf/internal/logger"
)

var WagfConfig Config

// TODO: Support configuration update from REST api
func InitConfigFactory(f string) error {
	if content, err := ioutil.ReadFile(f); err != nil {
		return err
	} else {
		WagfConfig = Config{}

		if yamlErr := yaml.Unmarshal(content, &WagfConfig); yamlErr != nil {
			return yamlErr
		}
	}

	return nil
}

func CheckConfigVersion() error {
	currentVersion := WagfConfig.GetVersion()

	if currentVersion != WagfExpectedConfigVersion {
		return fmt.Errorf("config version is [%s], but expected is [%s].",
			currentVersion, WagfExpectedConfigVersion)
	}

	logger.CfgLog.Infof("config version [%s]", currentVersion)

	return nil
}
