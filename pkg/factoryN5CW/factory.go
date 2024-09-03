package factoryN5CW

import (
	"errors"
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v3"

	"github.com/free5gc/wagf/internal/logger"
)

var N5cwConfig Config
var filePath string

// read Config file
func InitConfigFactory(f string) error {
	filePath = f
	if content, err := ioutil.ReadFile(filePath); err != nil {
		logger.CfgLog.Errorf("read file error")
		return err
	} else {
		N5cwConfig = Config{}

		if yamlErr := yaml.Unmarshal(content, &N5cwConfig); yamlErr != nil {
			return yamlErr
		}
		if err := checkConfigVersion(); err != nil {
			logger.CfgLog.Errorf("Init Config Fail: %+v", err)
		}
		N5cwConfig.SetLogLevel()
	}
	return nil
}

func WriteConfigWithKey(key, value string) error {
	var (
		data []byte
		err  error
		root yaml.Node
	)

	if data, err = ioutil.ReadFile(filePath); err != nil {
		return err
	}

	// yaml format -> go struct format
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}

	if ptr := findNodePtrWithKey(&root, key); ptr != nil {
		ptr.Value = value
	} else {
		return errors.New("There's no value with the key")
	}

	if data, err = yaml.Marshal(&root); err != nil {
		return err
	}

	if err := ioutil.WriteFile(filePath, data, 0); err != nil {
		return err
	}

	return nil
}

// Trace yaml node tree with DFS and return the pointer of node with the key
func findNodePtrWithKey(node *yaml.Node, key string) *yaml.Node {
	for i := range node.Content {
		if node.Content[i].Value == key {
			// A pair of key and value are located at same Content *[]yaml.Node
			return node.Content[i+1]
		}
		if ptr := findNodePtrWithKey(node.Content[i], key); ptr != nil {
			return ptr
		}
	}
	return nil
}

func checkConfigVersion() error {
	currentVersion := N5cwConfig.GetVersion()

	if currentVersion != N5cwExpectedConfigVersion {
		return fmt.Errorf("config version is [%s], but expected is [%s].",
			currentVersion, N5cwExpectedConfigVersion)
	}

	logger.CfgLog.Infof("config version [%s]", currentVersion)

	return nil
}
