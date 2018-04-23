package handler

import (
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/prometheus/common/log"
	"gopkg.in/yaml.v2"
)

// Config 定义main.yml中的配置信息结构体
type Config struct {
	Server    string      `yaml:"server"`
	Port      string      `yaml:"port"`
	Exporters []*Exporter `yaml:"exporters"`
}

// SafeConfig 定义一个线程安全访问的Config操作对象
type SafeConfig struct {
	sync.RWMutex
	C *Config
}

// ReloadConfig 读取主配置文件main.yml并导入到项目中
func (sc *SafeConfig) ReloadConfig(configFile string) (err error) {
	var c = &Config{}
	yamlFile, err := ioutil.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("Error reading config file:%s", err)
	}
	if err := yaml.Unmarshal(yamlFile, c); err != nil {
		return fmt.Errorf("Error parsing config file: %s", err)
	}
	sc.Lock()
	defer sc.Unlock()
	sc.C = c
	return sc.C.getConfigByName()
}

// getConfigByName 遍历主配置main.yml中exporters的内容
// 如果exporter的enable状态为true，那么读取该exporter的配置文件
// 否则不执行任何操作
func (c *Config) getConfigByName() error {
	for _, exporter := range c.Exporters {
		if exporter.Enable == true {
			log.Infof("[%s] Load enabled exporter ", exporter.Name)
		}
		if exporter.ConfigPath != "" && exporter.Enable == true {
			// 实际读取配置依赖于接口的不同的实现
			err := exporter.readConfigFile(exporter.ConfigPath)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
