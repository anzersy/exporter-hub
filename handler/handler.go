package handler

import (
	"fmt"

	"github.com/gorilla/mux"
)

// RegistedHandler 用于保存注册的Handlers
var RegistedHandler = make(map[string]ExporterHander)

// Exporter 定义main.yml中exporter内的配置项目
type Exporter struct {
	Name       string `yaml:"name,omitempty"`
	Path       string `yaml:"path,omitempty"`
	Enable     bool   `yaml:"enable,omitempty"`
	ConfigPath string `yaml:"config_path,omitempty"`
	// map结构存储每个Exporter的配置实例指针
	ConfigMap map[string]interface{}
}

// readConfigFile 读取exporter的配置文件的内容
func (exporter *Exporter) readConfigFile(path string) error {
	exporter.ConfigMap = make(map[string]interface{})
	if rh, ok := RegistedHandler[exporter.Name]; ok {
		rh.ConfigReader(exporter)
	} else {
		return fmt.Errorf("[%s] Exporter no registered handler for read config", exporter.Name)
	}
	return nil
}

// ExporterHander 定义一个导入exporter的处理接口
type ExporterHander interface {
	ConfigReader(exporter *Exporter) error
	Handler(exporter *Exporter, m *mux.Router) error
	GetName() string
}

// registHandler 用于注册exporter handler
func registHandler(exporterHandler ExporterHander) {
	if RegistedHandler == nil {
		RegistedHandler = make(map[string]ExporterHander)
	}
	RegistedHandler[exporterHandler.GetName()] = exporterHandler
}

// Start 首先查询所有注册的对象的handler是否存在
// 如果存在则执行对应的handler function
func Start(handlerName string, exporter *Exporter, m *mux.Router) error {
	handler, ok := RegistedHandler[handlerName]
	if !ok {
		return fmt.Errorf("[%s] No registered handler", handlerName)
	}
	err := handler.Handler(exporter, m)
	if err != nil {
		return err
	}
	return nil
}
