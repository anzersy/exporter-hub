package handler

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/node_exporter/collector"
)

var nodeExporter = NodeExporter{}

func init() {
	registHandler(&nodeExporter)
}

// NodeExporter 定义一个满足handler接口的结构体
type NodeExporter struct{}

// GetName implement ExporterHandler interface
// to return the name of exporter
func (node *NodeExporter) GetName() string {
	return "node_exporter"
}

// ConfigReader 读取配置文件并保存在ConfigMap中
// 如果不需要读取配置的话则直接返回即可
func (node *NodeExporter) ConfigReader(exporter *Exporter) error {
	// no config file to read
	return nil
}

// NewNodeHandler 创建一个处理node的web handler
func NewNodeHandler() func(w http.ResponseWriter, r *http.Request) {
	nc, err := collector.NewNodeCollector()
	if err != nil {
		log.Fatalf("[node_exporter] Couldn't create collector: %s", err)
	}
	collectors := []string{}
	for n := range nc.Collectors {
		collectors = append(collectors, n)
	}
	log.Infof("[node_exporter] Load %d node exporter collectors", len(collectors))
	return func(w http.ResponseWriter, r *http.Request) {
		filters := r.URL.Query()["collect[]"]
		log.Debugln("[node_exporter] collect query:", filters)
		nc, err := collector.NewNodeCollector(filters...)
		if err != nil {
			log.Warnln("[node_exporter] Couldn't create", err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("[node_exporter] Couldn't create %s", err)))
			return
		}

		registry := prometheus.NewRegistry()
		err = registry.Register(nc)
		if err != nil {
			log.Errorln("[node_exporter] Couldn't register collector:", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("[node_exporter] Couldn't register collector: %s", err)))
			return
		}

		gatherers := prometheus.Gatherers{
			prometheus.DefaultGatherer,
			registry,
		}
		// Delegate http serving to Prometheus client library, which will call collector.Collect.
		h := promhttp.InstrumentMetricHandler(
			registry,
			promhttp.HandlerFor(gatherers,
				promhttp.HandlerOpts{
					ErrorLog:      log.NewErrorLogger(),
					ErrorHandling: promhttp.ContinueOnError,
				}),
		)
		h.ServeHTTP(w, r)
	}
}

// Handler 实施 ExporterHandler接口
func (node *NodeExporter) Handler(exporter *Exporter, m *mux.Router) error {
	nodeHandler := NewNodeHandler()
	m.HandleFunc(exporter.Path, nodeHandler)
	return nil
}
