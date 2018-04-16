package handler

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	SNMPConfig "github.com/prometheus/snmp_exporter/config"
)

var (
	snmpExporter *SNMPExporter
	// Metrics about the SNMP exporter itself.
	snmpDuration = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "snmp_collection_duration_seconds",
			Help: "Duration of collections by the SNMP exporter",
		},
		[]string{"module"},
	)
	snmpRequestErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "snmp_request_errors_total",
			Help: "Errors in requests to the SNMP exporter",
		},
	)
)

func init() {
	snmpExporter = &SNMPExporter{}
	registHandler(snmpExporter)
}

// SNMPExporter 定义 SNMP的Exporter结构体
type SNMPExporter struct {
	C *SNMPConfig.Config
	sync.RWMutex
}

// GetName 实施 ExporterHandler接口
func (s *SNMPExporter) GetName() string {
	return "snmp_exporter"
}

func (s *SNMPExporter) snmpExporterHTTPHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "'target' parameter must be specified", 400)
		snmpRequestErrors.Inc()
		return
	}
	moduleName := r.URL.Query().Get("module")
	if moduleName == "" {
		moduleName = "if_mib"
	}
	s.RLock()
	module, ok := (*(s.C))[moduleName]
	s.RUnlock()
	if !ok {
		http.Error(w, fmt.Sprintf("Unkown module '%s'", moduleName), 400)
		snmpRequestErrors.Inc()
		return
	}
	log.Debugf("Scraping target '%s' with module '%s'", target, moduleName)

	start := time.Now()
	registry := prometheus.NewRegistry()
	collector := snmpCollector{target: target, module: module}
	registry.MustRegister(collector)
	// Delegate http serving to Promethues client library, which will call collector.Collect.
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
	duration := float64(time.Since(start).Seconds())
	snmpDuration.WithLabelValues(moduleName).Observe(duration)
	log.Debugf("Scrape of target '%s' with module '%s' took %f seconds", target, moduleName, duration)
}

// Handler 实施ExporterHandler接口
func (s *SNMPExporter) Handler(exporter *Exporter, m *mux.Router) error {
	m.HandleFunc(exporter.Path, s.snmpExporterHTTPHandler)
	return nil
}

// ConfigReader 读取配置文件并保存在ConfigMap中
func (s *SNMPExporter) ConfigReader(exporter *Exporter) error {
	conf, err := SNMPConfig.LoadFile(exporter.ConfigPath)
	if err != nil {
		return err
	}
	exporter.ConfigMap[exporter.Name] = conf
	s.C = conf
	return nil
}
