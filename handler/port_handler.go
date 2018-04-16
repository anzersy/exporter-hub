package handler

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	yaml "gopkg.in/yaml.v2"
)

const (
	namespace      = "portprobe"
	defaultTimeout = 10
)

var portProbeExporter *LocalPortExporter

func init() {
	portProbeExporter = NewPortProbeExporter()
	registHandler(portProbeExporter)
}

// PortExporterConfig for Port exporter config
type PortExporterConfig struct {
	Probe   string `yaml:"probe,omitempty" json:"probe"`
	Status  string `yaml:"status,omitempty" json:"status"`
	Timeout int    `yaml:"timeout,omitempty" json:"timeout"`
}

// ReadPortExporterConfig read config file and return config struct
func ReadPortExporterConfig(path string) (*PortExporterConfig, error) {
	config := PortExporterConfig{}
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(content, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// LocalPortExporter 定义port-exporter结构体
// 属性C包含了port-exporter的所有配置内容
type LocalPortExporter struct {
	mutex           sync.RWMutex
	duration, error prometheus.Gauge
	totalScrapes    prometheus.Counter
	metrics         map[string]prometheus.Gauge
	C               *PortExporterConfig
}

// NewPortProbeExporter 创建一个新的LocalPortExporter对象
func NewPortProbeExporter() *LocalPortExporter {
	return &LocalPortExporter{
		duration: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "exporter_last_scrape_duration_seconds",
			Help:      "The last scrape duration.",
		}),
		error: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "exporter_last_scrape_error",
			Help:      "The last scrape error status.",
		}),
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "exporter_scrapes_total",
			Help:      "Current total port probe scrapes.",
		}),
		metrics: map[string]prometheus.Gauge{},
	}
}

// Describe 导入数据指标描述
func (e *LocalPortExporter) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range e.metrics {
		m.Describe(ch)
	}
	ch <- e.duration.Desc()
	ch <- e.totalScrapes.Desc()
	ch <- e.error.Desc()
}

// Collect 定义实际进行的抓取和收集数据
func (e *LocalPortExporter) Collect(ch chan<- prometheus.Metric) {
	scrapes := make(chan []string)
	go e.scrape(scrapes)

	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.setMetrics(scrapes)
	ch <- e.duration
	ch <- e.totalScrapes
	ch <- e.error
	e.collectMetrics(ch)
}

func (e *LocalPortExporter) scrape(scrapes chan<- []string) {
	defer close(scrapes)
	now := time.Now().UnixNano()
	var wg sync.WaitGroup
	e.error.Set(0)
	entries := strings.Split((e.C).Probe, ",")
	if e.C.Timeout == 0 {
		e.C.Timeout = defaultTimeout
	}
	dialer := net.Dialer{Timeout: time.Duration(e.C.Timeout) * time.Second}
	for _, addr := range entries {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			host, port, err := net.SplitHostPort(strings.Replace(addr, " ", "", -1))
			if err == nil {
				res := make([]string, 2)
				if len(host) == 0 {
					host = "0.0.0.0"
				}
				res[0] = strings.Replace(host, ".", "_", -1) + "_" + port

				check := time.Now().UnixNano()

				// todo open port here
				conn, err := dialer.Dial("tcp", host+":"+port)
				if err == nil {
					conn.Close()

					if strings.EqualFold(e.C.Status, "0") {
						res[1] = strconv.FormatFloat(float64(time.Now().UnixNano()-check/1000000000), 'f', -1, 64)
					} else {
						res[1] = e.C.Status
					}

					scrapes <- res
				} else {
					e.error.Inc()
				}
			} else {
				e.error.Inc()
			}
		}(addr)
	}

	wg.Wait()

	e.duration.Set(float64(time.Now().UnixNano()-now) / 1000000000)
}

func (e *LocalPortExporter) setMetrics(scrapes <-chan []string) {
	for row := range scrapes {
		name := strings.ToLower(row[0])
		value, err := strconv.ParseInt(row[1], 10, 64)
		if err != nil {
			// convert/serve text values here ?
			continue
		}

		if _, ok := e.metrics[name]; !ok {
			e.metrics[name] = prometheus.NewGauge(prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      name,
				Help:      "default",
			})
		}

		e.metrics[name].Set(float64(value))
	}
}

func (e *LocalPortExporter) collectMetrics(metrics chan<- prometheus.Metric) {
	for _, m := range e.metrics {
		m.Collect(metrics)
	}
}

// GetName 实施 ExporterHandler接口
func (e *LocalPortExporter) GetName() string {
	return "port_exporter"
}

func (e *LocalPortExporter) portExporterHTTPHandler(w http.ResponseWriter, r *http.Request) {

	registry := prometheus.NewRegistry()
	err := registry.Register(e)
	if err != nil {
		log.Errorln("[port_exporter] Couldn't register port exporter:", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("[port_exporter]Couldn't register port exporter: %s", err)))
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

// Handler 实施ExporterHandler接口
func (e *LocalPortExporter) Handler(exporter *Exporter, m *mux.Router) error {
	if c, ok := exporter.ConfigMap[exporter.Name]; ok {
		e.C = c.(*PortExporterConfig)
		m.HandleFunc(exporter.Path, e.portExporterHTTPHandler)
		return nil
	}
	return fmt.Errorf("[port_exporter] Handler func no config define for %s", exporter.Name)
}

// ConfigReader 读取配置文件并保存在ConfigMap中
func (e *LocalPortExporter) ConfigReader(exporter *Exporter) error {
	c, err := ReadPortExporterConfig(exporter.ConfigPath)
	if err != nil {
		return err
	}
	exporter.ConfigMap[exporter.Name] = c
	return nil
}
