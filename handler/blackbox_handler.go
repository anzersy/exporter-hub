package handler

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/gorilla/mux"
	"github.com/prometheus/blackbox_exporter/config"
	blackboxConfig "github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/blackbox_exporter/prober"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v2"
)

var (
	blackBoxExporter = BlackBoxExporter{}
	// Probers 定义注册的probe执行函数
	Probers = map[string]prober.ProbeFn{
		"http": prober.ProbeHTTP,
		"tcp":  prober.ProbeTCP,
		"icmp": prober.ProbeICMP,
		"dns":  prober.ProbeDNS,
	}
)

func init() {
	registHandler(&blackBoxExporter)
}

// BlackBoxExporter 定义一个满足handler接口的结构体
type BlackBoxExporter struct{}

// GetName 实施 ExporterHandler接口
func (blackbox *BlackBoxExporter) GetName() string {
	return "blackbox_exporter"
}

type scrapeLogger struct {
	next         log.Logger
	module       string
	target       string
	buffer       bytes.Buffer
	bufferLogger log.Logger
}

func newScrapeLogger(logger log.Logger, module string, target string) *scrapeLogger {
	logger = log.With(logger, "module", module, "target", target)
	sl := &scrapeLogger{
		next:   logger,
		buffer: bytes.Buffer{},
	}
	bl := log.NewLogfmtLogger(&sl.buffer)
	sl.bufferLogger = log.With(bl, "ts", log.DefaultTimestampUTC, "caller", log.Caller(6), "module", module, "target", target)
	return sl
}

func (sl scrapeLogger) Log(keyvals ...interface{}) error {
	sl.bufferLogger.Log(keyvals...)
	kvs := make([]interface{}, len(keyvals))
	copy(kvs, keyvals)
	// Switch level to debug for application output.
	for i := 0; i < len(kvs); i += 2 {
		if kvs[i] == level.Key() {
			kvs[i+1] = level.DebugValue()
		}
	}
	return sl.next.Log(kvs...)
}

// DebugOutput Returns plaintext debug output for a probe.
func DebugOutput(module *config.Module, logBuffer *bytes.Buffer, registry *prometheus.Registry) string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "Logs for the probe:\n")
	logBuffer.WriteTo(buf)
	fmt.Fprintf(buf, "\n\n\nMetrics that would have been returned:\n")
	mfs, err := registry.Gather()
	if err != nil {
		fmt.Fprintf(buf, "[blackbox_exporter] Error gathering metrics: %s\n", err)
	}
	for _, mf := range mfs {
		expfmt.MetricFamilyToText(buf, mf)
	}
	fmt.Fprintf(buf, "\n\n\nModule configuration:\n")
	c, err := yaml.Marshal(module)
	if err != nil {
		fmt.Fprintf(buf, "[blackbox_exporter] Error marshalling config: %s\n", err)
	}
	buf.Write(c)

	return buf.String()
}

// NewBlackboxHandler 返回一个执行的blackbox web handler实例
func NewBlackboxHandler(c *config.Config, logger log.Logger) func(w http.ResponseWriter, r *http.Request) {
	rh := &resultHistory{maxResults: 100}
	probeSuccessGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_success",
		Help: "Displays whether or not the probe was a success",
	})
	probeDurationGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_duration_seconds",
		Help: "Returns how long the probe took to complete in seconds",
	})

	return func(w http.ResponseWriter, r *http.Request) {
		moduleName := r.URL.Query().Get("module")
		if moduleName == "" {
			moduleName = "http_2xx"
		}
		module, ok := c.Modules[moduleName]
		if !ok {
			http.Error(w, fmt.Sprintf("Unknown module %q", moduleName), http.StatusBadRequest)
			return
		}

		// If a timeout is configured via the Prometheus header, add it to the request.
		var timeoutSeconds float64
		if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
			var err error
			timeoutSeconds, err = strconv.ParseFloat(v, 64)
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to parse timeout from Prometheus header: %s", err), http.StatusInternalServerError)
				return
			}
		}
		if timeoutSeconds == 0 {
			timeoutSeconds = 10
		}

		if module.Timeout.Seconds() < timeoutSeconds && module.Timeout.Seconds() > 0 {
			timeoutSeconds = module.Timeout.Seconds()
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds*float64(time.Second)))
		defer cancel()
		r = r.WithContext(ctx)

		params := r.URL.Query()
		target := params.Get("target")
		if target == "" {
			http.Error(w, "Target parameter is missing", http.StatusBadRequest)
			return
		}

		prober, ok := Probers[module.Prober]
		if !ok {
			http.Error(w, fmt.Sprintf("Unknown prober %q", module.Prober), http.StatusBadRequest)
			return
		}

		sl := newScrapeLogger(logger, moduleName, target)
		level.Info(sl).Log("msg", "Beginning probe", "probe", module.Prober, "timeout_seconds", timeoutSeconds)

		start := time.Now()
		registry := prometheus.NewRegistry()
		registry.MustRegister(probeSuccessGauge)
		registry.MustRegister(probeDurationGauge)
		success := prober(ctx, target, module, registry, sl)
		duration := time.Since(start).Seconds()
		probeDurationGauge.Set(duration)
		if success {
			probeSuccessGauge.Set(1)
			level.Info(sl).Log("msg", "Probe succeeded", "duration_seconds", duration)
		} else {
			level.Error(sl).Log("msg", "Probe failed", "duration_seconds", duration)
		}

		debugOutput := DebugOutput(&module, &sl.buffer, registry)
		rh.Add(moduleName, target, debugOutput, success)

		if r.URL.Query().Get("debug") == "true" {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(debugOutput))
			return
		}

		h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
		h.ServeHTTP(w, r)
	}
}

// Handler 实施ExporterHandler接口
func (blackbox *BlackBoxExporter) Handler(exporter *Exporter, m *mux.Router) error {
	allowedLevel := promlog.AllowedLevel{}
	flag.AddFlags(kingpin.CommandLine, &allowedLevel)
	kingpin.Parse()
	logger := promlog.New(allowedLevel)
	if c, ok := exporter.ConfigMap[exporter.Name]; ok {
		handler := NewBlackboxHandler(c.(*config.Config), logger)
		m.HandleFunc(exporter.Path, handler)
		return nil
	}
	return fmt.Errorf("[blackbox_exporter] Handler func no config define for %s", exporter.Name)

}

// ConfigReader 读取配置文件并保存在ConfigMap中
func (blackbox *BlackBoxExporter) ConfigReader(exporter *Exporter) error {
	file, err := ioutil.ReadFile(exporter.ConfigPath)
	if err != nil {
		return fmt.Errorf("[blackbox_exporter] Error reading config file:%s\n%s", exporter.ConfigPath, err)
	}
	c := &blackboxConfig.Config{}
	if err := yaml.Unmarshal(file, c); err != nil {
		return fmt.Errorf("[blackbox_exporter] Error parsing config file:%s\n%s", exporter.ConfigPath, err)
	}
	exporter.ConfigMap[exporter.Name] = c
	return nil
}

// 实施一个ResultManager来管理输出结果

// Result define one result
type result struct {
	id          int64
	moduleName  string
	target      string
	debugOutput string
	success     bool
}

// resultHistory define a result hub for result management
type resultHistory struct {
	mu         sync.Mutex
	nextID     int64
	results    []*result
	maxResults uint
}

// Add a result to the history.
func (rh *resultHistory) Add(moduleName, target, debugOutput string, success bool) {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	r := &result{
		id:          rh.nextID,
		moduleName:  moduleName,
		target:      target,
		debugOutput: debugOutput,
		success:     success,
	}
	rh.nextID++

	rh.results = append(rh.results, r)
	if uint(len(rh.results)) > rh.maxResults {
		results := make([]*result, len(rh.results)-1)
		copy(results, rh.results[1:])
		rh.results = results
	}
}

// List Return a list of all results.
func (rh *resultHistory) List() []*result {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	return rh.results[:]
}

// Get Return a given result.
func (rh *resultHistory) Get(id int64) *result {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	for _, r := range rh.results {
		if r.id == id {
			return r
		}
	}

	return nil
}
