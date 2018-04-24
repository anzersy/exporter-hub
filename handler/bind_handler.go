package handler

import (
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	_ "net/http/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/digitalocean/bind_exporter/bind"
	"github.com/digitalocean/bind_exporter/bind/auto"
	"github.com/digitalocean/bind_exporter/bind/v2"
	"github.com/digitalocean/bind_exporter/bind/v3"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"

	yaml "gopkg.in/yaml.v2"
)

const (
	namespace_bind = "bind"
	exporter       = "bind_exporter"
	resolver       = "resolver"
)

var (
	bindExporter = BindExporter{}
	groups       = statisticGroups{bind.ServerStats, bind.ViewStats}

	up = prometheus.NewDesc(
		prometheus.BuildFQName(namespace_bind, "", "up"),
		"Was the Bind instance query successful?",
		nil, nil,
	)
	bootTime = prometheus.NewDesc(
		prometheus.BuildFQName(namespace_bind, "", "boot_time_seconds"),
		"Start time of the BIND process since unix epoch in seconds.",
		nil, nil,
	)
	configTime = prometheus.NewDesc(
		prometheus.BuildFQName(namespace_bind, "", "config_time_seconds"),
		"Time of the last reconfiguration since unix epoch in seconds.",
		nil, nil,
	)
	incomingQueries = prometheus.NewDesc(
		prometheus.BuildFQName(namespace_bind, "", "incoming_queries_total"),
		"Number of incoming DNS queries.",
		[]string{"type"}, nil,
	)
	incomingRequests = prometheus.NewDesc(
		prometheus.BuildFQName(namespace_bind, "", "incoming_requests_total"),
		"Number of incoming DNS requests.",
		[]string{"opcode"}, nil,
	)
	resolverCache = prometheus.NewDesc(
		prometheus.BuildFQName(namespace_bind, resolver, "cache_rrsets"),
		"Number of RRSets in Cache database.",
		[]string{"view", "type"}, nil,
	)
	resolverQueries = prometheus.NewDesc(
		prometheus.BuildFQName(namespace_bind, resolver, "queries_total"),
		"Number of outgoing DNS queries.",
		[]string{"view", "type"}, nil,
	)
	resolverQueryDuration = prometheus.NewDesc(
		prometheus.BuildFQName(namespace_bind, resolver, "query_duration_seconds"),
		"Resolver query round-trip time in seconds.",
		[]string{"view"}, nil,
	)
	resolverQueryErrors = prometheus.NewDesc(
		prometheus.BuildFQName(namespace_bind, resolver, "query_errors_total"),
		"Number of resolver queries failed.",
		[]string{"view", "error"}, nil,
	)
	resolverResponseErrors = prometheus.NewDesc(
		prometheus.BuildFQName(namespace_bind, resolver, "response_errors_total"),
		"Number of resolver response errors received.",
		[]string{"view", "error"}, nil,
	)
	resolverDNSSECSuccess = prometheus.NewDesc(
		prometheus.BuildFQName(namespace_bind, resolver, "dnssec_validation_success_total"),
		"Number of DNSSEC validation attempts succeeded.",
		[]string{"view", "result"}, nil,
	)
	resolverMetricStats = map[string]*prometheus.Desc{
		"Lame": prometheus.NewDesc(
			prometheus.BuildFQName(namespace_bind, resolver, "response_lame_total"),
			"Number of lame delegation responses received.",
			[]string{"view"}, nil,
		),
		"EDNS0Fail": prometheus.NewDesc(
			prometheus.BuildFQName(namespace_bind, resolver, "query_edns0_errors_total"),
			"Number of EDNS(0) query errors.",
			[]string{"view"}, nil,
		),
		"Mismatch": prometheus.NewDesc(
			prometheus.BuildFQName(namespace_bind, resolver, "response_mismatch_total"),
			"Number of mismatch responses received.",
			[]string{"view"}, nil,
		),
		"Retry": prometheus.NewDesc(
			prometheus.BuildFQName(namespace_bind, resolver, "query_retries_total"),
			"Number of resolver query retries.",
			[]string{"view"}, nil,
		),
		"Truncated": prometheus.NewDesc(
			prometheus.BuildFQName(namespace_bind, resolver, "response_truncated_total"),
			"Number of truncated responses received.",
			[]string{"view"}, nil,
		),
		"ValFail": prometheus.NewDesc(
			prometheus.BuildFQName(namespace_bind, resolver, "dnssec_validation_errors_total"),
			"Number of DNSSEC validation attempt errors.",
			[]string{"view"}, nil,
		),
	}
	resolverLabelStats = map[string]*prometheus.Desc{
		"QueryAbort":    resolverQueryErrors,
		"QuerySockFail": resolverQueryErrors,
		"QueryTimeout":  resolverQueryErrors,
		"NXDOMAIN":      resolverResponseErrors,
		"SERVFAIL":      resolverResponseErrors,
		"FORMERR":       resolverResponseErrors,
		"OtherError":    resolverResponseErrors,
		"ValOk":         resolverDNSSECSuccess,
		"ValNegOk":      resolverDNSSECSuccess,
	}
	serverQueryErrors = prometheus.NewDesc(
		prometheus.BuildFQName(namespace_bind, "", "query_errors_total"),
		"Number of query failures.",
		[]string{"error"}, nil,
	)
	serverResponses = prometheus.NewDesc(
		prometheus.BuildFQName(namespace_bind, "", "responses_total"),
		"Number of responses sent.",
		[]string{"result"}, nil,
	)
	serverLabelStats = map[string]*prometheus.Desc{
		"QryDropped":  serverQueryErrors,
		"QryFailure":  serverQueryErrors,
		"QrySuccess":  serverResponses,
		"QryReferral": serverResponses,
		"QryNxrrset":  serverResponses,
		"QrySERVFAIL": serverResponses,
		"QryFORMERR":  serverResponses,
		"QryNXDOMAIN": serverResponses,
	}
	serverMetricStats = map[string]*prometheus.Desc{
		"QryDuplicate": prometheus.NewDesc(
			prometheus.BuildFQName(namespace_bind, "", "query_duplicates_total"),
			"Number of duplicated queries received.",
			nil, nil,
		),
		"QryRecursion": prometheus.NewDesc(
			prometheus.BuildFQName(namespace_bind, "", "query_recursions_total"),
			"Number of queries causing recursion.",
			nil, nil,
		),
	}
	tasksRunning = prometheus.NewDesc(
		prometheus.BuildFQName(namespace_bind, "", "tasks_running"),
		"Number of running tasks.",
		nil, nil,
	)
	workerThreads = prometheus.NewDesc(
		prometheus.BuildFQName(namespace_bind, "", "worker_threads"),
		"Total number of available worker threads.",
		nil, nil,
	)
)

type collectorConstructor func(*bind.Statistics) prometheus.Collector

type serverCollector struct {
	stats *bind.Statistics
}

// newServerCollector implements collectorConstructor.
func newServerCollector(s *bind.Statistics) prometheus.Collector {
	return &serverCollector{stats: s}
}

// Describe implements prometheus.Collector.
func (c *serverCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- bootTime
	ch <- configTime
	ch <- incomingQueries
	ch <- incomingRequests
	ch <- serverQueryErrors
	ch <- serverResponses
	for _, desc := range serverMetricStats {
		ch <- desc
	}
}

// Collect implements prometheus.Collector.
func (c *serverCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(
		bootTime, prometheus.GaugeValue, float64(c.stats.Server.BootTime.Unix()),
	)
	if !c.stats.Server.ConfigTime.IsZero() {
		ch <- prometheus.MustNewConstMetric(
			configTime, prometheus.GaugeValue, float64(c.stats.Server.ConfigTime.Unix()),
		)
	}
	for _, s := range c.stats.Server.IncomingQueries {
		ch <- prometheus.MustNewConstMetric(
			incomingQueries, prometheus.CounterValue, float64(s.Counter), s.Name,
		)
	}
	for _, s := range c.stats.Server.IncomingRequests {
		ch <- prometheus.MustNewConstMetric(
			incomingRequests, prometheus.CounterValue, float64(s.Counter), s.Name,
		)
	}
	for _, s := range c.stats.Server.NameServerStats {
		if desc, ok := serverLabelStats[s.Name]; ok {
			r := strings.TrimPrefix(s.Name, "Qry")
			ch <- prometheus.MustNewConstMetric(
				desc, prometheus.CounterValue, float64(s.Counter), r,
			)
		}
		if desc, ok := serverMetricStats[s.Name]; ok {
			ch <- prometheus.MustNewConstMetric(
				desc, prometheus.CounterValue, float64(s.Counter),
			)
		}
	}
}

type viewCollector struct {
	stats *bind.Statistics
}

// newViewCollector implements collectorConstructor.
func newViewCollector(s *bind.Statistics) prometheus.Collector {
	return &viewCollector{stats: s}
}

// Describe implements prometheus.Collector.
func (c *viewCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- resolverDNSSECSuccess
	ch <- resolverQueries
	ch <- resolverQueryDuration
	ch <- resolverQueryErrors
	ch <- resolverResponseErrors
	for _, desc := range resolverMetricStats {
		ch <- desc
	}
}

// Collect implements prometheus.Collector.
func (c *viewCollector) Collect(ch chan<- prometheus.Metric) {
	for _, v := range c.stats.Views {
		for _, s := range v.Cache {
			ch <- prometheus.MustNewConstMetric(
				resolverCache, prometheus.GaugeValue, float64(s.Gauge), v.Name, s.Name,
			)
		}
		for _, s := range v.ResolverQueries {
			ch <- prometheus.MustNewConstMetric(
				resolverQueries, prometheus.CounterValue, float64(s.Counter), v.Name, s.Name,
			)
		}
		for _, s := range v.ResolverStats {
			if desc, ok := resolverMetricStats[s.Name]; ok {
				ch <- prometheus.MustNewConstMetric(
					desc, prometheus.CounterValue, float64(s.Counter), v.Name,
				)
			}
			if desc, ok := resolverLabelStats[s.Name]; ok {
				ch <- prometheus.MustNewConstMetric(
					desc, prometheus.CounterValue, float64(s.Counter), v.Name, s.Name,
				)
			}
		}
		if buckets, count, err := histogram(v.ResolverStats); err == nil {
			ch <- prometheus.MustNewConstHistogram(
				resolverQueryDuration, count, math.NaN(), buckets, v.Name,
			)
		} else {
			log.Warn("Error parsing RTT:", err)
		}
	}
}

type taskCollector struct {
	stats *bind.Statistics
}

// newTaskCollector implements collectorConstructor.
func newTaskCollector(s *bind.Statistics) prometheus.Collector {
	return &taskCollector{stats: s}
}

// Describe implements prometheus.Collector.
func (c *taskCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- tasksRunning
	ch <- workerThreads
}

// Collect implements prometheus.Collector.
func (c *taskCollector) Collect(ch chan<- prometheus.Metric) {
	threadModel := c.stats.TaskManager.ThreadModel
	ch <- prometheus.MustNewConstMetric(
		tasksRunning, prometheus.GaugeValue, float64(threadModel.TasksRunning),
	)
	ch <- prometheus.MustNewConstMetric(
		workerThreads, prometheus.GaugeValue, float64(threadModel.WorkerThreads),
	)
}

// Exporter collects Binds stats from the given server and exports them using
// the prometheus metrics package.
type BindExporter struct {
	client     bind.Client
	collectors []collectorConstructor
	groups     []bind.StatisticGroup
	C          *BindExporterConfig
}

// NewBindExporter returns an initialized Exporter.
func NewBindExporter(version, url string, timeout time.Duration, g []bind.StatisticGroup) *BindExporter {
	var c bind.Client
	switch version {
	case "xml.v2":
		c = v2.NewClient(url, &http.Client{Timeout: timeout})
	case "xml.v3":
		c = v3.NewClient(url, &http.Client{Timeout: timeout})
	default:
		c = auto.NewClient(url, &http.Client{Timeout: timeout})
	}

	var cs []collectorConstructor
	for _, g := range g {
		switch g {
		case bind.ServerStats:
			cs = append(cs, newServerCollector)
		case bind.ViewStats:
			cs = append(cs, newViewCollector)
		case bind.TaskStats:
			cs = append(cs, newTaskCollector)
		}
	}

	return &BindExporter{client: c, collectors: cs, groups: g}
}

// Describe describes all the metrics ever exported by the bind exporter. It
// implements prometheus.Collector.
func (bi *BindExporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- up
	for _, c := range bi.collectors {
		c(&bind.Statistics{}).Describe(ch)
	}
}

// Collect fetches the stats from configured bind location and delivers them as
// Prometheus metrics. It implements prometheus.Collector.
func (bi *BindExporter) Collect(ch chan<- prometheus.Metric) {
	status := 0.
	if stats, err := bi.client.Stats(bi.groups...); err == nil {
		for _, c := range bi.collectors {
			c(&stats).Collect(ch)
		}
		status = 1
	} else {
		log.Error("Couldn't retrieve BIND stats: ", err)
	}
	ch <- prometheus.MustNewConstMetric(up, prometheus.GaugeValue, status)
}

func histogram(stats []bind.Counter) (map[float64]uint64, uint64, error) {
	buckets := map[float64]uint64{}
	var count uint64

	for _, s := range stats {
		if strings.HasPrefix(s.Name, bind.QryRTT) {
			b := math.Inf(0)
			if !strings.HasSuffix(s.Name, "+") {
				var err error
				rrt := strings.TrimPrefix(s.Name, bind.QryRTT)
				b, err = strconv.ParseFloat(rrt, 32)
				if err != nil {
					return buckets, 0, fmt.Errorf("could not parse RTT: %s", rrt)
				}
			}

			buckets[b/1000] = count + uint64(s.Counter)
			count += uint64(s.Counter)
		}
	}
	return buckets, count, nil
}

type statisticGroups []bind.StatisticGroup

// String implements flag.Value.
func (s *statisticGroups) String() string {
	groups := []string{}
	for _, g := range *s {
		groups = append(groups, string(g))
	}
	return fmt.Sprintf("%q", strings.Join(groups, ","))
}

// Set implements flag.Value.
func (s *statisticGroups) Set(value string) error {
	*s = []bind.StatisticGroup{}
	if len(value) == 0 {
		return nil
	}
	var sg bind.StatisticGroup
	for _, dt := range strings.Split(value, ",") {
		switch dt {
		case string(bind.ServerStats):
			sg = bind.ServerStats
		case string(bind.ViewStats):
			sg = bind.ViewStats
		case string(bind.TaskStats):
			sg = bind.TaskStats
		default:
			return fmt.Errorf("unknown stats group %q", dt)
		}
		for _, existing := range *s {
			if existing == sg {
				return fmt.Errorf("duplicated stats group %q", sg)
			}
		}
		*s = append(*s, sg)
	}
	return nil
}

// BindExporterConfig for Port exporter config
type BindExporterConfig struct {
	BindURI     string `yaml:"bindURI,omitempty" json:"bindURI"`
	BindTimeout int    `yaml:"bindTimeout,omitempty" json:"bindTimeout"`
	BindPidFile string `yaml:"bindPidFile,omitempty" json:"bindPidFile"`
	BindVersion string `yaml:"bindVersion,omitempty" json:"bindVersion"`
	ShowVersion bool   `yaml:"showVersion,omitempty" json:"showVersion"`
}

// ReadBindExporterConfig read config file and return config struct
func ReadBindExporterConfig(path string) (*BindExporterConfig, error) {
	config := BindExporterConfig{}
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

// NewBindHandler 创建一个处理bind 的web handler
func (bi *BindExporter) NewBindHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		registry := prometheus.NewRegistry()
		err := registry.Register(NewBindExporter(bi.C.BindVersion, bi.C.BindURI, time.Duration(bi.C.BindTimeout)*time.Second, groups))
		if err != nil {
			log.Errorln("Couldn't register collector:", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Couldn't register collector: %s", err)))
			return
		}
		if bi.C.BindPidFile != "" {
			procExporter := prometheus.NewProcessCollectorPIDFn(
				func() (int, error) {
					content, err := ioutil.ReadFile(bi.C.BindPidFile)
					if err != nil {
						return 0, fmt.Errorf("Can't read pid file: %s", err)
					}
					value, err := strconv.Atoi(strings.TrimSpace(string(content)))
					if err != nil {
						return 0, fmt.Errorf("Can't parse pid file: %s", err)
					}
					return value, nil
				}, namespace_bind)
			err := registry.Register(procExporter)
			if err != nil {
				log.Errorln("Couldn't register collector:", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintf("Couldn't register collector: %s", err)))
				return
			}
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

func init() {
	registHandler(&bindExporter)
}

func (bi *BindExporter) GetName() string {
	return "bind_exporter"
}

func (bi *BindExporter) ConfigReader(exporter *Exporter) error {
	c, err := ReadBindExporterConfig(exporter.ConfigPath)
	if err != nil {
		return err
	}
	exporter.ConfigMap[exporter.Name] = c
	return nil
}

func (bi *BindExporter) Handler(exporter *Exporter, m *mux.Router) error {
	if c, ok := exporter.ConfigMap[exporter.Name]; ok {
		bindHandler := bi.NewBindHandler()
		bi.C = c.(*BindExporterConfig)
		m.HandleFunc(exporter.Path, bindHandler)
		return nil
	}
	return fmt.Errorf("[bind_exporter] Handler func no config define for %s", exporter.Name)
}
