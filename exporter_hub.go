package main

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"syscall"

	"github.com/fvbock/endless"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	"github.com/zhangmingkai4315/exporter-hub/handler"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	pid        int     // 当前进程的执行Pid
	configPath *string // 配置文件路径
)

func init() {
	prometheus.MustRegister(version.NewCollector("exporter_hub"))
	configPath = kingpin.Flag("config", "the config file path").Default("config/main.yml").String()

}

func printList(conf *handler.SafeConfig) string {
	indexList := ""
	for _, exporter := range conf.C.Exporters {
		enableStatus := "disable"
		if exporter.Enable == true {
			enableStatus = "enable"
			indexList += "<tr><td><a href=" +
				exporter.Path + ">" +
				exporter.Name + "</a></td><td>" +
				exporter.ConfigPath + "</td><td>" +
				enableStatus + "</td><tr>"
		} else {
			indexList += "<tr><td>" +
				exporter.Name + "</td><td>" +
				exporter.ConfigPath + "</td><td>" +
				enableStatus + "</td><tr>"
		}
	}
	return `
	    <html>
			<head><title>Exporter Hub</title></head>
			<body>
			<h1>Exporter Hub</h1>
            <table><tr><th>Name</th><th>ConfigFilePath</th><th>Status</th></tr>
	          ` + indexList + `
			</body>
	    </html>`
}

func startEnabledHandler(conf *handler.SafeConfig, m *mux.Router) {
	for _, exporter := range conf.C.Exporters {
		if exporter.Enable == true {
			err := handler.Start(exporter.Name, exporter, m)
			if err != nil {
				log.Errorf("Error start exporter:%s\n", err)
			}
		}
	}
}

func main() {
	mux := mux.NewRouter()
	kingpin.Parse()
	// 读取配置文件
	log.Infoln("Starting exporter hub", version.Info())
	log.Infoln("Build context", version.BuildContext())
	sconf := handler.SafeConfig{}
	err := sconf.ReloadConfig(*configPath)
	if err != nil {
		log.Errorf("Erro parse config file:%s\n", err)
	}
	// 遍历exporters，获取列表信息
	homeList := printList(&sconf)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(homeList))
	})

	// 为每一个exporter增加mux handler
	startEnabledHandler(&sconf, mux)

	// 定义重载配置文件
	reloadCh := make(chan chan error)
	go func() {
		for {
			select {
			case <-reloadCh:
				syscall.Kill(pid, syscall.SIGHUP)
			}
		}
	}()
	// 定义路由函数重载配置文件
	mux.HandleFunc("/-/reload",
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				fmt.Fprintf(w, "This endpoint requires a POST request.\n")
				return
			}
			rc := make(chan error)
			reloadCh <- rc
			if err := <-rc; err != nil {
				http.Error(w, fmt.Sprintf("failed to restart application: %s", err), http.StatusInternalServerError)
			}
		})

	listenAddrAndPort := sconf.C.Server + ":" + sconf.C.Port
	log.Infof("Start http server ListenAndServe: %s", listenAddrAndPort)
	server := endless.NewServer(listenAddrAndPort, mux)

	//获取PID用于执行的SIGHUP信号的重新启动
	server.BeforeBegin = func(add string) {
		pid = syscall.Getpid()
		log.Infof("Application pid is %d", pid)
	}

	err = server.ListenAndServe()
	if err != nil {
		log.Fatalf("Start http server error: %s", err)
	}
}
