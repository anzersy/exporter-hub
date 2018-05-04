# exporter-hub

![CircleCI](https://circleci.com/gh/zhangmingkai4315/exporter-hub.svg?style=svg)

exporter-hub是一个包含多个exporter的集合程序，仅通过一个端口接收指标查询。当前包含的exporter列表如下：

| exporter名称      | 路径                   |
|--------------    |------------------------|
|node-exporter     | /node-exporter         |
|process-exporter  | /process-exporter      |
|blackbox-exporter | /blackbox-exporter     |
|snmp-exporter     | /snmp-exporter         |
|port-exporter     | /port-exporter         |
|bind-exporter     | /bind-exporter         |


#### docker镜像

docker镜像已发布到docker-hub，执行下载命令启动

```
docker pull zhangmingkai4315/exporter-hub
```


#### 部署

二进制可执行文件[下载路径](https://github.com/zhangmingkai4315/exporter-hub/releases)
暂时只提供linux-386及amd64两种版本，下载后直接运行即可