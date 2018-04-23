FROM        quay.io/prometheus/busybox:latest

COPY exporter_hub  /bin/exporter_hub
COPY config      /etc/exporter_hub/config

EXPOSE      10010
ENTRYPOINT  [ "/bin/exporter_hub" ]
CMD         [ "--config.file=/etc/exporter_hub/config/main.yml" ]