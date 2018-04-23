FROM        quay.io/prometheus/busybox:latest

COPY exporter-hub  /bin/exporter-hub
COPY config      /etc/exporter-hub/config

EXPOSE      10010
ENTRYPOINT  [ "/bin/exporter-hub" ]
CMD         [ "--config.file=/etc/exporter-hub/config/main.yml" ]