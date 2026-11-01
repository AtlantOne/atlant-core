FROM golang:1.27.2-bookworm AS build
WORKDIR /src
ENV GOMAXPROCS=1 GOMEMLIMIT=450MiB
COPY core/ ./
COPY core-port-fixes.patch /tmp/core-port-fixes.patch
RUN (git apply --check /tmp/core-port-fixes.patch && git apply /tmp/core-port-fixes.patch) || \
    git apply --reverse --check /tmp/core-port-fixes.patch
RUN CGO_ENABLED=0 go -C server build -trimpath -o /out/atlant-server . && \
    CGO_ENABLED=0 go -C shared build -trimpath -o /out/atlant-cert-agent ./cmd/atlant-cert-agent

FROM python:3.14-slim-bookworm
RUN groupadd -g 10001 atlant && useradd -u 10001 -g atlant -M atlant
COPY --from=build /out/ /usr/local/bin/
COPY --chown=10001:10001 panel/management/ /opt/atlant/management/
COPY --chown=10001:10001 runtime.py /opt/atlant/management/docker_runtime.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["python3", "-I", "/opt/atlant/management/docker_runtime.py"]
