# Reproducing the local Atlant/Xray measurements

[Download the benchmark source archive](https://github.com/AtlantOne/atlant-core/releases/download/v0.1.0-preview.2/habr-benchmark-source-20261024.zip).
The archive is for running the harness; the reports and CSV tables can be
[viewed directly on GitHub](README.md) without downloading it.

These are test tools, not a VPN installer. They create private network and mount
namespaces and refuse to modify the primary namespaces. Run on a disposable
Linux/WSL environment with root, Go 1.27.2, iproute2, util-linux and ethtool.
Never remove the namespace guards or run network setup manually on the host.

The source package intentionally excludes credentials, generated certificate
keys, raw runtime directories, executable files and personal machine paths.

## Prepare

Extract the archive into a new empty directory. From that directory:

```sh
git clone https://github.com/AtlantOne/atlant-core.git core
git -C core checkout ddefeffb45cfcd31f13cf2a73ad187e57a317a5f
mkdir -p artifacts/article-bin artifacts/tools/xray-26.3.27
go -C core/server build -trimpath -o "$PWD/artifacts/article-bin/atlant-server" .
go -C core/client/linux build -trimpath -o "$PWD/artifacts/article-bin/atlant-client" .
go -C tests/localbench test ./...
go -C tests/localbench build -trimpath -o "$PWD/artifacts/article-bin/localbench" .
cp artifacts/article-bin/localbench artifacts/article-bin/localbench-impaired
```

Use `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` for the builds when reproducing the
original architecture. Builds must finish before throughput measurements begin.

Download the official Linux amd64 Xray 26.3.27 release from
https://github.com/XTLS/Xray-core/releases/tag/v26.3.27 and verify its published
checksums. Put the extracted `xray` executable in `artifacts/tools/xray-26.3.27/`.
The original test executable SHA-256 is
`8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed`.

## RAM matrix

```sh
sudo unshare -mn -- sh tests/localbench/run-article.sh \
  "$PWD" "$PWD/artifacts/ram" "$PWD/artifacts/article-bin"
python3 tests/localbench/article_report.py artifacts/ram artifacts/ram-public
```

This runs all six entries, three rounds, 1/4 streams, upload/download,
with/without inner TLS. Every batch is checked with byte counts and CRC32C.
The output is 144 samples; no success-only subset is accepted by the exporter.

## Channel matrix

Run scenarios sequentially, not concurrently:

```sh
for scenario in clean rtt50-loss1 rtt100-loss3; do
  sudo unshare -mn -- sh tests/localbench/run-article-impaired.sh \
    "$PWD" "$PWD/artifacts/channel-$scenario" \
    "$PWD/artifacts/article-bin" "$scenario" 2
done
python3 tests/localbench/channel_article_report.py artifacts artifacts/channel-public
```

Five protected variants, both directions, two repetitions, 8-second windows.
Each scenario caps the tunnel at 20 Mbps per direction. Four pipelined bulk
streams run alongside an independent reliable echo stream. Report both goodput
and loaded latency, including failed windows and timeout counts if any occur.
Do not interpret cold setup latency as a normalized protocol handshake benchmark.

Raw runtime output contains generated test keys and must not be published as a
directory. The public CSV exporters copy only selected measurement fields.
These are local implementation tests, not proof of DPI resistance or Internet
performance. Short windows and limited repeats should not be presented as a
universal ranking of protocols. Hysteria 2 is not included in this harness run.

The archive's Go and helper sources are Apache-2.0; see LICENSE and NOTICE.
Imported third-party modules retain their own licenses.
