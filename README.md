# Mini SIEM

SIEM (Security Information and Event Management) ringan dalam satu binary Go. Mini SIEM membaca log server, menormalkannya menjadi event, mencocokkan IP dengan threat intel, menjalankan aturan deteksi (bawaan dan aturan komunitas **Sigma**) secara real-time, menyimpan semuanya di SQLite, dan menampilkan alert di dashboard web yang update live.

```
 log files ──tail──┐                    threat intel feeds
                   ├─► parser ─► enrich (IP blocklist) ─► pipeline ─► SQLite (events, alerts)
 HTTP /api/ingest ─┘                                         │
                                rules: built-in + Sigma ─► engine ─► alert ─► dashboard (SSE live)
                                                                           └► webhook
```

## Fitur

### Fase 2: Sigma + threat intel

- **Aturan Sigma**: compiler sendiri untuk format standar industri [Sigma](https://sigmahq.io). `make sigma` mengunduh repo komunitas SigmaHQ, lalu semua aturan untuk log web server dan OpenSSH dimuat otomatis. Saat ini **87 aturan** terpakai, termasuk deteksi exploit CVE (Log4Shell, Apache CVE-2021-41773, Grafana, WebLogic, Citrix, Exchange, Fortinet, dan lain-lain), SQLi, XSS, SSTI, dan user-agent tool hacking. Aturan untuk sumber log lain (Windows, cloud, EDR) dilewati dan dilaporkan.
  - Didukung: selection map/list, keyword, wildcard `*` `?`, nilai `null`, modifier `contains`, `startswith`, `endswith`, `all`, `re`, `cidr`, `gt/gte/lt/lte`, `exists`, `cased`, dan kondisi lengkap (`and`, `or`, `not`, kurung, `1 of`, `all of`, `them`).
  - Belum didukung: agregasi `| count()`, correlation rule, modifier encoding (`base64`, `utf16`, `windash`).
- **Threat intel**: feed blocklist IP/CIDR dari URL atau file (format FireHOL, Spamhaus DROP, abuse.ch, atau daftar polos). Feed di-refresh berkala; kalau download gagal, data lama tetap dipakai. Event dari IP yang terdaftar diberi `fields.ti_lists` dan memicu aturan `threat-intel-ip`. IP privat/internal tidak pernah dicocokkan, karena banyak feed memasukkan range privat sebagai "bogon".
- **Dashboard**: badge Sigma, pencarian aturan (misalnya ketik "CVE"), link referensi CVE di detail alert, badge **TI** untuk IP berbahaya, dan kartu status feed.

### Fase 1: fondasi

- **Input**: tail file log (tahan rotasi dan truncate, seperti `tail -F`) dan endpoint HTTP `POST /api/ingest`.
- **Parser**: OpenSSH `auth.log` (format syslog klasik dan RFC 3339), nginx/Apache *combined* access log, dan JSON per baris.
- **Rule engine** berbasis YAML dengan tiga tipe aturan:
  - `match`: satu event cocok langsung jadi alert (dengan dedup per grup).
  - `threshold`: N event dalam jendela waktu per grup, atau N nilai *distinct* (misalnya banyak username dari satu IP).
  - `sequence`: event B setelah ≥N event A (misalnya login sukses setelah brute force).
  - Jendela waktu memakai waktu event, bukan jam dinding, sehingga replay log lama menghasilkan alert yang sama.
- **10 aturan bawaan** (`rules/default.yaml`): SSH brute force, password spraying, login sukses setelah brute force, login root, scan kerentanan web, probe file sensitif (`.env`, `.git`), percobaan SQLi/XSS/path traversal, brute force login web, dan lonjakan error 5xx. Tag MITRE ATT&CK disertakan.
- **Dashboard**: ringkasan, grafik event per interval, daftar alert (ack/close/reopen), detail alert beserta event pemicunya, top IP sumber, pencarian event, dan daftar aturan. Mendukung mode terang/gelap dan layar HP.
- **Keamanan**: token API opsional, CSP ketat, dan semua data log ditampilkan sebagai teks (bukan HTML), karena isi log bisa dikendalikan penyerang.
- **Retensi** event otomatis dan **webhook** untuk alert dengan severity minimum.

## Menjalankan

Butuh Go 1.26+.

```bash
make build
./siem                      # dashboard di http://127.0.0.1:8080
```

Demo lengkap (aturan Sigma, blocklist demo, dan lalu lintas simulasi dengan serangan acak):

```bash
make demo                   # = make sigma + ./siem -config config.demo.yaml + ./loggen
```

Atau manual:

```bash
make sigma                  # unduh aturan SigmaHQ ke ./sigma
./siem -config config.demo.yaml &
./loggen -once              # kirim semua skenario serangan sekali
./loggen -rate 5 -attack-every 15s   # atau terus-menerus
```

Skenario `loggen`: SSH brute force, password spraying, brute force yang berhasil login, scan kerentanan web, probe SQLi, brute force login web, dan payload exploit CVE asli (Log4Shell, Apache, Grafana, WebLogic, Bitbucket, VMware, XSS).

`loggen` juga bisa menulis ke file supaya jalur tail ikut teruji:

```bash
./loggen -ssh-file /tmp/auth.log -web-file /tmp/access.log
```

IP penyerang di data simulasi diambil dari blok dokumentasi RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Tidak ada lalu lintas yang dikirim ke IP tersebut; mereka hanya muncul di teks log.

Untuk server sungguhan, salin `config.example.yaml` ke `config.yaml`, sesuaikan path log, lalu:

```bash
SIEM_TOKEN=rahasia ./siem -config config.yaml
```

Kalau `listen` bukan alamat loopback, selalu pasang `auth_token` (atau `SIEM_TOKEN`).

### Docker

```bash
docker build -t mini-siem .
docker run -p 8080:8080 -v $PWD/data:/app/data -e SIEM_TOKEN=rahasia mini-siem
```

## API

Semua route `/api` butuh `Authorization: Bearer <token>` jika token diset.

| Method | Path | Keterangan |
|---|---|---|
| POST | `/api/ingest?parser=ssh\|nginx\|json` | Body berisi baris log mentah, satu per baris |
| GET | `/api/events` | Filter: `type`, `source`, `src_ip`, `user`, `q`, `since`, `until` (RFC 3339 atau durasi seperti `15m`), `limit`, `before_id` |
| GET | `/api/alerts` | Filter: `status`, `severity`, `rule_id`, `group`, `limit`, `before_id` |
| GET | `/api/alerts/{id}` | Alert beserta event pemicunya |
| PATCH | `/api/alerts/{id}` | `{"status": "open" \| "acknowledged" \| "closed"}` |
| GET | `/api/stats?range=15m\|1h\|6h\|24h` | Ringkasan dan timeline untuk dashboard |
| GET | `/api/rules` | Aturan yang dimuat, plus laporan load Sigma |
| GET | `/api/intel` | Status feed threat intel |
| GET | `/api/stream` | Server-Sent Events: alert baru dan jumlah event |
| GET | `/healthz` | Status dan counter pipeline |

Contoh kirim log JSON dari aplikasi:

```bash
curl -X POST 'localhost:8080/api/ingest?parser=json' \
  --data-binary '{"type":"auth_failure","src_ip":"203.0.113.9","user":"roy","app":"api"}'
```

## Menulis aturan

```yaml
rules:
  - id: api-token-abuse
    name: Banyak token API ditolak
    description: "{group} ditolak {count} kali dalam {window}"
    severity: high              # low | medium | high | critical
    type: threshold             # match | threshold | sequence
    where:
      source: json
      type: auth_failure
      fields.app: api
    group_by: src_ip
    threshold: 20
    window: 5m
```

Matcher: nilai biasa berarti *equals*; selain itu bisa `equals`, `not`, `in`, `not_in`, `contains`, `prefix`, `regex`, `gte`, `lte`, `exists`. Field: `type`, `source`, `host`, `src_ip`, `user`, `message`, atau `fields.<nama>`. Lihat `rules/default.yaml` untuk contoh lengkap.

## Menambah aturan Sigma sendiri

Tulis file `.yml` berformat Sigma dan tambahkan foldernya ke `sigma.paths`. Logsource yang dikenali: `category: webserver` (atau `product: nginx`/`apache`), dan `product: linux` + `service: sshd`. Field web memakai nama standar Sigma (`cs-method`, `cs-uri-query`, `cs-uri-stem`, `sc-status`, `cs-user-agent`, `cs-referer`, `c-ip`, ...). Server mencatat berapa aturan yang dimuat dan alasan aturan yang dilewati.

## Struktur kode

```
cmd/siem        server utama (config, wiring, shutdown)
cmd/loggen      generator log dan serangan simulasi
internal/event  tipe Event dan Alert
internal/parser parser ssh, nginx, json
internal/rules  loader aturan YAML dan rule engine
internal/sigma  compiler aturan Sigma (selection, modifier, condition)
internal/intel  feed threat intel dan enrichment IP
internal/store  penyimpanan SQLite (pure Go, tanpa CGO)
internal/pipeline  batching, deteksi, hub live, webhook
internal/ingest tail file
internal/api    REST API, SSE, dan dashboard (embedded)
```

## Tes

```bash
make test     # go vet + go test -race
```

Kalau folder `./sigma` ada, `make test` juga mengompilasi seluruh aturan SigmaHQ asli dan memastikan payload serangan nyata terdeteksi tanpa false positive pada request normal.

## Rencana berikutnya

- ~~**Fase 2**: aturan Sigma dan threat intel~~ (selesai).
- **Fase 3**: agent ringan untuk mengirim log dari banyak host, parser tambahan (Windows Event Log, sudo, firewall/iptables, Docker) agar lebih banyak aturan Sigma terpakai, enrichment GeoIP/ASN, dan agregasi Sigma (`| count()`).
- **Fase 4**: korelasi lintas sumber (misalnya scan web lalu brute force SSH dari IP yang sama), manajemen kasus (case/incident), respons otomatis (blokir IP via firewall/fail2ban), multi-user dengan RBAC, dan storage yang bisa diskalakan (ClickHouse/OpenSearch).
