````markdown
# Credit Card Sniffer (Educational Project)

> **⚠️ Disclaimer:**  
> This tool is for educational purposes only. Use **only** in controlled environments with explicit written permission. Unauthorized use is strictly prohibited.

---

## 📖 Overview

A production-grade network sniffer that detects credit-card numbers in live traffic. Designed for cybersecurity education, this project demonstrates:

- Traffic capture with high throughput  
- Regex-based pattern matching + Luhn checksum validation  
- Production-grade observability (rotating JSON logs, Prometheus metrics, CSV output)  
- Secure, containerized deployment  

---

## 🚀 Features

- **High-performance packet processing** via `AsyncSniffer` + thread pool  
- **Configurable detection** of multiple card types (Visa, MasterCard, Amex, …)  
- **Observability**  
  - Rotating JSON logs for SIEM ingestion  
  - Prometheus metrics endpoint (`/metrics`)  
  - Optional CSV reporting  
- **Security-first design**  
  - Masked card numbers in output (e.g. `1234****5678`)  
  - Non-root Docker execution  
  - Config schema validation on startup  
- **Containerized** with Dockerfile  
- **Raspberry Pi compatible**  

---

## ⚙️ Setup

### Prerequisites

- Python 3.11+  
- `libpcap-dev` (or equivalent)  
- Admin/`root` privileges for packet capture  

### Installation

```bash
git clone https://github.com/your-repo/cc_sniffer.git
cd cc_sniffer

# Install Python dependencies
pip install -r requirements.txt

# Install the package
python setup.py install
````

### Docker Build

```bash
docker build -t cc_sniffer .
```

---

## 🛠 Configuration

All runtime settings live in `config.yaml`:

```yaml
interface: eth0
bpf_filter: "tcp port 80"
log_path: /var/log/cc_sniffer.json
max_log_size_mb: 10
backup_count: 5
csv_output: /data/cc_reports.csv
prometheus_port: 8000
thread_workers: 4

card_types:
  Amex:       "3[47][0-9]{13}"
  MasterCard: "5[1-5][0-9]{14}"
  Visa:       "4[0-9]{12}(?:[0-9]{3})?"
```

* **interface**: network interface to monitor
* **bpf\_filter**: BPF filter string for `sniff()`
* **log\_path**: file path for rotated JSON logs
* **csv\_output**: optional CSV report file
* **prometheus\_port**: port for metrics HTTP server
* **thread\_workers**: number of worker threads

---

## ▶️ Usage

### As a CLI

```bash
sudo cc-sniffer --verbose
```

### In Docker

```bash
docker run --rm --cap-add=NET_RAW \
  -v "$(pwd)/config.yaml":/app/config.yaml \
  -v "$(pwd)/logs":/var/log \
  -v "$(pwd)/data":/data \
  -p 8000:8000 \
  cc_sniffer
```

---

## 📊 Observability

### Logging

* **Format:** JSON
* **Rotation:** size-based, configured in `config.yaml`
* **Sample entry:**

  ```json
  {
    "timestamp": "2025-06-14T12:34:56Z",
    "level": "INFO",
    "message": "card_match",
    "extra": {
      "type": "Visa",
      "number": "4242****4242",
      "src": "192.168.1.100:54321",
      "dst": "203.0.113.5:80",
      "time": "2025-06-14T12:34:56.789Z"
    }
  }
  ```

### Metrics

Prometheus endpoint at `http://<host>:8000/metrics`:

* `sniffer_packets_total`
* `sniffer_matches_total`
* `sniffer_errors_total`

### CSV Reporting

If enabled, CSV at `csv_output` contains columns:

```
time, type, number, src, dst
```

---

## 🔐 Security Measures

1. **Data Masking** – only partial PANs logged.
2. **Least Privilege** – non-root container, minimal capabilities.
3. **Validation** – Luhn algorithm + regex.
4. **Immutable Audit Trail** – rotating JSON logs + secure CSV.

---

## 🧠 Ethical Considerations

* **Only** with explicit written permission
* **Only** in isolated, controlled networks
* **Only** for educational/testing purposes

By using this software, you confirm you understand and agree to these constraints.

---

## 🔧 Extending the Project

1. Add new card regex patterns in `config.yaml`
2. Hook alerts (e.g., Slack, email) into `handle_packet()`
3. Ship logs to Elasticsearch or Kafka
4. Add custom IDS/IPS integration
5. Build unit/integration tests under `tests/`

---

## 📄 License

**Educational Use Only** – All rights reserved.

```
```
