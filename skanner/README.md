# Skanner

<p align="center">
  <img src="docs/images/skanner-logo.png" alt="Skanner Logo" width="200"/>
</p>

Example of an advanced security scanning tool designed to detect secrets, credentials, and sensitive information in Git repositories. It helps developers and security teams identify potential security risks before they become vulnerabilities.

## Features

- **Comprehensive Secret Detection**: Scans Git repositories for exposed secrets and credentials
- **Multiple Secret Types**: Identifies various sensitive information including:
  - API keys
  - Passwords and credentials
  - Private keys (RSA, SSH, PGP)
  - OAuth tokens
  - Slack tokens
  - AWS keys and cloud credentials
  - High entropy strings
  - Database connection strings
  - Authorization headers
- **REST API**: Easy integration with CI/CD pipelines and other tools
- **Detailed Reporting**: Comprehensive reports with context for each finding
- **Low False Positives**: Advanced algorithms to reduce false positives
- **Customizable**: Add your own patterns via configuration

## Getting Started

### Prerequisites

- Go 1.16+ (for the scanner worker)
- Python 3.8+ (for the API server)
- FastAPI
- Docker (optional, for containerized deployment)

### Installation

#### From Source

1. Clone the repository:
```bash
git clone https://github.com/yourusername/skanner.git
cd skanner
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Build the Go worker (optional, pre-built binaries are included):
```bash
cd skanner/worker
go build -o skanner-worker
```

#### Using Docker

```bash
docker pull yourusername/skanner
docker run -p 8000:8000 yourusername/skanner
```

### Starting the Server

```bash
uvicorn skanner.main:app --host 0.0.0.0 --port 8000
```

## 📖 Usage

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scan-secrets` | POST | Scan a repository for secrets |
| `/scan-status/{scan_id}` | GET | Get the status of a scan |
| `/scan-results/{scan_id}` | GET | Get the results of a completed scan |

### Example: Scanning a Repository

```bash
curl -X POST "http://localhost:8000/scan-secrets" \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/example/repo"}'
```

### Response Format

```json
{
  "scan_id": "unique-scan-id",
  "repo_url": "https://github.com/example/repo",
  "secrets_found": [
    {
      "file": "config.js",
      "line": 42,
      "type": "api_key",
      "match": "api_key=abc123def456",
      "context": "const config = { api_key=abc123def456 };"
    }
  ],
  "scan_time": "2023-07-08T12:34:56Z",
  "total_files_scanned": 156,
  "scan_duration_seconds": 3.45
}
```

##  Configuration

### Custom Patterns

Create a YAML file with your custom patterns:

```yaml
patterns:
  - pattern:
      name: "custom_api_key"
      regex: "myapi[-_]?key['\"]?\\s*[:=]\\s*['\"]?([a-zA-Z0-9]{32,})"
  - pattern:
      name: "internal_token"
      regex: "int[-_]?token['\"]?\\s*[:=]\\s*['\"]?([a-zA-Z0-9_-]{24,})"
```

Then pass it to the scanner:

```bash
curl -X POST "http://localhost:8000/scan-secrets" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/example/repo",
    "custom_patterns_file": "/path/to/patterns.yaml"
  }'
```

## Security Considerations

- This tool is designed for security professionals to audit their own code
- Always ensure you have permission before scanning repositories that don't belong to you
- Handle scan results securely as they may contain sensitive information

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

Project Link: [https://github.com/yourusername/skanner](https://github.com/yourusername/skanner)
