# Secure Architecture Lab (Secure by Design)

Цей шаблон показує **архітектурну контрольованість**: система має “світитися” сигналами, які читають гейти.

## 🔦 Сигнали (що має бути видимим)
- **API контракт**: `openapi.json` (генерується з `main.py`) + DTO/`response_model`
- **Сигнали взаємодії**: JSON-логи у stdout + `X-Request-ID`
- **Secrets management**: Vault/CSI (секрети як файли у volume)
- **Policy-as-Code**: OPA (rego) як артефакт + conftest у CI
- **IaC**: Terraform як джерело правди + політики на `tfplan.json`
- **Supply chain**: SBOM + Trivy CVE gate + Cosign підпис/attestation

## ✅ Гейти у CI (обов’язкові)
- gitleaks (secrets)
- semgrep (SAST)
- OpenAPI export + diff з `openapi.json` (контроль змін контракту)
- conftest (K8s OPA policies)
- terraform validate/plan + conftest (Terraform OPA policies)
- trivy (CVE gate)
- syft SBOM (артефакт)
- cosign sign + attest (походження/незмінність)

## 🧪 Локальний запуск
```bash
export APP_PASSWORD="change-me"
uvicorn main:app --host 0.0.0.0 --port 8000
curl http://localhost:8000/health
