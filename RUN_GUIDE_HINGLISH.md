# RUN GUIDE (Hinglish) — Risk Drift Framework

Ye guide un logon ke liye hai jinhe Python nahi aata. Har command copy-paste karke chalao.
Saare commands project folder (`risk_drift_framework/`) ke andar chalane hain.

---

## 1. Ek baar setup (Ubuntu 22.04 / 24.04)

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip unzip curl
unzip risk_drift_framework.zip && cd risk_drift_framework
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# OPA (policy engine) install
curl -L -o opa https://github.com/open-policy-agent/opa/releases/download/v1.4.2/opa_linux_amd64_static
chmod 755 opa && sudo mv opa /usr/local/bin/opa
opa version
```

Check karo sab theek hai:
```bash
opa test policies/          # PASS: 22/22 aana chahiye
python -m pytest -q         # 152 passed aana chahiye
```

---

## 2. Framework kaise chalta hai (ek cycle)

```
Ubuntu machine → collector (8 checks) → OPA/Rego (COMPLIANT / NON_COMPLIANT) → SQLite me save
→ pichhle run se compare (configuration drift) → risk score R = 0.45V + 0.25C + 0.20D + 0.10A
→ ΔR (risk drift) → dashboard
```

| Letter | Matlab |
|---|---|
| V | Vulnerability — Greenbone/OpenVAS scan ke findings (CVSS) |
| C | Compliance — 8 controls me kitne fail |
| D | Drift — kitni configuration badli (naye violations) |
| A | Asset criticality — machine kitni important hai (Low/Medium/High/Critical) |

---

## 3. Main commands

```bash
python cli.py init-db                                    # database banao
sudo -E .venv/bin/python cli.py assess --asset-id ubuntu-vm-01     # ek assessment (root se)
python cli.py import-greenbone --asset-id ubuntu-vm-01 --file report.xml   # Greenbone report daalo
python cli.py score --asset-id ubuntu-vm-01              # risk score dobara nikalo
sudo -E .venv/bin/python cli.py monitor --asset-id ubuntu-vm-01 --interval 3600   # har ghante apne-aap check (Ctrl+C se band)
streamlit run app.py                                     # dashboard: http://localhost:8501
```

Pehle `config/asset_policy.json` me apni VM ka `ip_address` (jo Greenbone scan karta hai) daal dena.

---

## 4. Asli (REAL) drift experiment — paper ke results

**Sirf apni lab VM pe chalao** (ye script jaan-bujh ke security settings kharab karti hai, phir theek karti hai).
VM ka snapshot pehle le lo, aur ek dusra SSH/console session khula rakho.

```bash
sudo apt install -y openssh-server ufw libpam-pwquality unattended-upgrades vsftpd
sudo TRIALS=3 bash lab/drift_experiment.sh all       # 3 baar × 12 assessments
python cli.py --db data/real_lab.sqlite3 lab-report  # result table
python cli.py figures                                # paper ke graphs (figures/ folder)
sudo bash lab/drift_experiment.sh restore            # VM ko original settings pe wapas
```

Experiment ke 12 steps (har trial me):

| Step | Kya hota hai | Kaunsa control fail hona chahiye |
|---|---|---|
| R1 | sab harden (baseline) | koi nahi |
| R2 | kuch nahi badla | koi nahi (false drift check) |
| R3 | `PermitRootLogin yes` | SSH-001 |
| R4 | UFW firewall off | FW-001 |
| R5 | vsftpd (FTP) service chalu | SVC-001 |
| R6 | `/etc/shadow` permission 0644 | FILE-001 |
| R7 | SSH password login on | SSH-002 |
| R8 | password minlen 8 | PWD-001 |
| R9 | pam_faillock (account lockout) hata diya | LOCK-001 |
| R10 | automatic security updates off | UPD-001 |
| R11 | sab wapas theek (remediation) | sab CORRECTED |
| R12 | kuch nahi badla | koi nahi |

Hamare lab container pe result: **24/24 changes detect hue, 0 false drift, 24/24 remediation pehchaane gaye.**
Risk 13.6 se 95.5 tak gaya aur remediation ke baad 81.8 points gira.

---

## 5. Kaunsa data asli hai, kaunsa synthetic

| Part | Data |
|---|---|
| Evidence collection, OPA results, drift, risk score (C, D, A), ΔR | **REAL** — lab container (`data/real_lab.sqlite3`) |
| Greenbone/OpenVAS findings (V) | **SYNTHETIC** report files — asli scan nahi tha |
| 17 evaluation scenarios | SYNTHETIC input, lekin asli pipeline (OPA, SQLite) |
| Baseline comparison (CVSS-only vs proposed) | SYNTHETIC 6 assets |

Dashboard me har row pe `HOST` (asli) ya `SYNTHETIC` likha aata hai. Paper me bhi yahi likhna.

**Limitations (paper me zaroor likhna):**
1. Lab host ek Ubuntu 24.04 container tha (systemd PID 1 nahi) — services `/proc` se padhi gayi.
2. Asli Greenbone scan nahi tha, isliye real data pe V missing hai → score PARTIAL.
3. Final dissertation ke liye yahi experiment full Ubuntu VM pe chala lena best rahega.

---

## 6. Dashboard ke 9 pages

1. Overview  2. Compliance checks  3. Configuration drift  4. Vulnerabilities  5. Risk prioritisation
6. Risk drift trend  7. Risk explanations  8. Assessment history & data quality  9. Method comparison

Demo dekhne ke liye: `RDF_DB=data/showcase.sqlite3 streamlit run app.py`
(isme asli lab experiment + synthetic demo assets dono hain, label ke saath).

---

## 7. Viva me puchhe jaane wale sawaal (short jawab)

* **Drift kaise detect hota hai?** Har run ka evidence normalize karke (timestamp, order, whitespace hata ke)
  pichhle run se compare hota hai; status COMPLIANT → NON_COMPLIANT ho to NEW_NON_COMPLIANCE.
* **False drift kaise roka?** Timestamps, list order, line numbers aur collection method ignore hote hain.
  R2/R12 (no change) runs me 0 drift aaya.
* **Missing data ko kya mana?** Kabhi "safe" nahi — UNKNOWN, aur score me bounds (range) dikhte hain.
* **Weights kahan se aaye?** `config/risk_model.json` — configurable; sensitivity analysis
  `evaluate-baselines` me hai.
