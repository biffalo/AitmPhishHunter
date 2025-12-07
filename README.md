# AitmPhishHunter

PowerShell script for hunting **Adversary-in-the-Middle (AiTM)** phishing pages (e.g., Evilginx) by analyzing **Chrome** and **Edge (Chromium-based)** history and favicon databases **for all users** on a Windows system.

The core idea:

> **Detect non-Microsoft URLs that are using the Microsoft login favicon**, a strong heuristic for Evilginx-style AiTM phishing infrastructure.

> ⚠️ **Status:** This tool is under active development. It is intended to **assist** in threat hunting and BEC investigations — **not** replace a full incident response process.

---

## ⚡ Features

* 🔍 Scans **Chrome** and **Edge** browser history for all user profiles under `C:\Users`
* 🕒 Analyzes **recent history** only (default: last **14 days**)
* 🧠 Correlates visited URLs with their **favicon** stored in SQLite DBs
* 🧪 Computes SHA1 hash of favicon blobs to identify the **Microsoft login icon**
* 🛑 Uses an extensive **exclusion list** to dramatically reduce false positives
* 🗂 Exports detected suspicious URLs to timestamped per-user CSV files
* 🔒 Handles file locks by creating temporary copies of history and favicon DBs

---

## 🧭 How It Works

1. **Downloads SQLite provider (`System.Data.SQLite.dll`)** to `C:\temp`
2. **Loads the DLL** so PowerShell can query Chromium SQLite databases
3. **Enumerates valid user profiles** under `C:\Users`
4. **Finds Chrome and Edge profiles** (`Default`, fallback `Profile 1`)
5. **Copies browser DBs** (`History` + `Favicons`) to `%TEMP%`
6. **Queries visit history** for entries within the configured date window
7. **Matches visited URLs to favicon records**
8. **Calculates SHA1 hash of favicon blobs**
9. Flags a visit when:

   * Favicon hash matches:

     ```
     2153f0aa2e30bf0940b6589b1e2fb78f8b337f27
     ```

     *(Microsoft login favicon)*
   * AND the domain/path/query is **not excluded**
10. **Outputs findings** in console + CSV

---

## 📦 Requirements

* Windows 10/11 or Windows Server
* PowerShell 5.1+
* Internet access to download SQLite binaries
* Permission to read user browser histories (run as Administrator)

---

## 🚀 Installation

```powershell
git clone https://github.com/<your-user>/<your-repo>.git
cd <your-repo>
```

Unblock the script if needed:

```powershell
Unblock-File .\AiTM-Favicon-Hunter.ps1
```

Ensure `C:\temp` exists:

```powershell
New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null
```

---

## ▶️ Usage

Open PowerShell **as Administrator** and run:

```powershell
.\AiTM-Favicon-Hunter.ps1
```

The script will automatically:

* Download SQLite provider
* Scan all user Chrome/Edge profiles
* Print any suspicious URLs
* Export findings to:

```
C:\temp\BrowsingHistory-<username>-YYYYMMDD_HHMMSS.csv
```

---

## 🖥 Example Console Output

```
Processing user: alice

Potential AiTM URLs were found for user alice
==============================
URL                                                         VisitTime
---                                                         ---------
https://example-login[.]com/                                11/30/2025 10:42:13 AM
https://evilginx-redirect[.]io/login                        11/30/2025 10:44:56 AM
==============================
Potential AiTM URLs for user alice exported to C:\temp\BrowsingHistory-alice-20251207_104500.csv
```

---

## 🔧 Configuration & Tuning

### Change the Lookback Window

Current value in script:

```powershell
$cutoffDate = (Get-Date).AddDays(-14)
```

To scan last 90 days:

```powershell
$cutoffDate = (Get-Date).AddDays(-90)
```

---

### Excluded Domain List

The script includes a carefully vetted exclusion list of domains such as:

* Microsoft 365 / Azure / GCC / GCC High
* SSO platforms
* Security vendors
* Microsoft-branded redirects
* Known benign patterns found during field investigations

Location in script:

```powershell
$excludedDomains = @(
    "microsoftonline.com",
    "outlook.com",
    "service-now.com",
    "urldefense.proofpoint.com",
    "mimecastprotect.com",
    "1drv.ms",
    "sharepoint.com",
    ...
)
```

> ⚠️ **Warning:** Changing this list can create false negatives.
> Add entries **only if you fully understand the domains being excluded.**

---

### Path & Query Exclusions

The script ignores URLs with paths typical of legitimate authentication flows, such as:

* `/adfs/`
* `/idp/`
* `/browsersso/`
* `/accounts`
* `/identity`

It also excludes requests with OAuth parameters (e.g., `client_id`, `state`, `code_challenge`).

These drastically reduce noise from legitimate login flows.

---

## ⚠️ Limitations

* Heuristic detection only — adversaries may change favicons or techniques
* Only inspects Chromium-based browsers
* Only checks Default + Profile 1
* Local machine only — not remote/historical logs
* Browsing history may have been cleared
* Does **not** block or remediate threats — detection only

---

## 🛠 Operational Guidance

Use this script for:

* **BEC investigations**
* **Suspected account takeover**
* **Post-incident forensic enrichment**
* **Baseline hunts across endpoints**

Combine with:

* Proxy logs
* CT logs
* Identity provider sign-in logs
* DNS histories
* SOAR enrichment tools

---

## 🗺 Roadmap

* [ ] Support multiple arbitrary Chromium profiles
* [ ] Accept CLI parameters for user, browser, and lookback period
* [ ] JSON export format
* [ ] Convert into a PowerShell module
* [ ] Add multithreading for faster scans

---

## 🤝 Contributing

Pull requests and issue reports are welcome!

* Improve exclusions
* Add new detection heuristics
* Report false positives
* Suggest new features
