JS Miner Pro - Burp Suite Extension
===================================
![Java](https://img.shields.io/badge/Java-17+-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)

**JS Miner Pro** is a powerful, customizable Burp Suite extension designed to find hard-coded secrets, API endpoints, and hidden paths inside JavaScript, JSON, and HTML files.

Built using the modern **Montoya API**, it is optimized for Bug Hunters who need to dig deep into client-side code without the performance overhead of heavy scanners.

Why Use This?
-------------

Most passive scanners rely on Burp's default scanning scheduler, which often skips static files (`.js`, `.json`) to save performance during live audits.

**JS Miner Pro is different.** It implements the `HttpHandler` interface, meaning it sits directly in the HTTP traffic pipeline. It sees **every** response passing through the Proxy, Repeater, and Logger, ensuring no file is ignored even if it's cached or minified.

### Key Features

#### Core Scanning
-   **Deep Traffic Inspection**: Scans all traffic (JS, HTML, JSON) for sensitive data
-   **Proxy History Scanning**: One-click button to scan all existing items in your Proxy HTTP History
-   **Zero-Latency**: Optimized to ignore heavy media files (images, fonts) to keep your proxy fast
-   **Smart MIME Detection**: Multiple detection methods (inferredMimeType, Content-Type header, URL extension)

#### Secret Detection
-   **80+ Built-in Regex Rules**: Comprehensive patterns for:
  - **Cloud Providers**: AWS (Access Keys, Secret Keys, ARNs), GCP (API keys, service accounts), Azure, Firebase, DigitalOcean, Heroku, Cloudflare
  - **Payment Services**: Stripe (secret/publishable keys), PayPal, Square
  - **Communication**: Twilio (Account SID, Auth Token), SendGrid, Mailgun, Mailchimp
  - **Social & Chat**: Discord webhooks, Telegram bot tokens, Slack webhooks
  - **Version Control**: GitHub tokens, GitLab tokens, Bitbucket credentials
  - **Authentication**: JWT tokens, OAuth Bearer tokens, Basic Auth credentials
  - **Databases**: MongoDB connection strings, PostgreSQL/MySQL URLs, Redis URLs
  - **SaaS**: Sentry DSN, Datadog API keys, Segment, Mixpanel, Intercom, Amplitude
  - **Hardcoded Secrets**: Password assignments, encoded credentials (Base64)
  - **Debug Endpoints**: /debug, /test, /dev, /admin paths
  - **Internal IPs**: 10.x.x.x, 172.16-31.x.x, 192.168.x.x ranges

#### Analysis Features
-   **Entropy Analysis**: Shannon entropy calculation to detect high-randomness strings (likely secrets)
  - Color-coded levels: VERY HIGH (red), HIGH (orange), MEDIUM (yellow), LOW (default)
-   **Duplicate Detection**: Track secrets that appear across multiple URLs (credential reuse indicator)
-   **Severity Levels**: AUTO, HIGH, MEDIUM, LOW, INFO - auto-assigned based on finding type

#### Configuration
-   **Fully Configurable Regex**: Add, edit, disable, or delete scanning rules on the fly
-   **Regex Validation**: Real-time validation prevents invalid patterns from breaking the scanner
-   **Rule Import/Export**: Share rule configurations as JSON files
-   **Noise Filtering**: Configure domain prefixes and noise domains to skip common CDN/analytics URLs
-   **Configurable Logging**: DEBUG, INFO, WARN, ERROR log levels

#### Data Management
-   **Persistent Settings**: Custom regex rules and findings saved automatically
-   **Auto-Save**: Findings saved on a configurable interval (default: 60 seconds)
-   **Export Options**: Export findings as JSON or CSV
-   **Smart UI**: Split-view interface with auto-highlighting. Click a finding to see where it is in the response

#### Integration
-   **Context Menu Actions**: Right-click findings to:
  - Copy finding/URL to clipboard
  - Send to Repeater/Intruder/Organizer
  - Delete individual findings
-   **Filtering**: Filter results by severity, type, or search text
-   **Sortable Columns**: Sort by severity, entropy, reuse count, etc.

Installation
------------

1.  Download the latest JAR file from the [Releases](https://github.com/tobiasGuta/JS-Miner-Pro-Burp-Suite-Extension/releases) page.

2.  Open **Burp Suite** (2023.10+ recommended for Montoya API compatibility).

3.  Navigate to **Extensions** -> **Installed**.

4.  Click **Add**.

5.  Select **Java** as the extension type.

6.  Select the `JsMinerPro-2.0-Pro.jar` file.

Building from Source
--------------------

If you want to modify the code or build it yourself, follow these steps. You need **Java 17+** installed.

1.  Clone this repository:

    ```bash
    git clone https://github.com/tobiasGuta/JS-Miner-Pro-Burp-Suite-Extension.git
    cd JS-Miner-Pro-Burp-Suite-Extension/JsMinerPro
    ```

2.  Build the "Fat JAR" (includes dependencies) using Gradle:

    -   **Linux/Mac**:

        ```bash
        ./gradlew shadowJar
        ```

    -   **Windows**:

        ```cmd
        .\gradlew.bat shadowJar
        ```

3.  The compiled extension will be located in: `build/libs/JsMinerPro-2.0-Pro.jar`

Usage
-----

### 1. The Results Tab

As you browse a target website, the extension passively scans responses. Findings appear in the **JS Miner -> Results** tab.

#### UI Components
-   **Scan Proxy History Button**: Click to scan all existing items in your Proxy HTTP History
-   **Filters**: Filter by Severity (HIGH/MEDIUM/LOW/INFO), Type (SECRET/URL/ENDPOINT/FILE), or search text
-   **Results Table**: Shows Severity, Type, Finding, Rule Name, Entropy, Reuse Count, URL
-   **Request/Response Editors**: View the original request and response for any finding
-   **Auto-Highlighting**: Click any row to highlight the finding in the response

#### Understanding Columns
| Column | Description |
|--------|-------------|
| Severity | HIGH (secrets), MEDIUM (endpoints), LOW (paths), INFO (debug info) |
| Type | SECRET, URL, ENDPOINT, FILE, INFO |
| Finding | The matched string |
| Rule Name | Which regex rule found this |
| Entropy | LOW/MEDIUM/HIGH/VERY HIGH - higher = more likely a real secret |
| Reuse | Number of different URLs where this exact secret appears |
| URL | Where the finding was discovered |

#### Context Menu (Right-Click)
- **Copy Finding** - Copy the matched secret/path to clipboard
- **Copy URL** - Copy the source URL
- **Send to Repeater** - Open request in Repeater tab
- **Send to Intruder** - Open request in Intruder tab
- **Send to Organizer** - Add to Organizer for later review
- **Delete Finding** - Remove the selected finding

#### Export Options
- **Export JSON** - Full finding details in JSON format
- **Export CSV** - Spreadsheet-compatible format

### 2. The Configuration Tab

Customize exactly what the extension looks for.

#### Rules Management Tab
-   **Add Rule**: Create a new regex pattern with name, pattern, type, and severity
-   **Edit Rule**: Double-click to modify existing rules
-   **Active Toggle**: Enable/disable rules without deleting them
-   **Regex Validation**: Patterns are validated before saving
-   **Reset to Defaults**: Restore the optimized default patterns (80+ rules)
-   **Import/Export**: Share rule configurations as JSON

#### General Settings Tab
-   **Noise Domains**: Skip scanning responses from these domains (e.g., google-analytics.com, cdn.jsdelivr.net)
-   **Noise Prefixes**: Skip paths starting with these prefixes (e.g., /static/, /assets/)
-   **Log Level**: Control verbosity (DEBUG, INFO, WARN, ERROR)

Tips for Bug Hunters
--------------------

1. **Start Fresh**: Click "Scan Proxy History" after loading the extension to analyze all existing traffic

2. **Focus on High Entropy**: Sort by entropy column - VERY HIGH entropy findings are most likely to be real secrets

3. **Check Reuse**: Findings appearing across multiple URLs (high reuse count) indicate widespread credential exposure

4. **Custom Rules**: Add company-specific patterns (internal domains, custom API key formats)

5. **Export Before Reporting**: Use JSON export for evidence collection when writing bug reports

6. **Filter Noise First**: Configure noise domains to skip CDNs and analytics before scanning

Technical Details
-----------------

- **Thread Pool**: Bounded queue (1000) with 4 worker threads for efficient parallel scanning
- **Regex Timeout**: 5-second timeout per regex match to prevent ReDoS
- **Auto-Save**: Findings persisted every 60 seconds to prevent data loss
- **MIME Filtering**: Skips images, fonts, PDFs, videos, and other binary content

License
-------

MIT License - Feel free to use, modify, and distribute.

Contributing
------------

Pull requests welcome! Please ensure your changes build successfully with `./gradlew shadowJar` before submitting.

### Default Regex Patterns

The extension comes pre-loaded with these battle-tested patterns:

| Rule Name              | Regex |
|------------------------|-------|
| Generic High-Entropy Secret | `(?i)(?:secret|token|password|auth|key)['"]?\s*[:=]\s*['"]?([A-Za-z0-9\-_:/.+=]{20,})['"]?` |
| AWS Key ID             | `(AKIA[0-9A-Z]{16})` |
| Google API Key         | `(AIza[0-9A-Za-z\-_]{35})` |
| Stripe Live Key        | `(sk_live_[0-9a-zA-Z]{24,})` |
| GitHub PAT             | `(ghp_[0-9a-zA-Z]{36})` |
| Slack Token            | `(xox[baprs]-[0-9a-zA-Z\-]{10,48})` |
| JWT Token              | `(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)` |
| Private Key            | `(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)` |
| MongoDB URL            | `(mongodb(?:\+srv)?://[^\s"'<>]+)` |
| PostgreSQL URL         | `(postgres(?:ql)?://[^\s"'<>]+)` |
| Generic Path           | `['"](/[a-zA-Z0-9/._-]{8,})['"]` |
| API Endpoint           | `(?i)["']((?:https?:)?//[^"']+/api/[a-zA-Z0-9/_-]+)["']` |
| GraphQL Path           | `(?i)["'](/graphql[a-zA-Z0-9/_-]*)["']` |
| Full URL               | `["'](https?://[^\s"'<>]{10,})["']` |
| WebSocket URL          | `["'](wss?://[^\s"'<>]{10,})["']` |
| S3 Bucket URL          | `(https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"'<>']*)` |
| Azure Blob URL         | `(https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net[^\s"'<>']*)` |
| GCP Storage URL        | `(https?://storage\.googleapis\.com/[^\s"'<>']*)` |
| Email Address          | `([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})` |
| Sensitive File         | `(?i)["']([a-zA-Z0-9_/.-]+\.(?:sql|csv|json|xml|yml|log|conf|ini|env|bak|key|pem|crt|pfx))["']` |

<img width="1916" height="1002" alt="Screenshot 2026-03-09 224838" src="https://github.com/user-attachments/assets/5f4c4601-b1b2-4448-92df-b9823549cadf" />

<img width="1919" height="995" alt="image" src="https://github.com/user-attachments/assets/834ffe5e-3fc6-4d2a-8218-08d1373f1bfd" />

<img width="1919" height="997" alt="image" src="https://github.com/user-attachments/assets/1b8ea6eb-b55f-4b8b-a8f6-25e7d2ac584a" />

<img width="1919" height="1000" alt="image" src="https://github.com/user-attachments/assets/cfd9d2f8-de5c-426c-b09d-28f8ec520e11" />

Disclaimer
----------

This tool is for educational purposes and authorized security testing only. Do not use this tool on systems you do not have permission to test. The author is not responsible for any misuse.
---

<div align="center">
  <h3>☕ Support My Journey</h3>
</div>


<div align="center">
  <a href="https://www.buymeacoffee.com/tobiasguta">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" />
  </a>
</div>
