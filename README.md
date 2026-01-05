JS Miner Pro - Burp Suite Extension
===================================
![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)

**JS Miner Pro** is a lightweight, customizable Burp Suite extension designed to find hard-coded secrets, API endpoints, and hidden paths inside JavaScript, JSON, and HTML files.

Built using the modern **Montoya API**, it is optimized for Bug Hunters who need to dig deep into client-side code without the performance overhead of heavy scanners.

Why Use This?
-------------

Most passive scanners rely on Burp's default scanning scheduler, which often skips static files (`.js`, `.json`) to save performance during live audits.

**JS Miner Pro is different.** It implements the `HttpHandler` interface, meaning it sits directly in the HTTP traffic pipeline. It sees **every** response passing through the Proxy, Repeater, and Logger, ensuring no file is ignored even if it's cached or minified.

### Key Features

-   **Deep Traffic Inspection**: Scans all traffic (JS, HTML, JSON) for sensitive data.

-   **Fully Configurable Regex**: Add, edit, disable, or delete scanning rules on the fly.

-   **Persistent Settings**: Your custom regex rules are saved automatically and persist across restarts.

-   **Zero-Latency**: Optimized to ignore heavy media files (images, fonts) to keep your proxy fast.

-   **Smart UI**: Split-view interface with auto-highlighting. Click a finding to see exactly where it is in the response.

-   **Noise Filtering**: Built-in logic to ignore common false positives (like short paths).

Installation
------------

1.  Download the latest JAR file from the [Releases](https://github.com/tobiasGuta/JS-Miner-Pro-Burp-Suite-Extension/releases/download/JsMinerPro-2.0-Pro-all1212025/JsMinerPro-2.0-Pro-all.jar) page.

2.  Open **Burp Suite**.

3.  Navigate to **Extensions** -> **Installed**.

4.  Click **Add**.

5.  Select **Java** as the extension type.

6.  Select the `JsMinerPro-2.0-Pro-all.jar` file.

Building from Source
--------------------

If you want to modify the code or build it yourself, follow these steps. You need **Java 21** installed.

1.  Clone this repository:

    ```
    git clone https://github.com/tobiasGuta/JS-Miner-Pro-Burp-Suite-Extension.git
    cd js-miner-pro

    ```

2.  Build the "Fat JAR" (includes dependencies) using Gradle:

    -   **Linux/Mac**:

        ```
        ./gradlew shadowJar

        ```

    -   **Windows**:

        ```
        .\gradlew.bat shadowJar

        ```

3.  The compiled extension will be located in: `build/libs/JsMinerPro-2.0-Pro-all.jar`

Usage
-----

### 1\. The Results Tab

As you browse a target website, the extension passively scans responses. Findings appear in the **JS Miner -> Results** tab.

-   **Top Pane**: List of all found paths and secrets.

-   **Bottom Pane**: The Request/Response editor.

-   **Highlighting**: Click any row in the table, and the extension will automatically load the response and **highlight** the specific string found.

### 2\. The Configuration Tab

You can customize exactly what the extension looks for.

-   **Add Rule**: Create a new Regex pattern.

-   **Type**: Label it as a `PATH` or a `SECRET`.

-   **Active**: Toggle rules on/off without deleting them.

-   **Reset to Defaults**: If you mess up your rules, click this to restore the optimized default patterns.

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
