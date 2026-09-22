# DOM-source-sink-locator

A Burp Suite extension that automatically scans textual Proxy responses for DOM source indicators and exports findings as CSV.

## What it does

- Registers a Montoya HTTP response handler and scans responses originating from Burp Proxy.
- Scans text-like content types (HTML, JavaScript, JSON, XML, SVG, and `text/*`) up to 2 MB per response.
- Shows concrete source expressions such as `location.search`, `location.hash`, `document.referrer`, `event.data`, and storage reads in the Source column. The findings table is capped at 5,000 rows.
- Includes a **Candidate sink(s) in response** column and separate sink rows for patterns such as `innerHTML`, `insertAdjacentHTML()`, `document.write()`, `eval()`, and `new Function()`. A sink listed with a source means only that both occur in the same response; it does not prove a data flow.
- Lets you pause or resume automatic Proxy scanning.
- Exports the currently displayed findings to UTF-8 CSV, or copies them as TSV.
- Keeps paste-in scanning, plus Proxy context-menu actions to send the selected response body to the Input tab or analyze it immediately.

This is static triage, not proof of XSS. A source match or source/sink co-occurrence does not establish that an attacker-controlled value reaches an executable sink. Confirm the runtime flow with DOM Invader or browser debugger breakpoints.

## Build

Requires JDK 17+ and Gradle. This build file supports older Gradle releases that do not have the `java {}` toolchain DSL. From this project folder, run:

```sh
gradle clean jar
```

The JAR is created at `build/libs/dom-source-sink-locator-1.0.0.jar`.

## Load into Burp

In Burp, open **Extensions → Installed → Add**, choose **Java**, and select the JAR from `build/libs`. Browse through Proxy with automatic scanning enabled, then open the `DOM-source-sink-locator` tab and its `Sources/Sinks/postMessage` results tab. Use **Export CSV** to save the visible findings.
