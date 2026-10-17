# ConnectTag Threat Engine (KMP)

[![](https://jitpack.io/v/connecttag/threat-engine-lib-kmp.svg)](https://jitpack.io/#connecttag/threat-engine-lib-kmp)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A high-performance, cross-platform Kotlin Multiplatform library providing unified threat detection, Indicators of Compromise (IOC) matching (`DomainSuffixTrie`, `IpRadixTree`), application security classification, risk engines, and cross-application security IPC navigation.

## Features

- 🌐 **Full Kotlin Multiplatform**: Android, JVM, and Apple Native targets.
- 🌳 **Fast In-Memory IOC Matching**:
  - `DomainSuffixTrie`: High-throughput reverse domain lookup matching malicious domains and wildcards.
  - `IpRadixTree`: Bitwise CIDR prefix matching for IPv4 and IPv6 suspicious subnets.
- 🛡️ **Threat Risk Engine**: Deterministic risk calculation and scoring based on permissions, network endpoints, and behavior flags.
- ☁️ **Edge Threat Intelligence**: Plug-and-play client contract (`SoorThreatApiClient`) for querying live edge security feeds (DoH verdicts, IP/domain reputation).
- 🔗 **Android Security IPC Companion**: `SoorSuiteNavigator` enables deep-link navigation and signature-protected threat broadcasts across security suite apps (`SoorNet`, `Hazm`, `SoorDefender`).

## Installation

Add JitPack repository to your root `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url = java.net.URI("https://jitpack.io") }
    }
}
```

Add the dependency to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.github.connecttag:threat-engine-lib-kmp:1.0.0")
}
```

## Quick Start

### 1. Fast Domain Suffix Matching

```kotlin
import org.connecttag.lib.threat.engine.matcher.DomainSuffixTrie
import org.connecttag.lib.threat.engine.model.ThreatCategory
import org.connecttag.lib.threat.engine.model.ThreatSeverity

val trie = DomainSuffixTrie()
trie.insert("malware-example.com", ThreatCategory.MALWARE, ThreatSeverity.CRITICAL)

val match = trie.match("sub.malware-example.com")
if (match != null) {
    println("Threat detected: ${match.category} (${match.severity})")
}
```

### 2. IP CIDR Matching

```kotlin
import org.connecttag.lib.threat.engine.matcher.IpRadixTree
import org.connecttag.lib.threat.engine.model.ThreatCategory

val ipTree = IpRadixTree()
ipTree.insert("198.51.100.0/24", ThreatCategory.PHISHING)

if (ipTree.contains("198.51.100.42")) {
    println("IP belongs to known phishing subnet!")
}
```

## License

```
Copyright 2026 Connect Tag

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
