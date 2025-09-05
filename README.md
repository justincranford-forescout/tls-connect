# TLS Connect - FIPS Cipher Suite Analysis Tool

A comprehensive TLS cipher suite analysis application that demonstrates FIPS-compliant cryptographic operations using BouncyCastle FIPS providers in containerized environments.

## Quick Start 🚀

### One-Liner Execution Commands

**FIPS Container Environment (Recommended):**
```bash
docker run --platform linux/amd64 --rm \
  -v "$(pwd)":/workspace \
  crplatnpdacreaus001.azurecr.io/chainguard/adoptium-jdk-fips:adoptium-openjdk-21.0 \
  sh -c "cd /workspace && \
         mkdir -p target/classes && \
         javac src/main/java/com/justincranford/tls/TlsConnect.java -d target/classes && \
         java --class-path \"target/classes:\$JAVA_FIPS_CLASSPATH\" \
              -Djava.security.properties=/usr/lib/jvm/jdk-fips-config/kernel-entropy.java.security \
              com.justincranford.tls.TlsConnect"
```

**Host System (Standard Java):**
```bash
mkdir -p target/classes && \
javac src/main/java/com/justincranford/tls/TlsConnect.java -d target/classes && \
java --class-path target/classes com.justincranford.tls.TlsConnect
```

**Create an Alias for Repeated Use:**
Add this to your `~/.zshrc` or `~/.bashrc`:
```bash
alias tls-connect-fips='docker run --platform linux/amd64 --rm \
  -v "$(pwd)":/workspace \
  crplatnpdacreaus001.azurecr.io/chainguard/adoptium-jdk-fips:adoptium-openjdk-21.0 \
  sh -c "cd /workspace && \
         mkdir -p target/classes && \
         javac src/main/java/com/justincranford/tls/TlsConnect.java -d target/classes && \
         java --class-path \"target/classes:\$JAVA_FIPS_CLASSPATH\" \
              -Djava.security.properties=/usr/lib/jvm/jdk-fips-config/kernel-entropy.java.security \
              com.justincranford.tls.TlsConnect"'
```

Then simply run: `tls-connect-fips`

## Overview

This application performs detailed analysis of TLS cipher suites, categorizing them by security strength and FIPS compliance. It connects to servers (default: github.com) to test cipher suite compatibility and generates comprehensive analysis tables.

## Features

- ✅ **FIPS-140 Compliance**: Runs with BouncyCastle FIPS providers
- ✅ **Cipher Suite Analysis**: Ranks 37+ cipher suites by security strength (Mozilla guidelines)
- ✅ **Server Compatibility Testing**: Tests which cipher suites are supported by target servers
- ✅ **Detailed Analysis Tables**: Separate FIPS vs Non-FIPS analysis with support/enabled status
- ✅ **Certificate Chain Analysis**: Displays complete certificate chain information with validation dates
- ✅ **Containerized Deployment**: Optimized for FIPS-enabled container environments
- ✅ **Standalone Application**: No external dependencies beyond JDK and BouncyCastle FIPS
- ✅ **Comprehensive Testing**: Individual cipher suite server compatibility validation
- ✅ **Security-First Design**: Only enables TLS 1.2+ protocols, comprehensive fallback mechanisms

## Project Structure

```
tls-connect/
├── src/
│   ├── main/java/com/justincranford/tls/
│   │   └── TlsConnect.java                 # Main application
│   └── test/java/com/justincranford/tls/
│       └── TlsConnectTests.java           # JUnit 5 tests
├── pom.xml                                # Maven configuration (no Spring Boot)
└── README.md                              # This file
```

## Maven Configuration

### Group ID and Package Structure
- **Group ID**: `com.justincranford.tls`
- **Artifact ID**: `tls-connect`  
- **Main Package**: `com.justincranford.tls`
- **Main Class**: `com.justincranford.tls.TlsConnect`

### Maven Execution Plugin
The project includes the Maven exec plugin configured to run the main class:
```xml
<plugin>
    <groupId>org.codehaus.mojo</groupId>
    <artifactId>exec-maven-plugin</artifactId>
    <version>3.1.0</version>
    <configuration>
        <mainClass>com.justincranford.tls.TlsConnect</mainClass>
    </configuration>
</plugin>
```

## Prerequisites

- Java 21 (OpenJDK or similar) - for host execution
- Docker - for FIPS container execution  
- Maven 3.6+ (optional, for building with Maven)
- Network access for TLS connections

## Alternative Execution Methods

### Maven Execution (Host)
```bash
# Build and run with Maven
mvn clean compile exec:java -Dexec.mainClass="com.justincranford.tls.TlsConnect"
```

### Pre-compiled Container Execution
If you already have compiled classes, use the shorter version:
```bash
docker run --platform linux/amd64 --rm \
  -v "$(pwd)":/workspace \
  crplatnpdacreaus001.azurecr.io/chainguard/adoptium-jdk-fips:adoptium-openjdk-21.0 \
  sh -c "cd /workspace && \
         java --class-path \"target/classes:\$JAVA_FIPS_CLASSPATH\" \
              -Djava.security.properties=/usr/lib/jvm/jdk-fips-config/kernel-entropy.java.security \
              com.justincranford.tls.TlsConnect"
```

## Manual Container Setup (Advanced)

For detailed exploration and debugging, you can work interactively:

### Step 1: Start FIPS Container
```bash
docker run --platform linux/amd64 -it --rm \
  -v "$(pwd)":/workspace \
  crplatnpdacreaus001.azurecr.io/chainguard/adoptium-jdk-fips:adoptium-openjdk-21.0 \
  sh
```

### Step 2: Navigate to Workspace
```bash
cd /workspace
```

### Step 3: Verify FIPS Configuration
```bash
# Check Java version and FIPS settings
java --version

# Verify BouncyCastle FIPS providers
ls -la /usr/share/java/bouncycastle-fips/

# Check security configuration
cat /usr/lib/jvm/java-21-adoptium/conf/security/java.security | grep -A 5 -B 5 "security.provider"
```

**Expected FIPS Providers:**
```
security.provider.1=org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider C:HYBRID;ENABLE{ALL};
security.provider.2=org.bouncycastle.jsse.provider.BouncyCastleJsseProvider fips:BCFIPS
security.provider.3=org.bouncycastle.entropy.provider.BouncyCastleEntropyProvider
```

### Step 4: Compile Application
```bash
javac src/main/java/com/justincranford/tls/TlsConnect.java -d target/classes
```

### Step 5: Run with Kernel Entropy (Recommended)
```bash
java --class-path "target/classes:\$JAVA_FIPS_CLASSPATH" \
  -Djava.security.properties=/usr/lib/jvm/jdk-fips-config/kernel-entropy.java.security \
  com.justincranford.tls.TlsConnect
```

**Why Kernel Entropy?**
The JENT (Java Entropy) provider can cause crashes in containerized environments, especially when running AMD64 containers on ARM64 hosts (Apple Silicon Macs) due to CPU instruction emulation issues. The kernel entropy configuration uses `/dev/random` instead.

**Technical Details**:
- **Default FIPS config**: Uses `org.bouncycastle.entropy.provider.BouncyCastleEntropyProvider` with JENT (Jitterentropy Library) 
- **Architecture Issue**: JENT native libraries expect specific x86_64 entropy instructions (RDTSC, RDRAND)
- **Emulation Problem**: ARM64→AMD64 emulation (Rosetta/QEMU) may not properly support these instructions
- **Kernel entropy config**: Switches to kernel-provided entropy via `/dev/random`
- **Key differences**:
  ```bash
  # Default: Uses BouncyCastle entropy provider (can crash in emulated environments)
  securerandom.strongAlgorithms=ENTROPY:BCRNG
  
  # Kernel entropy: Uses kernel /dev/random (emulation-safe)
  securerandom.source=file:/dev/random
  securerandom.strongAlgorithms=NativePRNGBlocking:SUN,DRBG:SUN
  ```

**From the container documentation**: *"This security file can be used to opt-out of bc-rng-jent userspace certified entropy source, and instead use kernel provided entropy. The strength of keys generated is affected by the available entropy."*

## Expected Output

### FIPS Provider Loading
```
NOTE: Picked up JDK_JAVA_OPTIONS: --add-exports=java.base/sun.security.internal.spec=ALL-UNNAMED --add-exports=java.base/sun.security.provider=ALL-UNNAMED -Djavax.net.ssl.trustStoreType=FIPS
Picked up JAVA_TOOL_OPTIONS: -Djava.class.path=/usr/share/java/bouncycastle-fips/bc-fips.jar
Sep 04, 2025 12:34:56 AM com.justincranford.tls.TlsConnect main
INFO: Attempting to manually load BouncyCastle FIPS providers...
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO: Successfully loaded BouncyCastleFipsProvider
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO: Successfully loaded BouncyCastleJsseProvider
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO: === SECURITY PROVIDERS ===
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO: 1. BCFIPS v2.101: BouncyCastle Security Provider (FIPS edition) v2.1.1
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO: 2. BCJSSE v2.012: Bouncy Castle JSSE Provider Version 2.1.20
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO: 3. BCRNG v1.36: Bouncy Castle JENT Entropy Provider v1.3.6 [x86_64_linux 7 successfully loaded]
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO: 4. SUN v21: SUN (DSA key/parameter generation; DSA signing; SHA-1, MD5 digests; SecureRandom; X.509 certificates; PKCS12, JKS & DKS keystores; PKIX CertPathValidator; PKIX CertPathBuilder; LDAP, Collection CertStores, JavaPolicy Policy; JavaLoginConfig Configuration)
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO: 5. SunJGSS v21: Sun (Kerberos v5, SPNEGO)
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO: 6. SunSASL v21: Sun SASL provider(implements client mechanisms for: DIGEST-MD5, EXTERNAL, PLAIN, CRAM-MD5, NTLM; server mechanisms for: DIGEST-MD5, CRAM-MD5, NTLM)
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO: 7. XMLDSig v21: XMLDSig (DOM XMLSignatureFactory; DOM KeyInfoFactory; C14N 1.0, C14N 1.1, Exclusive C14N, Base64, Enveloped, XPath, XPath2, XSLT TransformServices)
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO: 8. SunPCSC v21: Sun PC/SC provider
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO: 9. JdkLDAP v21: JdkLDAP Provider (implements LDAP CertStore)
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO: 10. JdkSASL v21: JDK SASL provider(implements client and server mechanisms for GSSAPI)
```

### Available SSL Context Algorithms
```
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO: === AVAILABLE SSL CONTEXT ALGORITHMS ===
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO:   TLSV1
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO:   TLS
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO:   TLSV1.1
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO:   TLSV1.3
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO:   DEFAULT
Sep 04, 2025 12:34:57 AM com.justincranford.tls.TlsConnect main
INFO:   TLSV1.2
```

### TLS Connection Information  
```
Sep 04, 2025 12:34:58 AM com.justincranford.tls.TlsConnect main
INFO: Trying SSLContext algorithm: TLSv1.3
Sep 04, 2025 12:34:58 AM com.justincranford.tls.TlsConnect main
INFO: Successfully initialized SSLContext with algorithm: TLSv1.3
Sep 04, 2025 12:34:58 AM com.justincranford.tls.TlsConnect main
INFO: Establishing TLS connection to github.com:443...
Sep 04, 2025 12:34:59 AM com.justincranford.tls.TlsConnect main
INFO: === TLS CONNECTION INFORMATION ===
Sep 04, 2025 12:34:59 AM com.justincranford.tls.TlsConnect main
INFO: Connected to: github.com
Sep 04, 2025 12:34:59 AM com.justincranford.tls.TlsConnect main
INFO: Protocol: TLSv1.3
Sep 04, 2025 12:34:59 AM com.justincranford.tls.TlsConnect main
INFO: Negotiated Cipher Suite: TLS_AES_128_GCM_SHA256
```

### Complete FIPS Cipher Suite Analysis Table
```
Sep 04, 2025 12:34:59 AM com.justincranford.tls.TlsConnect main
INFO: === CIPHER SUITE ANALYSIS ===
Sep 04, 2025 12:34:59 AM com.justincranford.tls.TlsConnect analyzeCipherSuites
INFO: Testing 36 unique cipher suites for server compatibility...
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displayCipherSuiteTable
INFO: 
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displayCipherSuiteTable
INFO: CIPHER SUITE ANALYSIS TABLE (Ranked by Security Strength) - FIPS ONLY
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displayCipherSuiteTable
INFO: ==========================================================
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displayCipherSuiteTable
INFO: 
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displayTableHeader
INFO: | Rank     | Category     | Protocol   | FIPS   | Cipher Suite                                       | Client Support  | Client Enabled  | Server Support  | Server Enabled  |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displayTableHeader
INFO: |----------+--------------+------------+--------+----------------------------------------------------+-----------------+-----------------+-----------------+-----------------|
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 1        | Modern       | TLSv1.3    | YES    | TLS_AES_256_GCM_SHA384                             | YES             | YES             | YES             | YES             |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 3        | Modern       | TLSv1.3    | YES    | TLS_AES_128_GCM_SHA256                             | YES             | YES             | YES             | YES             |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 4        | Intermediate | TLSv1.2    | YES    | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384            | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 6        | Intermediate | TLSv1.2    | YES    | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256            | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 7        | Intermediate | TLSv1.2    | YES    | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384              | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 9        | Intermediate | TLSv1.2    | YES    | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256              | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 10       | Intermediate | TLSv1.2    | YES    | TLS_DHE_RSA_WITH_AES_256_GCM_SHA384                | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 12       | Intermediate | TLSv1.2    | YES    | TLS_DHE_RSA_WITH_AES_128_GCM_SHA256                | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 13       | Intermediate | TLSv1.2    | YES    | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384            | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 14       | Intermediate | TLSv1.2    | YES    | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256            | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 15       | Intermediate | TLSv1.2    | YES    | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384              | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 16       | Intermediate | TLSv1.2    | YES    | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256              | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 21       | Old          | TLSv1.2    | YES    | TLS_DHE_RSA_WITH_AES_256_CBC_SHA256                | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 22       | Old          | TLSv1.2    | YES    | TLS_DHE_RSA_WITH_AES_128_CBC_SHA256                | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displayTableFooter
INFO: |----------+--------------+------------+--------+----------------------------------------------------+-----------------+-----------------+-----------------+-----------------|
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displayTableFooter
INFO: 
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displaySummaryStatistics
INFO: SUMMARY (FIPS CIPHER SUITES):
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displaySummaryStatistics
INFO:   Total Cipher Suites: 14
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displaySummaryStatistics
INFO:   Client Supported: 14
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displaySummaryStatistics
INFO:   Client Enabled: 14
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displaySummaryStatistics
INFO:   Server Supported: 2
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displaySummaryStatistics
INFO:   Common (Both Enabled): 2
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displaySummaryStatistics
INFO: 
```

### Complete Non-FIPS Cipher Suite Analysis Table
```
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displayCipherSuiteTable
INFO: 
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displayCipherSuiteTable
INFO: CIPHER SUITE ANALYSIS TABLE (Ranked by Security Strength) - NON-FIPS ONLY
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displayCipherSuiteTable
INFO: ==========================================================
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displayCipherSuiteTable
INFO: 
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displayTableHeader
INFO: | Rank     | Category     | Protocol   | FIPS   | Cipher Suite                                       | Client Support  | Client Enabled  | Server Support  | Server Enabled  |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displayTableHeader
INFO: |----------+--------------+------------+--------+----------------------------------------------------+-----------------+-----------------+-----------------+-----------------|
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 2        | Modern       | TLSv1.3    | NO     | TLS_CHACHA20_POLY1305_SHA256                       | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 5        | Intermediate | TLSv1.2    | NO     | TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256      | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 8        | Intermediate | TLSv1.2    | NO     | TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256        | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 11       | Intermediate | TLSv1.2    | NO     | TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256          | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 17       | Old          | TLSv1      | NO     | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 18       | Old          | TLSv1      | NO     | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 19       | Old          | TLSv1      | NO     | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                 | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 20       | Old          | TLSv1      | NO     | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                 | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 23       | Old          | SSL_v3     | NO     | TLS_DHE_RSA_WITH_AES_256_CBC_SHA                   | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 24       | Old          | SSL_v3     | NO     | TLS_DHE_RSA_WITH_AES_128_CBC_SHA                   | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 31       | Weak         | TLSv1.2    | NO     | TLS_DHE_DSS_WITH_AES_256_GCM_SHA384                | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 32       | Weak         | TLSv1.2    | NO     | TLS_DHE_DSS_WITH_AES_128_GCM_SHA256                | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 33       | Weak         | TLSv1.2    | NO     | TLS_DHE_DSS_WITH_AES_256_CBC_SHA256                | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 34       | Weak         | TLSv1.2    | NO     | TLS_DHE_DSS_WITH_AES_128_CBC_SHA256                | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 35       | Weak         | SSL_v3     | NO     | TLS_DHE_DSS_WITH_AES_256_CBC_SHA                   | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayKnownCipherSuites$4
INFO: | 36       | Weak         | SSL_v3     | NO     | TLS_DHE_DSS_WITH_AES_128_CBC_SHA                   | YES             | YES             | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayUnknownCipherSuites$7
INFO: | UNKNOWN  | Unknown      | Unknown    | UNKNOWN | TLS_AES_128_CCM_8_SHA256                           | YES             | NO              | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayUnknownCipherSuites$7
INFO: | UNKNOWN  | Unknown      | Unknown    | UNKNOWN | TLS_AES_128_CCM_SHA256                             | YES             | NO              | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayUnknownCipherSuites$7
INFO: | UNKNOWN  | Unknown      | Unknown    | UNKNOWN | TLS_DHE_RSA_WITH_AES_128_CCM                       | YES             | NO              | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayUnknownCipherSuites$7
INFO: | UNKNOWN  | Unknown      | Unknown    | UNKNOWN | TLS_DHE_RSA_WITH_AES_128_CCM_8                     | YES             | NO              | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayUnknownCipherSuites$7
INFO: | UNKNOWN  | Unknown      | Unknown    | UNKNOWN | TLS_DHE_RSA_WITH_AES_256_CCM                       | YES             | NO              | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayUnknownCipherSuites$7
INFO: | UNKNOWN  | Unknown      | Unknown    | UNKNOWN | TLS_DHE_RSA_WITH_AES_256_CCM_8                     | YES             | NO              | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayUnknownCipherSuites$7
INFO: | UNKNOWN  | Unknown      | Unknown    | UNKNOWN | TLS_ECDHE_ECDSA_WITH_AES_128_CCM                   | YES             | NO              | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayUnknownCipherSuites$7
INFO: | UNKNOWN  | Unknown      | Unknown    | UNKNOWN | TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8                 | YES             | NO              | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayUnknownCipherSuites$7
INFO: | UNKNOWN  | Unknown      | Unknown    | UNKNOWN | TLS_ECDHE_ECDSA_WITH_AES_256_CCM                   | YES             | NO              | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$displayUnknownCipherSuites$7
INFO: | UNKNOWN  | Unknown      | Unknown    | UNKNOWN | TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8                 | YES             | NO              | NO              | NO              |
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displayTableFooter
INFO: |----------+--------------+------------+--------+----------------------------------------------------+-----------------+-----------------+-----------------+-----------------|
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displayTableFooter
INFO: 
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displaySummaryStatistics
INFO: SUMMARY (NON-FIPS CIPHER SUITES):
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displaySummaryStatistics
INFO:   Total Cipher Suites: 26
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displaySummaryStatistics
INFO:   Client Supported: 26
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displaySummaryStatistics
INFO:   Client Enabled: 16
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displaySummaryStatistics
INFO:   Server Supported: 0
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displaySummaryStatistics
INFO:   Common (Both Enabled): 0
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect displaySummaryStatistics
INFO: 
```

### Server Certificate Chain Analysis
```
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO: Server Certificates:
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO:   Issuer Name: CN=Sectigo ECC Domain Validation Secure Server CA,O=Sectigo Limited,L=Salford,ST=Greater Manchester,C=GB
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO:   Subject Name: CN=github.com
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO:   Serial Number: 227830333772454795620750445496253172213
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO:   Not Before: Wed Feb 05 00:00:00 GMT 2025
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO:   Not After: Thu Feb 05 23:59:59 GMT 2026
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO:   Issuer Name: CN=USERTrust ECC Certification Authority,O=The USERTRUST Network,L=Jersey City,ST=New Jersey,C=US
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO:   Subject Name: CN=Sectigo ECC Domain Validation Secure Server CA,O=Sectigo Limited,L=Salford,ST=Greater Manchester,C=GB
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO:   Serial Number: 323523223200994243259439853290236540189
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO:   Not Before: Fri Nov 02 00:00:00 GMT 2018
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO:   Not After: Tue Dec 31 23:59:59 GMT 2030
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO:   Issuer Name: CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO:   Subject Name: CN=USERTrust ECC Certification Authority,O=The USERTRUST Network,L=Jersey City,ST=New Jersey,C=US
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO:   Serial Number: 114849002793238729640937462275813569940
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO:   Not Before: Tue Mar 12 00:00:00 GMT 2019
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO:   Not After: Sun Dec 31 23:59:59 GMT 2028
```

### SSL Session Details
```
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO: Enabled Protocols:
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$0
INFO:   TLSv1.3
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$0
INFO:   TLSv1.2
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO: Enabled Cipher Suites:
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_AES_256_GCM_SHA384
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_AES_128_GCM_SHA256
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_DHE_RSA_WITH_AES_256_CBC_SHA
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_DHE_DSS_WITH_AES_256_CBC_SHA
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_DHE_RSA_WITH_AES_128_CBC_SHA
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect lambda$main$1
INFO:   TLS_DHE_DSS_WITH_AES_128_CBC_SHA
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO: Maximum TLS Fragment Length: 0
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO: End Point Identification Algorithm: null
Sep 04, 2025 12:35:10 AM com.justincranford.tls.TlsConnect main
INFO: Server Name Indication: Not available
```

## Key Technical Details

### Comprehensive Cipher Suite Analysis
The application analyzes **37 ranked cipher suites** categorized by Mozilla Security guidelines:
- **Modern** (3): TLS 1.3 with AEAD ciphers
- **Intermediate** (13): TLS 1.2 with secure key exchange and encryption
- **Old** (10): Legacy TLS/SSL with backward compatibility  
- **Weak** (6): DSS-based or deprecated algorithms
- **Special** (1): Protocol-level security mechanisms
- **Unknown** (4+): CCM variants and unclassified cipher suites

Each cipher suite is tested individually for:
- ✅ Client support status
- ✅ Client enabled status  
- ✅ Server compatibility (live testing against target)
- ✅ FIPS compliance classification

### Architecture Changes Made
1. **Removed Spring Boot**: Converted from Spring Boot to standalone Java application
2. **Replaced SLF4J**: Uses JDK `java.util.logging.Logger` instead of SLF4J
3. **FIPS Provider Integration**: Dynamically loads BouncyCastle FIPS providers
4. **Fallback SSL Context**: Multiple fallback strategies for SSL context initialization
5. **Container Optimization**: Handles JENT entropy provider issues with kernel entropy fallback

### FIPS Compliance Features
- **BouncyCastle FIPS Providers**: Uses certified FIPS 140-2 cryptographic providers
- **FIPS Cipher Suite Classification**: Separates FIPS-approved from non-FIPS cipher suites
- **Secure Defaults**: Enables only TLSv1.2 and TLSv1.3 protocols
- **Certificate Validation**: Full certificate chain analysis with FIPS-compliant algorithms

### Cipher Suite Categories
- **Modern**: TLSv1.3 cipher suites (highest security)
- **Intermediate**: TLSv1.2 with modern algorithms
- **Old**: Legacy protocols (TLSv1, SSL_v3) - compatibility only
- **Weak**: Weak authentication or key exchange algorithms
- **Special**: Special-purpose cipher suites (e.g., renegotiation)

## Troubleshooting

### Container Crashes with SIGILL
**Problem**: Application crashes with `SIGILL` error in `libbcjent-jent.so`

**Root Cause**: The JENT (Jitterentropy Library) crashes are primarily due to **architecture emulation issues** when running AMD64 containers on ARM64 hosts (Apple Silicon Macs):

- **Host Architecture**: ARM64 (Apple Silicon Mac)
- **Container Architecture**: AMD64/x86_64 (forced by `--platform linux/amd64`)
- **CPU Emulation**: VirtualApple CPU emulation doesn't fully support x86_64 entropy instructions
- **JENT Requirements**: The native library `libbcjent-jent.so` requires specific CPU entropy features

**Detailed Technical Information**:
- **Provider Class**: `org.bouncycastle.entropy.provider.BouncyCastleEntropyProvider`
- **JAR File**: `/usr/share/java/bouncycastle-fips/bc-rng-jent.jar`
- **Native Libraries in JAR**:
  ```
  native/linux/arm64/jent/7/libbcjent-jent.so
  native/linux/arm64/jent/7/libjitterentropy.so.3.6.1
  native/linux/x86_64/jent/7/libbcjent-jent.so
  native/linux/x86_64/jent/7/libjitterentropy.so.3.6.1
  ```
- **Container Selects**: x86_64 native libraries since container runs AMD64
- **JENT Instructions**: Uses hardware-specific entropy gathering instructions (e.g., RDTSC, RDRAND)
- **Emulation Failure**: These instructions may not be properly emulated in Rosetta/QEMU translation layers
- **Result**: The SIGILL (Illegal Instruction) occurs when the native library tries to execute unsupported instructions

**Solution**: Use kernel entropy configuration to bypass JENT entirely:
```bash
-Djava.security.properties=/usr/lib/jvm/jdk-fips-config/kernel-entropy.java.security
```

**What this does**:
- Switches from `securerandom.strongAlgorithms=ENTROPY:BCRNG` (JENT-based)
- To `securerandom.source=file:/dev/random` and `securerandom.strongAlgorithms=NativePRNGBlocking:SUN,DRBG:SUN`
- Uses kernel entropy instead of userspace certified entropy source
- **Avoids native library calls entirely**, eliminating architecture emulation issues

### SSL Context Initialization Fails
**Problem**: Cannot initialize SSL context with BouncyCastle providers

**Solutions**:
1. Verify BouncyCastle FIPS JARs are on classpath
2. Check security provider configuration
3. Use fallback SSL context algorithms (TLS, Default)

### No Server-Supported Cipher Suites
**Problem**: All cipher suites show "Server Support: NO"

**Causes**:
1. Network connectivity issues
2. Firewall blocking HTTPS (port 443)
3. Server enforcing strict security policies

### BouncyCastle FIPS Providers Not Loading
**Problem**: Security providers fail to load even though JARs are present in `/usr/share/java/bouncycastle-fips/`

**Root Cause**: The container sets multiple environment variables, but `JAVA_TOOL_OPTIONS=-Djava.class.path=/usr/share/java/bouncycastle-fips/bc-fips.jar` only sets the `java.class.path` **system property**, not the actual JVM classpath.

**Container Environment Variables**:
- `JAVA_FIPS_CLASSPATH=/usr/share/java/bouncycastle-fips/*` - Intended classpath for FIPS JARs
- `CLASSPATH=/usr/share/java/bouncycastle-fips/*:./*:.` - Default shell classpath 
- `JAVA_TOOL_OPTIONS=-Djava.class.path=...` - System property (NOT runtime classpath)

**Explanation**:
- `JAVA_TOOL_OPTIONS` with `-Djava.class.path=...` sets a system property, NOT the runtime classpath
- When you use `--class-path target/classes`, it completely overrides/replaces the classpath
- Security providers in `java.security` are loaded by class name during JVM initialization
- These classes must be on the **actual classpath** to be loadable

**Solutions** (in order of preference):
```bash
# ✅ Option 1: Use environment variable (most flexible)
java --class-path "target/classes:$JAVA_FIPS_CLASSPATH" com.justincranford.tls.TlsConnect

# ✅ Option 2: Use hardcoded path (current approach)  
java --class-path 'target/classes:/usr/share/java/bouncycastle-fips/*' com.justincranford.tls.TlsConnect

# ❌ This fails - BC classes not on actual classpath
java --class-path target/classes com.justincranford.tls.TlsConnect
```

**Verification**: Check if providers load successfully by looking for these log messages:
```
INFO: Successfully loaded BouncyCastleFipsProvider
INFO: Successfully loaded BouncyCastleJsseProvider
```

## Testing

Run unit tests to verify functionality:
```bash
# In container or host
mvn test
```

**Test Coverage**:
- ✅ Class instantiation
- ✅ SSL context creation  
- ✅ Security provider availability
- ✅ SSL algorithm availability
- ✅ Application constants validation

## Container Environment Details

### Base Image
- **Image**: `crplatnpdacreaus001.azurecr.io/chainguard/adoptium-jdk-fips:adoptium-openjdk-21.0`
- **JDK**: Adoptium OpenJDK 21.0.8 with FIPS configuration
- **OS**: Alpine Linux (Chainguard minimal)

### FIPS Environment Variables
The container provides several environment variables for FIPS configuration:

```bash
# BouncyCastle FIPS classpath
JAVA_FIPS_CLASSPATH=/usr/share/java/bouncycastle-fips/*
CLASSPATH=/usr/share/java/bouncycastle-fips/*:./*:.

# Java system properties for FIPS
JAVA_TOOL_OPTIONS=-Djava.class.path=/usr/share/java/bouncycastle-fips/bc-fips.jar
JAVA_TRUSTSTORE_OPTIONS=-Djavax.net.ssl.trustStoreType=FIPS

# JDK module exports for FIPS providers
JDK_JAVA_OPTIONS=--add-exports=java.base/sun.security.internal.spec=ALL-UNNAMED --add-exports=java.base/sun.security.provider=ALL-UNNAMED -Djavax.net.ssl.trustStoreType=FIPS
JDK_JAVA_FIPS_OPTIONS=--add-exports=java.base/sun.security.internal.spec=ALL-UNNAMED --add-exports=java.base/sun.security.provider=ALL-UNNAMED
JDK_JAVAC_FIPS_OPTIONS=--add-exports=java.base/sun.security.internal.spec=ALL-UNNAMED --add-exports=java.base/sun.security.provider=ALL-UNNAMED
```

**Alternative Classpath Usage**: You can reference the environment variable in commands:
```bash
# Using JAVA_FIPS_CLASSPATH environment variable
java --class-path "target/classes:$JAVA_FIPS_CLASSPATH" com.justincranford.tls.TlsConnect
```

### FIPS Configuration Files
- **Main Config**: `/usr/lib/jvm/java-21-adoptium/conf/security/java.security`
  - Default FIPS configuration with BouncyCastle providers
  - Uses JENT (Jitterentropy Library) for entropy: `securerandom.strongAlgorithms=ENTROPY:BCRNG`
  - Can cause SIGILL crashes in containers due to hardware requirements

- **Kernel Entropy**: `/usr/lib/jvm/jdk-fips-config/kernel-entropy.java.security` ⭐ **Recommended**
  - Container-safe entropy configuration  
  - Uses kernel entropy: `securerandom.source=file:/dev/random`
  - Algorithms: `securerandom.strongAlgorithms=NativePRNGBlocking:SUN,DRBG:SUN`
  - **Purpose**: *"opt-out of bc-rng-jent userspace certified entropy source, and instead use kernel provided entropy"*

- **Unapproved Mode**: `/usr/lib/jvm/jdk-fips-config/unapproved.java.security`
  - For non-FIPS compliant operations (testing/development only)

### BouncyCastle FIPS Libraries
```
/usr/share/java/bouncycastle-fips/
├── bc-fips.jar           # Core FIPS provider
├── bctls-fips.jar        # TLS provider  
├── bcpkix-fips.jar       # PKI/X.509 support
├── bcutil-fips.jar       # Utilities
├── bc-rng-jent.jar       # Hardware entropy (problematic on emulated systems)
├── bcmail-fips.jar       # S/MIME
└── bcpg-fips.jar         # OpenPGP
```

**JENT (Jitterentropy) Details**:
- **JAR**: `bc-rng-jent.jar` contains `org.bouncycastle.entropy.provider.BouncyCastleEntropyProvider`
- **Native Libraries**: Contains both ARM64 and x86_64 versions:
  ```
  native/linux/arm64/jent/7/libbcjent-jent.so
  native/linux/arm64/jent/7/libjitterentropy.so.3.6.1
  native/linux/x86_64/jent/7/libbcjent-jent.so
  native/linux/x86_64/jent/7/libjitterentropy.so.3.6.1
  ```
- **Issue**: x86_64 libraries crash under ARM64→AMD64 emulation
- **Solution**: Use kernel entropy configuration to avoid native library calls

## Security Considerations

### FIPS 140-2 Compliance
- Uses only FIPS-approved cryptographic algorithms
- BouncyCastle FIPS providers are certified to FIPS 140-2 Level 1
- Entropy sourced from certified sources (`/dev/random` or hardware)

### Network Security
- Connects only to HTTPS endpoints (port 443)
- Validates complete certificate chains
- Supports modern TLS protocols only (1.2, 1.3)

### Container Security
- Runs with minimal Alpine Linux base
- No unnecessary system packages
- Isolated network namespace

## Performance Notes

- **Cipher Suite Testing**: Tests each cipher suite individually (~30-40 connections)
- **Network Latency**: Performance depends on target server response time
- **Container Overhead**: Minimal performance impact in containerized environment
- **Memory Usage**: Low memory footprint (~50-100MB)

## Testing

### Run Unit Tests
```bash
# Standard host environment
mvn test

# In FIPS container environment  
docker run --platform linux/amd64 --rm \
  -v "$(pwd)":/workspace \
  crplatnpdacreaus001.azurecr.io/chainguard/adoptium-jdk-fips:adoptium-openjdk-21.0 \
  sh -c "cd /workspace && mvn test"
```

### Test Mac Algorithm Spellings in FIPS Container
To verify Mac algorithm spelling compatibility in the FIPS environment:
```bash
# Quick Mac algorithm test in FIPS container
docker run --platform linux/amd64 --rm \
  -v "$(pwd)":/workspace \
  crplatnpdacreaus001.azurecr.io/chainguard/adoptium-jdk-fips:adoptium-openjdk-21.0 \
  sh -c "cd /workspace && \
         mkdir -p target/classes && \
         javac src/main/java/com/justincranford/tls/TlsConnect.java -d target/classes && \
         java --class-path \"target/classes:\$JAVA_FIPS_CLASSPATH\" \
              -Djava.security.properties=/usr/lib/jvm/jdk-fips-config/kernel-entropy.java.security \
              com.justincranford.tls.TlsConnect 2>&1 | grep -A 10 'MAC ALGORITHM'"
```

Look for output like:
```
INFO: === MAC ALGORITHM SPELLING TEST ===
INFO: ✅ Mac.getInstance("HMACSHA256") SUCCESS - Provider: BCFIPS
INFO: ✅ Mac.getInstance("HmacSHA256") SUCCESS - Provider: BCFIPS
```

If you see `❌ FAILED` for either spelling, that indicates the FIPS environment doesn't support that particular algorithm name variation.

### Test Coverage
The test suite includes:
- ✅ **Cipher Suite Metadata Validation**: Verifies all 37+ ranked cipher suites have complete metadata
- ✅ **FIPS Classification Tests**: Validates proper FIPS vs non-FIPS categorization  
- ✅ **Security Provider Tests**: Validates SSL context creation and provider fallbacks
- ✅ **Protocol Configuration Tests**: Ensures only secure TLS protocols are enabled
- ✅ **Cipher Suite Ranking Tests**: Validates uniqueness and proper security ordering
- ✅ **Constants Validation**: Verifies all cipher suite constants and configuration
- ✅ **Integration Tests**: Tests main application components and data structures

### Manual Testing
Test the application with different target servers:
```bash
# Test against different hosts (modify DEFAULT_HOST in Constants.java)
# Examples: badssl.com, github.com, google.com, cloudflare.com
```

## Future Enhancements

- [ ] Support for custom target hosts/ports
- [ ] OCSP certificate status checking  
- [ ] Additional cipher suite categories
- [ ] JSON/XML output formats
- [ ] Integration with security scanning tools
- [ ] Performance benchmarking modes

## Contributing

1. Ensure all changes maintain FIPS compliance
2. Test in both host and container environments  
3. Update documentation for any configuration changes
4. Verify cipher suite classifications are accurate
5. Run full test suite before submitting

## License

This project is provided as-is for educational and testing purposes. Ensure compliance with your organization's security policies when using in production environments.

## Container Shell Access

For advanced debugging, exploration, or manual execution, you can connect directly to the FIPS container with an interactive shell:

### Interactive Shell Session
```bash
docker run --platform linux/amd64 -it --rm \
  -v "$(pwd)":/workspace \
  crplatnpdacreaus001.azurecr.io/chainguard/adoptium-jdk-fips:adoptium-openjdk-21.0 \
  /bin/sh
```

### What You Can Do in the Container Shell

Once connected, you'll have access to the full FIPS-enabled environment:

**Navigate to your project:**
```bash
cd /workspace
```

**Explore the FIPS environment:**
```bash
# Check Java version and FIPS configuration
java --version

# List BouncyCastle FIPS JAR files
ls -la /usr/share/java/bouncycastle-fips/

# View FIPS security configuration
cat /usr/lib/jvm/java-21-adoptium/conf/security/java.security | grep security.provider

# Check available entropy configurations
ls -la /usr/lib/jvm/jdk-fips-config/
```

**Compile and run manually:**
```bash
# Create target directory
mkdir -p target/classes

# Compile the application
javac src/main/java/com/justincranford/tls/TlsConnect.java -d target/classes

# Run with kernel entropy (recommended)
java --class-path "target/classes:$JAVA_FIPS_CLASSPATH" \
  -Djava.security.properties=/usr/lib/jvm/jdk-fips-config/kernel-entropy.java.security \
  com.justincranford.tls.TlsConnect

# Or run with default FIPS configuration (may crash on ARM64 hosts)
java --class-path "target/classes:$JAVA_FIPS_CLASSPATH" \
  com.justincranford.tls.TlsConnect
```

**Debug environment variables:**
```bash
# Check FIPS-related environment variables
echo "JAVA_FIPS_CLASSPATH: $JAVA_FIPS_CLASSPATH"
echo "JDK_JAVA_OPTIONS: $JDK_JAVA_OPTIONS"
echo "JAVA_TOOL_OPTIONS: $JAVA_TOOL_OPTIONS"

# List all Java-related environment variables
env | grep -i java
```

**Explore BouncyCastle FIPS components:**
```bash
# Check BouncyCastle FIPS JAR contents
jar tf /usr/share/java/bouncycastle-fips/bc-fips.jar | head -20

# Check native library dependencies
ls -la /usr/lib/x86_64-linux-gnu/ | grep -i jent
ls -la /usr/lib/x86_64-linux-gnu/ | grep -i bouncy
```

### Exit the Container
When you're done exploring, simply type:
```bash
exit
```

This interactive approach is perfect for:
- 🔍 **Debugging**: Investigating FIPS configuration issues
- 📚 **Learning**: Understanding the FIPS container environment  
- 🧪 **Experimentation**: Testing different configurations manually
- 🛠️ **Development**: Iterative development and testing
