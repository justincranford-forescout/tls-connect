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
- ✅ **Cipher Suite Analysis**: Ranks 37+ cipher suites by security strength
- ✅ **Server Compatibility Testing**: Tests which cipher suites are supported by target servers
- ✅ **Detailed Tables**: Separate FIPS vs Non-FIPS analysis tables
- ✅ **Certificate Analysis**: Displays complete certificate chain information
- ✅ **Containerized Deployment**: Optimized for FIPS-enabled container environments
- ✅ **Standalone Application**: No external dependencies beyond JDK and BouncyCastle FIPS

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
INFO: Attempting to manually load BouncyCastle FIPS providers...
INFO: Successfully loaded BouncyCastleFipsProvider
INFO: Successfully loaded BouncyCastleJsseProvider
INFO: === SECURITY PROVIDERS ===
INFO: 1. BCFIPS v2.101: BouncyCastle Security Provider (FIPS edition) v2.1.1
INFO: 2. BCJSSE v2.012: Bouncy Castle JSSE Provider Version 2.1.20
```

### TLS Connection Information  
```
INFO: === TLS CONNECTION INFORMATION ===
INFO: Connected to: github.com
INFO: Protocol: TLSv1.3
INFO: Negotiated Cipher Suite: TLS_AES_128_GCM_SHA256
```

### FIPS Cipher Suite Analysis Table
```
CIPHER SUITE ANALYSIS TABLE (Ranked by Security Strength) - FIPS ONLY
==========================================================

| Rank     | Category     | Protocol   | FIPS   | Cipher Suite                               | Client Support  | Client Enabled  | Server Support  | Server Enabled  |
|----------+--------------+------------+--------+--------------------------------------------+-----------------+-----------------+-----------------+-----------------|
| 1        | Modern       | TLSv1.3    | YES    | TLS_AES_256_GCM_SHA384                     | YES             | YES             | YES             | YES             |
| 3        | Modern       | TLSv1.3    | YES    | TLS_AES_128_GCM_SHA256                     | YES             | YES             | YES             | YES             |
...

SUMMARY (FIPS CIPHER SUITES):
  Total Cipher Suites: 14
  Client Supported: 14
  Client Enabled: 14  
  Server Supported: 2
  Common (Both Enabled): 2
```

### Certificate Information
```
INFO: Server Certificates:
INFO:   Issuer Name: CN=Sectigo ECC Domain Validation Secure Server CA,O=Sectigo Limited...
INFO:   Subject Name: CN=github.com
INFO:   Serial Number: 227830333772454795620750445496253172213
INFO:   Not Before: Wed Feb 05 00:00:00 GMT 2025
INFO:   Not After: Thu Feb 05 23:59:59 GMT 2026
```

## Key Technical Details

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

**Technical Details**: 
- JENT uses hardware-specific entropy gathering instructions (e.g., RDTSC, RDRAND)
- These instructions may not be properly emulated in Rosetta/QEMU translation layers
- The SIGILL (Illegal Instruction) occurs when the native library tries to execute unsupported instructions

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
├── bc-rng-jent.jar       # Hardware entropy (problematic)
└── bcmail-fips.jar.      # S/MIME
└── bcpg-fips.jar         # OpenPGP
```

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
