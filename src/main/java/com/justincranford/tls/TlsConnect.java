package com.justincranford.tls;

import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static com.justincranford.tls.TlsConnect.Constants.*;
import static com.justincranford.tls.TlsConnect.Constants.FipsStatus.*;

@SuppressWarnings({"unused"})
public class TlsConnect {
    private static final Logger logger = Logger.getLogger(TlsConnect.class.getName());

    // From https://wiki.mozilla.org/Security/Server_Side_TLS
    private static final List<CipherSuiteDetails> RANKED_CIPHER_SUITES = List.of(
        // Modern
        new CipherSuiteDetails(MODERN, RANK.getAndIncrement(), TLS_V1_3, FIPS, TLS_AES_256_GCM_SHA384, KxANY, AuANY, EncAESGCM256, MacAEAD),
        new CipherSuiteDetails(MODERN, RANK.getAndIncrement(), TLS_V1_3, NOPE, TLS_CHACHA20_POLY1305_SHA256, KxANY, AuANY, EncCHACHA20_POLY1305_256, MacAEAD),
        new CipherSuiteDetails(MODERN, RANK.getAndIncrement(), TLS_V1_3, FIPS, TLS_AES_128_GCM_SHA256, KxANY, AuANY, EncAESGCM128, MacAEAD),
        // Intermediate
        new CipherSuiteDetails(INTERM, RANK.getAndIncrement(), TLS_V1_2, FIPS, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, KxECDH, AuECDSA, EncAESGCM256, MacAEAD),
        new CipherSuiteDetails(INTERM, RANK.getAndIncrement(), TLS_V1_2, NOPE, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, KxECDH, AuECDSA, EncCHACHA20_POLY1305_256, MacAEAD),
        new CipherSuiteDetails(INTERM, RANK.getAndIncrement(), TLS_V1_2, FIPS, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, KxECDH, AuECDSA, EncAESGCM128, MacAEAD),
        new CipherSuiteDetails(INTERM, RANK.getAndIncrement(), TLS_V1_2, FIPS, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, KxECDH, AuRSA, EncAESGCM256, MacAEAD),
        new CipherSuiteDetails(INTERM, RANK.getAndIncrement(), TLS_V1_2, NOPE, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, KxECDH, AuRSA, EncCHACHA20_POLY1305_256, MacAEAD),
        new CipherSuiteDetails(INTERM, RANK.getAndIncrement(), TLS_V1_2, FIPS, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, KxECDH, AuRSA, EncAESGCM128, MacAEAD),
        new CipherSuiteDetails(INTERM, RANK.getAndIncrement(), TLS_V1_2, FIPS, TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, KxDH, AuRSA, EncAESGCM256, MacAEAD),
        new CipherSuiteDetails(INTERM, RANK.getAndIncrement(), TLS_V1_2, NOPE, TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, KxDH, AuRSA, EncCHACHA20_POLY1305_256, MacAEAD),
        new CipherSuiteDetails(INTERM, RANK.getAndIncrement(), TLS_V1_2, FIPS, TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, KxDH, AuRSA, EncAESGCM128, MacAEAD),
        new CipherSuiteDetails(INTERM, RANK.getAndIncrement(), TLS_V1_2, FIPS, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, KxECDH, AuECDSA, EncAES256, MacSHA384),
        new CipherSuiteDetails(INTERM, RANK.getAndIncrement(), TLS_V1_2, FIPS, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, KxECDH, AuECDSA, EncAES128, MacSHA256),
        new CipherSuiteDetails(INTERM, RANK.getAndIncrement(), TLS_V1_2, FIPS, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, KxECDH, AuRSA, EncAES256, MacSHA384),
        new CipherSuiteDetails(INTERM, RANK.getAndIncrement(), TLS_V1_2, FIPS, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, KxECDH, AuRSA, EncAES128, MacSHA256),
        // Old
        new CipherSuiteDetails(OLD, RANK.getAndIncrement(), TLS_V1, NOPE, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, KxECDH, AuECDSA, EncAES256, MacSHA1),
        new CipherSuiteDetails(OLD, RANK.getAndIncrement(), TLS_V1, NOPE, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, KxECDH, AuECDSA, EncAES128, MacSHA1),
        new CipherSuiteDetails(OLD, RANK.getAndIncrement(), TLS_V1, NOPE, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, KxECDH, AuRSA, EncAES256, MacSHA1),
        new CipherSuiteDetails(OLD, RANK.getAndIncrement(), TLS_V1, NOPE, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, KxECDH, AuRSA, EncAES128, MacSHA1),
        new CipherSuiteDetails(OLD, RANK.getAndIncrement(), TLS_V1_2, FIPS, TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, KxDH, AuRSA, EncAES256, MacSHA256),
        new CipherSuiteDetails(OLD, RANK.getAndIncrement(), TLS_V1_2, FIPS, TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, KxDH, AuRSA, EncAES128, MacSHA256),
        new CipherSuiteDetails(OLD, RANK.getAndIncrement(), SSL_v3, NOPE, TLS_DHE_RSA_WITH_AES_256_CBC_SHA, KxDH, AuRSA, EncAES256, MacSHA1),
        new CipherSuiteDetails(OLD, RANK.getAndIncrement(), SSL_v3, NOPE, TLS_DHE_RSA_WITH_AES_128_CBC_SHA, KxDH, AuRSA, EncAES128, MacSHA1),
        new CipherSuiteDetails(OLD, RANK.getAndIncrement(), TLS_V1_2, FIPS, TLS_RSA_WITH_AES_256_GCM_SHA384, KxRSA, AuRSA, EncAESGCM256, MacAEAD),
        new CipherSuiteDetails(OLD, RANK.getAndIncrement(), TLS_V1_2, FIPS, TLS_RSA_WITH_AES_128_GCM_SHA256, KxRSA, AuRSA, EncAESGCM128, MacAEAD),
        new CipherSuiteDetails(OLD, RANK.getAndIncrement(), TLS_V1_2, FIPS, TLS_RSA_WITH_AES_256_CBC_SHA256, KxRSA, AuRSA, EncAES256, MacSHA256),
        new CipherSuiteDetails(OLD, RANK.getAndIncrement(), TLS_V1_2, FIPS, TLS_RSA_WITH_AES_128_CBC_SHA256, KxRSA, AuRSA, EncAES128, MacSHA256),
        new CipherSuiteDetails(OLD, RANK.getAndIncrement(), SSL_v3, NOPE, TLS_RSA_WITH_AES_256_CBC_SHA, KxRSA, AuRSA, EncAES256, MacSHA1),
        new CipherSuiteDetails(OLD, RANK.getAndIncrement(), SSL_v3, NOPE, TLS_RSA_WITH_AES_128_CBC_SHA, KxRSA, AuRSA, EncAES128, MacSHA1),
        // Weak
        new CipherSuiteDetails(WEAK, RANK.getAndIncrement(), TLS_V1_2, NOPE, TLS_DHE_DSS_WITH_AES_256_GCM_SHA384, KxDH, AuDSS, EncAESGCM256, MacAEAD),
        new CipherSuiteDetails(WEAK, RANK.getAndIncrement(), TLS_V1_2, NOPE, TLS_DHE_DSS_WITH_AES_128_GCM_SHA256, KxDH, AuDSS, EncAESGCM128, MacAEAD),
        new CipherSuiteDetails(WEAK, RANK.getAndIncrement(), TLS_V1_2, NOPE, TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, KxDH, AuDSS, EncAES256, MacSHA256),
        new CipherSuiteDetails(WEAK, RANK.getAndIncrement(), TLS_V1_2, NOPE, TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, KxDH, AuDSS, EncAES128, MacSHA256),
        new CipherSuiteDetails(WEAK, RANK.getAndIncrement(), SSL_v3, NOPE, TLS_DHE_DSS_WITH_AES_256_CBC_SHA, KxDH, AuDSS, EncAES256, MacSHA1),
        new CipherSuiteDetails(WEAK, RANK.getAndIncrement(), SSL_v3, NOPE, TLS_DHE_DSS_WITH_AES_128_CBC_SHA, KxDH, AuDSS, EncAES128, MacSHA1),
        // Special
        new CipherSuiteDetails(SPECIAL, RANK.getAndIncrement(), NA, NOPE, TLS_EMPTY_RENEGOTIATION_INFO_SCSV, KxNA, AuNA, EncNA, MacNA)
    );

    public static void main(String[] args) {
        try {
            // Try to manually load BouncyCastle FIPS providers
            try {
                logger.info("Attempting to manually load BouncyCastle FIPS providers...");
                Class<?> bcFipsProvider = Class.forName("org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider");
                java.security.Security.addProvider((java.security.Provider) bcFipsProvider.getDeclaredConstructor().newInstance());
                logger.info("Successfully loaded BouncyCastleFipsProvider");
                
                Class<?> bcJsseProvider = Class.forName("org.bouncycastle.jsse.provider.BouncyCastleJsseProvider");
                java.security.Security.addProvider((java.security.Provider) bcJsseProvider.getDeclaredConstructor().newInstance());
                logger.info("Successfully loaded BouncyCastleJsseProvider");
            } catch (Exception e) {
                logger.warning("Could not manually load BouncyCastle providers: " + e.getMessage());
            }
            
            // Print security providers for debugging
            logger.info("=== SECURITY PROVIDERS ===");
            java.security.Provider[] providers = java.security.Security.getProviders();
            for (int i = 0; i < providers.length; i++) {
                logger.info((i+1) + ". " + providers[i].getName() + " v" + providers[i].getVersionStr() + ": " + providers[i].getInfo());
            }
            
            // Print available SSL context algorithms
            logger.info("=== AVAILABLE SSL CONTEXT ALGORITHMS ===");
            java.util.Set<String> algorithms = java.security.Security.getAlgorithms("SSLContext");
            for (String alg : algorithms) {
                logger.info("  " + alg);
            }
            
            // Test Mac algorithm spellings for FIPS compatibility
            logger.info("=== MAC ALGORITHM SPELLING TEST ===");
            String[] macSpellings = {"HMACSHA256", "HmacSHA256"};
            for (String macAlgorithm : macSpellings) {
                try {
                    javax.crypto.Mac mac = javax.crypto.Mac.getInstance(macAlgorithm);
                    logger.info("✅ Mac.getInstance(\"" + macAlgorithm + "\") SUCCESS - Provider: " + mac.getProvider().getName());
                } catch (java.security.NoSuchAlgorithmException e) {
                    logger.warning("❌ Mac.getInstance(\"" + macAlgorithm + "\") FAILED: " + e.getMessage());
                }
            }
            
            // Try different SSL context algorithms that work with FIPS
            SSLContext sslContext = null;
            String[] algorithmsToTry = {TLS_V1_3, TLS_V1_2, "TLS", "Default"};
            
            for (String algorithm : algorithmsToTry) {
                try {
                    logger.info("Trying SSLContext algorithm: " + algorithm);
                    sslContext = SSLContext.getInstance(algorithm);
                    sslContext.init(null, null, null);
                    logger.info("Successfully initialized SSLContext with algorithm: " + algorithm);
                    break;
                } catch (Exception e) {
                    logger.warning("Failed to initialize SSLContext with " + algorithm + ": " + e.getMessage());
                }
            }
            
            if (sslContext == null) {
                // Try with BouncyCastle provider explicitly using different provider names
                String[] bcProviders = {"BouncyCastleJsseProvider", "BCJSSE", "org.bouncycastle.jsse.provider.BouncyCastleJsseProvider"};
                for (String providerName : bcProviders) {
                    try {
                        logger.info("Trying with provider: " + providerName);
                        sslContext = SSLContext.getInstance("TLS", providerName);
                        sslContext.init(null, null, null);
                        logger.info("Successfully initialized SSLContext with provider: " + providerName);
                        break;
                    } catch (Exception e) {
                        logger.warning("Failed to initialize SSLContext with provider " + providerName + ": " + e.getMessage());
                    }
                }
            }
            
            // Final fallback - try with standard Java providers using different approaches
            if (sslContext == null) {
                logger.info("Attempting fallback to standard Java SSL providers...");
                try {
                    // Try creating SSLContext with default provider but using SunJSSE explicitly
                    sslContext = SSLContext.getInstance("TLS", "SunJSSE");
                    sslContext.init(null, null, null);
                    logger.info("Successfully initialized SSLContext with SunJSSE provider");
                } catch (Exception e) {
                    logger.warning("Failed with SunJSSE: " + e.getMessage());
                    
                    // Last resort - try getting the default SSL context
                    try {
                        sslContext = SSLContext.getDefault();
                        logger.info("Successfully got default SSLContext");
                    } catch (Exception e2) {
                        logger.severe("Failed to get default SSLContext: " + e2.getMessage());
                    }
                }
            }
            
            if (sslContext == null) {
                logger.severe("Could not initialize any SSLContext. Available providers:");
                for (java.security.Provider provider : java.security.Security.getProviders()) {
                    logger.severe("  Provider: " + provider.getName() + " - " + provider.getClass().getName());
                }
                throw new RuntimeException("Could not initialize any SSLContext");
            }

            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            logger.info("Establishing TLS connection to " + DEFAULT_HOST + ":" + DEFAULT_PORT + "...");

            try (SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(DEFAULT_HOST, DEFAULT_PORT)) {
                sslSocket.setEnabledProtocols(ALLOWED_PROTOCOLS);

                sslSocket.startHandshake();
                final SSLSession sslSession = sslSocket.getSession();

                // Print TLS connection information
                logger.info("=== TLS CONNECTION INFORMATION ===");
                logger.info("Connected to: " + sslSession.getPeerHost());

                logger.info("Protocol: " + sslSession.getProtocol());
                logger.info("Negotiated Cipher Suite: " + sslSession.getCipherSuite());

                final String[] clientSupportedCipherSuites = sslSocket.getSupportedCipherSuites();
                final String[] clientEnabledCipherSuites = sslSocket.getEnabledCipherSuites();

                logger.info("=== CIPHER SUITE ANALYSIS ===");
                final CipherSuiteAnalysis analysis = analyzeCipherSuites(sslSocketFactory, clientSupportedCipherSuites, clientEnabledCipherSuites);
                displayCipherSuiteTable(analysis, true);
                displayCipherSuiteTable(analysis, false);

                logger.info("Server Certificates:");
                for (var cert : sslSession.getPeerCertificates()) {
                    if (cert instanceof X509Certificate x509) {
                        logger.info("  Issuer Name: " + x509.getIssuerX500Principal().getName());
                        logger.info("  Subject Name: " + x509.getSubjectX500Principal().getName());
                        logger.info("  Serial Number: " + x509.getSerialNumber());
                        logger.info("  Not Before: " + x509.getNotBefore());
                        logger.info("  Not After: " + x509.getNotAfter());
                    }
                }

                logger.info("Enabled Protocols:");
                Arrays.stream(sslSocket.getEnabledProtocols()).forEach(p -> logger.info("  " + p));

                logger.info("Enabled Cipher Suites:");
                Arrays.stream(sslSocket.getEnabledCipherSuites()).forEach(cs -> logger.info("  " + cs));

                SSLParameters sslParameters = sslSocket.getSSLParameters();
                logger.info("Maximum TLS Fragment Length: " + sslParameters.getMaximumPacketSize());
                logger.info("End Point Identification Algorithm: " + sslParameters.getEndpointIdentificationAlgorithm());

                logger.info("Server Name Indication: " + (sslParameters.getServerNames() != null ? sslParameters.getServerNames() : "Not available"));
            }
        } catch (IOException e) {
            logger.severe("Connection failed: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static CipherSuiteAnalysis analyzeCipherSuites(SSLSocketFactory sslSocketFactory, String[] clientSupportedCipherSuites, String[] clientEnabledCipherSuites) {
        CipherSuiteAnalysis analysis = new CipherSuiteAnalysis();

        // Add all client supported cipher suites to the analysis
        List<String> clientSupported = List.of(clientSupportedCipherSuites);
        List<String> clientEnabled = List.of(clientEnabledCipherSuites);

        // Get all unique cipher suites from both supported and enabled
        Set<String> allCipherSuites = new HashSet<>();
        allCipherSuites.addAll(clientSupported);
        allCipherSuites.addAll(clientEnabled);

        logger.info("Testing " + allCipherSuites.size() + " unique cipher suites for server compatibility...");
        for (String cipherSuite : allCipherSuites) {
            boolean isClientSupported = clientSupported.contains(cipherSuite);
            boolean isClientEnabled = clientEnabled.contains(cipherSuite);
            boolean isServerSupported = false;
            boolean isServerEnabled = false;
            if (isClientEnabled) {
                try (SSLSocket testSocket = (SSLSocket) sslSocketFactory.createSocket(DEFAULT_HOST, DEFAULT_PORT)) {
                    testSocket.setEnabledProtocols(new String[]{TLS_V1_3, TLS_V1_2});
                    testSocket.setEnabledCipherSuites(new String[]{cipherSuite});
                    testSocket.startHandshake();
                    isServerSupported = true;
                    isServerEnabled = true;
                } catch (IOException e) {
                    isServerSupported = false;
                    isServerEnabled = false;
                }
            }
            analysis.addCipherSuite(cipherSuite, isClientSupported, isClientEnabled, isServerSupported, isServerEnabled);
        }
        return analysis;
    }

    private static void displayCipherSuiteTable(CipherSuiteAnalysis analysis, boolean onlyFips) {
        logger.info("");
        logger.info("CIPHER SUITE ANALYSIS TABLE (Ranked by Security Strength) - " + (onlyFips ? "FIPS" : "NON-FIPS") + " ONLY");
        logger.info("==========================================================");
        logger.info("");

        displayTableHeader();
        displayKnownCipherSuites(analysis, onlyFips);
        displayUnknownCipherSuites(analysis, onlyFips);
        displayTableFooter();
        displaySummaryStatistics(analysis, onlyFips);
    }

    private static void displayTableHeader() {
        final String headerFormat = "| %-8s | %-12s | %-10s | %-6s | %-50s | %-15s | %-15s | %-15s | %-15s |";
        logger.info(String.format(headerFormat, "Rank", "Category", "Protocol", "FIPS", "Cipher Suite", "Client Support", "Client Enabled", "Server Support", "Server Enabled"));
        logger.info(getTableSeparator());
    }

    private static void displayKnownCipherSuites(CipherSuiteAnalysis analysis, boolean onlyFips) {
        final String rowFormat = "| %-8d | %-12s | %-10s | %-6s | %-50s | %-15s | %-15s | %-15s | %-15s |";
        RANKED_CIPHER_SUITES.stream()
            .filter(details -> analysis.getAllCipherSuites().contains(details.name()))
            .filter(details -> onlyFips ? details.fips().equals(FIPS) : details.fips().equals(NOPE))
            .forEach(details -> {
                CipherSuiteAnalysis.CipherSuiteInfo info = analysis.getCipherSuiteInfo(details.name());
                logger.info(String.format(rowFormat,
                    details.securityRank(),
                    details.category(),
                    details.tlsVersion(),
                    details.fips().equals(FIPS) ? "YES" : "NO",
                    details.name(),
                    info.isClientSupported() ? "YES" : "NO",
                    info.isClientEnabled() ? "YES" : "NO",
                    info.isServerSupported() ? "YES" : "NO",
                    info.isServerEnabled() ? "YES" : "NO"
                ));
            });
    }

    private static void displayUnknownCipherSuites(CipherSuiteAnalysis analysis, boolean onlyFips) {
        if (onlyFips) {
            return;
        }
        final String unknownRowFormat = "| %-8s | %-12s | %-10s | %-6s | %-50s | %-15s | %-15s | %-15s | %-15s |";
        analysis.getAllCipherSuites().stream()
            .filter(cs -> RANKED_CIPHER_SUITES.stream().noneMatch(details -> details.name().equals(cs)))
            .sorted()
            .forEach(cs -> {
                CipherSuiteAnalysis.CipherSuiteInfo info = analysis.getCipherSuiteInfo(cs);
                logger.info(String.format(unknownRowFormat,
                    "UNKNOWN",
                    "Unknown",
                    "Unknown",
                    "UNKNOWN",
                    cs,
                    info.isClientSupported() ? "YES" : "NO",
                    info.isClientEnabled() ? "YES" : "NO",
                    info.isServerSupported() ? "YES" : "NO",
                    info.isServerEnabled() ? "YES" : "NO"
                ));
            });
    }

    private static void displayTableFooter() {
        logger.info(getTableSeparator());
        logger.info("");
    }

    private static String getTableSeparator() {
        return java.lang.String.format("|%s+%s+%s+%s+%s+%s+%s+%s+%s|",
            "-".repeat(10),
            "-".repeat(14),
            "-".repeat(12),
            "-".repeat(8),
            "-".repeat(52),
            "-".repeat(17),
            "-".repeat(17),
            "-".repeat(17),
            "-".repeat(17)
        );
    }

    private static void displaySummaryStatistics(CipherSuiteAnalysis analysis, boolean onlyFips) {
        // Filter cipher suites based on FIPS requirement
        Set<String> filteredCipherSuites = analysis.getAllCipherSuites().stream()
            .filter(cs -> 
                // For known cipher suites, filter by FIPS status
                RANKED_CIPHER_SUITES.stream()
                    .filter(details -> details.name().equals(cs))
                    .findFirst()
                    .map(details -> onlyFips ? details.fips().equals(FIPS) : details.fips().equals(NOPE))
                    .orElse(!onlyFips) // Unknown cipher suites only appear in non-FIPS table
            )
            .collect(java.util.stream.Collectors.toSet());

        long clientSupportedCount = countFilteredCipherSuites(analysis, filteredCipherSuites, CipherSuiteAnalysis.CipherSuiteInfo::isClientSupported);
        long clientEnabledCount = countFilteredCipherSuites(analysis, filteredCipherSuites, CipherSuiteAnalysis.CipherSuiteInfo::isClientEnabled);
        long serverSupportedCount = countFilteredCipherSuites(analysis, filteredCipherSuites, CipherSuiteAnalysis.CipherSuiteInfo::isServerSupported);
        long commonCount = countFilteredCipherSuites(analysis, filteredCipherSuites, info -> info.isClientEnabled() && info.isServerEnabled());

        logger.info("SUMMARY (" + (onlyFips ? "FIPS" : "NON-FIPS") + " CIPHER SUITES):");
        logger.info("  Total Cipher Suites: " + filteredCipherSuites.size());
        logger.info("  Client Supported: " + clientSupportedCount);
        logger.info("  Client Enabled: " + clientEnabledCount);
        logger.info("  Server Supported: " + serverSupportedCount);
        logger.info("  Common (Both Enabled): " + commonCount);
        logger.info("");
    }

    private static long countCipherSuites(CipherSuiteAnalysis analysis, java.util.function.Predicate<CipherSuiteAnalysis.CipherSuiteInfo> predicate) {
        return analysis.getAllCipherSuites().stream()
            .mapToLong(cs -> predicate.test(analysis.getCipherSuiteInfo(cs)) ? 1 : 0)
            .sum();
    }

    private static long countFilteredCipherSuites(CipherSuiteAnalysis analysis, Set<String> filteredCipherSuites, java.util.function.Predicate<CipherSuiteAnalysis.CipherSuiteInfo> predicate) {
        return filteredCipherSuites.stream()
            .mapToLong(cs -> predicate.test(analysis.getCipherSuiteInfo(cs)) ? 1 : 0)
            .sum();
    }

    private static class CipherSuiteAnalysis {
        private final java.util.Map<String, CipherSuiteInfo> allCipherSuites = new java.util.HashMap<>();

        public void addCipherSuite(String cipherSuite, boolean isClientSupported, boolean isClientEnabled, boolean isServerSupported, boolean isServerEnabled) {
            CipherSuiteInfo info = new CipherSuiteInfo(isClientSupported, isClientEnabled, isServerSupported, isServerEnabled);
            allCipherSuites.put(cipherSuite, info);
        }

        public java.util.Set<String> getAllCipherSuites() {
            return allCipherSuites.keySet();
        }

        public CipherSuiteInfo getCipherSuiteInfo(String cipherSuite) {
            return allCipherSuites.get(cipherSuite);
        }

        public record CipherSuiteInfo(
            boolean isClientSupported,
            boolean isClientEnabled,
            boolean isServerSupported,
            boolean isServerEnabled
        ) {}
    }

    record CipherSuiteDetails(
        String category,
        int securityRank,
        String tlsVersion,
        Constants.FipsStatus fips,
        String name,
        String keyExchange,
        String authentication,
        String encryption,
        String mac
    ) {}

    static class Constants {
        // All cipher suites ranked by security strength (highest to lowest) based on Mozilla guidelines (https://wiki.mozilla.org/Security/Server_Side_TLS)
        public static final AtomicInteger RANK = new AtomicInteger(1);

        public static final String DEFAULT_HOST = "github.com";
        public static final int DEFAULT_PORT = 443; // HTTPS port

        public static final String MODERN = "Modern";
        public static final String INTERM = "Intermediate";
        public static final String OLD = "Old";
        public static final String WEAK = "Weak";
        public static final String SPECIAL = "Special";

        public static final String TLS_V1_3 = "TLSv1.3";
        public static final String TLS_V1_2 = "TLSv1.2";
        public static final String TLS_V1_1 = "TLSv1.1";
        public static final String TLS_V1 = "TLSv1";
        public static final String SSL_v3 = "SSL_v3";
        public static final String NA = "N/A";
        public static final String[] ALLOWED_PROTOCOLS = {TLS_V1_3, TLS_V1_2};

        public static final String KxANY = "any";
        public static final String KxRSA = "RSA";
        public static final String KxECDH = "ECDH";
        public static final String KxDH = "DH";
        public static final String KxNA = "N/A";

        public static final String AuANY = "any";
        public static final String AuECDSA = "ECDSA";
        public static final String AuRSA = "RSA";
        public static final String AuDSS = "DSS";
        public static final String AuNA = "N/A";

        public static final String EncAESGCM256 = "AESGCM(256)";
        public static final String EncAESGCM192 = "AESGCM(192)";
        public static final String EncAESGCM128 = "AESGCM(128)";
        public static final String EncAES256 = "AES(256)";
        public static final String EncAES192 = "AES(192)";
        public static final String EncAES128 = "AES(128)";
        public static final String EncCHACHA20_POLY1305_256 = "CHACHA20/POLY1305(256)";
        public static final String EncNA = "N/A";

        public static final String MacAEAD = "AEAD";
        public static final String MacSHA512 = "SHA512";
        public static final String MacSHA384 = "SHA384";
        public static final String MacSHA256 = "SHA256";
        public static final String MacSHA1 = "SHA1";
        public static final String MacNA = "N/A";

        // Cipher Suite Names
        public static final String TLS_AES_256_GCM_SHA384 = "TLS_AES_256_GCM_SHA384";
        public static final String TLS_CHACHA20_POLY1305_SHA256 = "TLS_CHACHA20_POLY1305_SHA256";
        public static final String TLS_AES_128_GCM_SHA256 = "TLS_AES_128_GCM_SHA256";
        public static final String TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
        public static final String TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
        public static final String TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        public static final String TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        public static final String TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
        public static final String TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        public static final String TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
        public static final String TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
        public static final String TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
        public static final String TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
        public static final String TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
        public static final String TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
        public static final String TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
        public static final String TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
        public static final String TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
        public static final String TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
        public static final String TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
        public static final String TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
        public static final String TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
        public static final String TLS_DHE_RSA_WITH_AES_256_CBC_SHA = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
        public static final String TLS_DHE_RSA_WITH_AES_128_CBC_SHA = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
        public static final String TLS_RSA_WITH_AES_256_GCM_SHA384 = "TLS_RSA_WITH_AES_256_GCM_SHA384";
        public static final String TLS_RSA_WITH_AES_128_GCM_SHA256 = "TLS_RSA_WITH_AES_128_GCM_SHA256";
        public static final String TLS_RSA_WITH_AES_256_CBC_SHA256 = "TLS_RSA_WITH_AES_256_CBC_SHA256";
        public static final String TLS_RSA_WITH_AES_128_CBC_SHA256 = "TLS_RSA_WITH_AES_128_CBC_SHA256";
        public static final String TLS_RSA_WITH_AES_256_CBC_SHA = "TLS_RSA_WITH_AES_256_CBC_SHA";
        public static final String TLS_RSA_WITH_AES_128_CBC_SHA = "TLS_RSA_WITH_AES_128_CBC_SHA";
        public static final String TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384";
        public static final String TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256";
        public static final String TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256";
        public static final String TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256";
        public static final String TLS_DHE_DSS_WITH_AES_256_CBC_SHA = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA";
        public static final String TLS_DHE_DSS_WITH_AES_128_CBC_SHA = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA";
        public static final String TLS_EMPTY_RENEGOTIATION_INFO_SCSV = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";

        public enum FipsStatus { FIPS, NOPE}
    }
}
