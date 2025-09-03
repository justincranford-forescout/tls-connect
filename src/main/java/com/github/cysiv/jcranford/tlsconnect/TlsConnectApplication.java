package com.github.cysiv.jcranford.tlsconnect;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Java 21 program that establishes a TLS connection to GitHub.com and prints
 * detailed information about the negotiated TLS parameters.
 */
public class TlsConnectApplication {
    private static final Logger logger = LoggerFactory.getLogger(TlsConnectApplication.class);
    private static final String HOST = "github.com";
    private static final int PORT = 443; // HTTPS port

    public static void main(String[] args) {
        try {
            // Create SSL context with default parameters
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);

            // Get SSL socket factory
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            logger.info("Establishing TLS connection to {}:{}...", HOST, PORT);

            // Create and configure SSL socket
            try (SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(HOST, PORT)) {
                // Enable only TLS 1.2 and 1.3 protocols for security
                sslSocket.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});

                // Start handshake explicitly
                sslSocket.startHandshake();

                // Get the SSL session
                SSLSession sslSession = sslSocket.getSession();

                // Print TLS connection information
                logger.info("=== TLS CONNECTION INFORMATION ===");
                logger.info("Connected to: {}", sslSession.getPeerHost());

                // Protocol version
                logger.info("Protocol: {}", sslSession.getProtocol());

                // Cipher suite
                logger.info("Cipher Suite: {}", sslSession.getCipherSuite());

                // Certificate information
                logger.info("Server Certificates:");
                for (var cert : sslSession.getPeerCertificates()) {
                    if (cert instanceof X509Certificate x509) {
                        logger.info("  Subject: {}", x509.getSubjectX500Principal().getName());
                        logger.info("  Issuer: {}", x509.getIssuerX500Principal().getName());
                        logger.info("  Valid from: {}", x509.getNotBefore());
                        logger.info("  Valid until: {}", x509.getNotAfter());
                        logger.info("  Serial number: {}", x509.getSerialNumber());
                    }
                }

                // Application Layer Protocol Negotiation (ALPN)
                // Note: For actual ALPN, we would need to check different methods
                logger.info("Application Protocol: Not negotiated (would require ALPN setup)");

                // List enabled protocols
                logger.info("Enabled Protocols:");
                Arrays.stream(sslSocket.getEnabledProtocols()).forEach(p -> logger.info("  {}", p));

                // List enabled cipher suites
                logger.info("Enabled Cipher Suites:");
                Arrays.stream(sslSocket.getEnabledCipherSuites()).forEach(cs -> logger.info("  {}", cs));

                // Session parameters using Java 21 features
                SSLParameters sslParameters = sslSocket.getSSLParameters();
                logger.info("Maximum TLS Fragment Length: {}", sslParameters.getMaximumPacketSize());
                logger.info("End Point Identification Algorithm: {}", sslParameters.getEndpointIdentificationAlgorithm());

                logger.info("Server Name Indication: {}",
                    (sslParameters.getServerNames() != null ? sslParameters.getServerNames() : "Not available"));
            }

        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            logger.error("SSL context initialization failed: {}", e.getMessage(), e);
        } catch (IOException e) {
            logger.error("Connection failed: {}", e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Error: {}", e.getMessage(), e);
        }
    }
}
