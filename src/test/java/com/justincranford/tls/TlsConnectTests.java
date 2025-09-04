package com.justincranford.tls;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Assertions;

import javax.net.ssl.SSLContext;
import java.security.Security;
import java.security.Provider;

class TlsConnectTests {

    @Test
    @DisplayName("Test that TLS Connect main class exists and can be instantiated")
    void testTlsConnectClassExists() {
        Assertions.assertDoesNotThrow(() -> {
            TlsConnect tlsConnect = new TlsConnect();
            Assertions.assertNotNull(tlsConnect);
        });
    }

    @Test
    @DisplayName("Test that TLS context can be created")
    void testTlsContextCreation() {
        Assertions.assertDoesNotThrow(() -> {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            Assertions.assertNotNull(sslContext);
        });
    }

    @Test
    @DisplayName("Test that security providers are available")
    void testSecurityProvidersAvailable() {
        Provider[] providers = Security.getProviders();
        Assertions.assertTrue(providers.length > 0, "At least one security provider should be available");
        
        // Check for common providers
        boolean sunProviderFound = false;
        for (Provider provider : providers) {
            if ("SUN".equals(provider.getName())) {
                sunProviderFound = true;
                break;
            }
        }
        Assertions.assertTrue(sunProviderFound, "SUN security provider should be available");
    }

    @Test
    @DisplayName("Test that SSL algorithms are available")
    void testSslAlgorithmsAvailable() {
        java.util.Set<String> algorithms = Security.getAlgorithms("SSLContext");
        Assertions.assertTrue(algorithms.size() > 0, "SSL context algorithms should be available");
        Assertions.assertTrue(algorithms.contains("TLS"), "TLS algorithm should be available");
    }

    @Test
    @DisplayName("Test TLS Connect constants are properly defined")
    void testTlsConnectConstants() {
        Assertions.assertEquals("github.com", TlsConnect.Constants.DEFAULT_HOST);
        Assertions.assertEquals(443, TlsConnect.Constants.DEFAULT_PORT);
        Assertions.assertNotNull(TlsConnect.Constants.ALLOWED_PROTOCOLS);
        Assertions.assertTrue(TlsConnect.Constants.ALLOWED_PROTOCOLS.length > 0);
    }

    @Test
    @DisplayName("Test that main method exists and is accessible")
    void testMainMethodExists() {
        Assertions.assertDoesNotThrow(() -> {
            java.lang.reflect.Method mainMethod = TlsConnect.class.getMethod("main", String[].class);
            Assertions.assertNotNull(mainMethod);
            Assertions.assertTrue(java.lang.reflect.Modifier.isStatic(mainMethod.getModifiers()));
            Assertions.assertTrue(java.lang.reflect.Modifier.isPublic(mainMethod.getModifiers()));
        });
    }
}
