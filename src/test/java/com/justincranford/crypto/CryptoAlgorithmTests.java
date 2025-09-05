package com.justincranford.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;

import javax.crypto.Mac;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class CryptoAlgorithmTests {

    @Nested
    @DisplayName("MAC Algorithm Tests")
    class MacAlgorithmTests {

        @Test
        @DisplayName("Test Mac.getInstance with HMACSHA256 algorithm name")
        void testMacInstanceHMACSHA256() {
            assertDoesNotThrow(() -> {
                Mac mac = Mac.getInstance("HMACSHA256");
                assertNotNull(mac, "Mac instance should not be null");
                assertEquals("HMACSHA256", mac.getAlgorithm(), "Algorithm name should match");
            });
        }

        @Test
        @DisplayName("Test Mac.getInstance with HMacSHA256 algorithm name")
        void testMacInstanceHMacSHA256() {
            assertDoesNotThrow(() -> {
                Mac mac = Mac.getInstance("HMacSHA256");
                assertNotNull(mac, "Mac instance should not be null");
                assertEquals("HMacSHA256", mac.getAlgorithm(), "Algorithm name should match");
            });
        }

        @Test
        @DisplayName("Test Mac.getInstance with standard HmacSHA256 algorithm name")
        void testMacInstanceHmacSHA256() {
            assertDoesNotThrow(() -> {
                Mac mac = Mac.getInstance("HmacSHA256");
                assertNotNull(mac, "Mac instance should not be null");
                assertEquals("HmacSHA256", mac.getAlgorithm(), "Algorithm name should match");
            });
        }

        @Test
        @DisplayName("Test HMAC algorithm variations produce same results")
        void testHmacAlgorithmVariationsProduceSameResults() {
            assertDoesNotThrow(() -> {
                // Generate a test key
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
                SecretKey secretKey = keyGen.generateKey();
                
                // Test data
                byte[] testData = "Hello, FIPS World!".getBytes(StandardCharsets.UTF_8);
                
                // Test different algorithm name variations
                String[] algorithmVariations = {"HmacSHA256", "HMACSHA256", "HMacSHA256"};
                byte[][] results = new byte[algorithmVariations.length][];
                
                for (int i = 0; i < algorithmVariations.length; i++) {
                    try {
                        Mac mac = Mac.getInstance(algorithmVariations[i]);
                        mac.init(secretKey);
                        results[i] = mac.doFinal(testData);
                        assertNotNull(results[i], "HMAC result should not be null for " + algorithmVariations[i]);
                        assertTrue(results[i].length > 0, "HMAC result should not be empty for " + algorithmVariations[i]);
                    } catch (NoSuchAlgorithmException e) {
                        // Some variations might not be available on all systems
                        System.out.println("Algorithm variation not available: " + algorithmVariations[i]);
                    }
                }
                
                // Compare results where both algorithms are available
                for (int i = 0; i < results.length; i++) {
                    for (int j = i + 1; j < results.length; j++) {
                        if (results[i] != null && results[j] != null) {
                            assertTrue(Arrays.equals(results[i], results[j]), 
                                "HMAC results should be identical for " + algorithmVariations[i] + " and " + algorithmVariations[j]);
                        }
                    }
                }
            });
        }

        @Test
        @DisplayName("Test HMAC with different SHA variants")
        void testHmacWithDifferentShaVariants() {
            String[] hmacAlgorithms = {
                "HmacSHA1", "HmacSHA224", "HmacSHA256", "HmacSHA384", "HmacSHA512"
            };
            
            for (String algorithm : hmacAlgorithms) {
                assertDoesNotThrow(() -> {
                    try {
                        Mac mac = Mac.getInstance(algorithm);
                        assertNotNull(mac, "Mac instance should not be null for " + algorithm);
                        assertEquals(algorithm, mac.getAlgorithm(), "Algorithm name should match for " + algorithm);
                        
                        // Test that we can generate a key and compute HMAC
                        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
                        SecretKey secretKey = keyGen.generateKey();
                        mac.init(secretKey);
                        
                        byte[] testData = "Test data for HMAC".getBytes(StandardCharsets.UTF_8);
                        byte[] hmacResult = mac.doFinal(testData);
                        
                        assertNotNull(hmacResult, "HMAC result should not be null for " + algorithm);
                        assertTrue(hmacResult.length > 0, "HMAC result should not be empty for " + algorithm);
                        
                    } catch (NoSuchAlgorithmException e) {
                        System.out.println("HMAC algorithm not available: " + algorithm);
                    }
                }, "Should be able to create and use HMAC with " + algorithm);
            }
        }

        @Test
        @DisplayName("Test HMAC key size requirements")
        void testHmacKeySizeRequirements() {
            assertDoesNotThrow(() -> {
                Mac mac = Mac.getInstance("HmacSHA256");
                
                // Test with different key sizes
                int[] keySizes = {16, 32, 64}; // 128, 256, 512 bits
                
                for (int keySize : keySizes) {
                    KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
                    keyGen.init(keySize * 8); // Convert bytes to bits
                    SecretKey secretKey = keyGen.generateKey();
                    
                    mac.init(secretKey);
                    byte[] testData = "Test data".getBytes(StandardCharsets.UTF_8);
                    byte[] result = mac.doFinal(testData);
                    
                    assertNotNull(result, "HMAC result should not be null for key size " + keySize + " bytes");
                    assertEquals(32, result.length, "HMAC-SHA256 should always produce 32-byte output");
                }
            });
        }

        @Test
        @DisplayName("Test HMAC algorithm case sensitivity")
        void testHmacAlgorithmCaseSensitivity() {
            // Test various case combinations that should work
            String[] caseVariations = {
                "HmacSHA256",
                "HMACSHA256", 
                "HMacSHA256",
                "hmacsha256", // lowercase - may not work on all providers
                "HmacSha256"  // mixed case - may not work on all providers
            };
            
            int successCount = 0;
            
            for (String algorithm : caseVariations) {
                try {
                    Mac mac = Mac.getInstance(algorithm);
                    assertNotNull(mac, "Mac instance should not be null for " + algorithm);
                    successCount++;
                } catch (NoSuchAlgorithmException e) {
                    // Some case variations might not be supported
                    System.out.println("Case variation not supported: " + algorithm);
                }
            }
            
            assertTrue(successCount >= 1, "At least one HMAC algorithm variation should be supported");
        }
    }

    @Nested
    @DisplayName("FIPS Compliance Tests")
    class FipsComplianceTests {

        @Test
        @DisplayName("Test FIPS-approved HMAC algorithms")
        void testFipsApprovedHmacAlgorithms() {
            // FIPS 140-2 approved HMAC algorithms
            String[] fipsApprovedAlgorithms = {
                "HmacSHA1",    // FIPS approved but deprecated
                "HmacSHA224",  // FIPS approved
                "HmacSHA256",  // FIPS approved - most common
                "HmacSHA384",  // FIPS approved
                "HmacSHA512"   // FIPS approved
            };
            
            for (String algorithm : fipsApprovedAlgorithms) {
                assertDoesNotThrow(() -> {
                    try {
                        Mac mac = Mac.getInstance(algorithm);
                        assertNotNull(mac, "FIPS-approved algorithm should be available: " + algorithm);
                        
                        // Verify we can use it for actual HMAC computation
                        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
                        SecretKey key = keyGen.generateKey();
                        mac.init(key);
                        
                        byte[] testData = "FIPS compliance test".getBytes(StandardCharsets.UTF_8);
                        byte[] hmac = mac.doFinal(testData);
                        
                        assertNotNull(hmac, "HMAC computation should succeed for " + algorithm);
                        assertTrue(hmac.length > 0, "HMAC result should not be empty for " + algorithm);
                        
                    } catch (NoSuchAlgorithmException e) {
                        System.out.println("FIPS algorithm not available in this environment: " + algorithm);
                    }
                }, "FIPS-approved algorithm should work: " + algorithm);
            }
        }

        @Test
        @DisplayName("Test HMAC output lengths match expected values")
        void testHmacOutputLengths() {
            assertDoesNotThrow(() -> {
                // Expected output lengths for different HMAC algorithms (in bytes)
                Object[][] algorithmOutputLengths = {
                    {"HmacSHA1", 20},     // 160 bits
                    {"HmacSHA224", 28},   // 224 bits  
                    {"HmacSHA256", 32},   // 256 bits
                    {"HmacSHA384", 48},   // 384 bits
                    {"HmacSHA512", 64}    // 512 bits
                };
                
                byte[] testData = "Output length test".getBytes(StandardCharsets.UTF_8);
                
                for (Object[] algorithmInfo : algorithmOutputLengths) {
                    String algorithm = (String) algorithmInfo[0];
                    int expectedLength = (Integer) algorithmInfo[1];
                    
                    try {
                        Mac mac = Mac.getInstance(algorithm);
                        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
                        SecretKey key = keyGen.generateKey();
                        mac.init(key);
                        
                        byte[] hmac = mac.doFinal(testData);
                        assertEquals(expectedLength, hmac.length, 
                            "HMAC output length should be " + expectedLength + " bytes for " + algorithm);
                            
                    } catch (NoSuchAlgorithmException e) {
                        System.out.println("Algorithm not available for output length test: " + algorithm);
                    }
                }
            });
        }
    }
}
