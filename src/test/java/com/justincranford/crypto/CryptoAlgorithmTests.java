package com.justincranford.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.Mac;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

class CryptoAlgorithmTests {
    @ParameterizedTest
    @ValueSource(strings = {"HMACSHA256", "HmacSHA256"})
    void testMacInstanceWithDifferentSpellings(String algorithmName) {
        assertDoesNotThrow(() -> {
            Mac mac = Mac.getInstance(algorithmName);
            assertNotNull(mac, "Mac instance should not be null for " + algorithmName);
            assertEquals(algorithmName, mac.getAlgorithm(), "Algorithm name should match for " + algorithmName);
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"HMACSHA256", "HmacSHA256"})
    void testHmacComputationWithDifferentSpellings(String algorithmName) {
        assertDoesNotThrow(() -> {
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
            SecretKey secretKey = keyGen.generateKey();

            Mac mac = Mac.getInstance(algorithmName);
            mac.init(secretKey);
            byte[] testData = "Test data for HMAC SHA256".getBytes(StandardCharsets.UTF_8);
            byte[] hmacResult = mac.doFinal(testData);
            
            assertNotNull(hmacResult, "HMAC result should not be null for " + algorithmName);
            assertEquals(32, hmacResult.length, "HMAC-SHA256 should produce 32-byte output for " + algorithmName);
            assertTrue(hmacResult.length > 0, "HMAC result should not be empty for " + algorithmName);
        });
    }
}
