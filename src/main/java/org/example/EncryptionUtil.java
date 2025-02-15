package org.example;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class EncryptionUtil {
    private static final int IV_LENGTH = 12;           // 12 bytes for GCM recommended
    private static final int GCM_TAG_LENGTH = 128;       // in bits

    /**
     * Encrypts the given plaintext (e.g., a password) using AES-GCM.
     *
     * @param plaintext     The password to encrypt.
     * @param encryptionKey The derived master key.
     * @return Base64-encoded string containing IV and ciphertext.
     * @throws Exception If encryption fails.
     */
    public static String encrypt(String plaintext, byte[] encryptionKey) throws Exception {
        // Generate a random IV
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        // Set up the cipher in encryption mode
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(encryptionKey, "AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, parameterSpec);

        // Encrypt the plaintext password
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Prepend IV to ciphertext so it can be used during decryption
        byte[] ivAndCiphertext = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, ivAndCiphertext, 0, iv.length);
        System.arraycopy(ciphertext, 0, ivAndCiphertext, iv.length, ciphertext.length);

        // Return the result as a Base64-encoded string
        return Base64.getEncoder().encodeToString(ivAndCiphertext);
    }

    /**
     * Decrypts the given Base64-encoded ciphertext using AES-GCM.
     *
     * @param base64IvAndCiphertext The encrypted password data.
     * @param encryptionKey         The derived master key.
     * @return The decrypted plaintext password.
     * @throws Exception If decryption fails.
     */
    public static String decrypt(String base64IvAndCiphertext, byte[] encryptionKey) throws Exception {
        // Decode the Base64-encoded data
        byte[] ivAndCiphertext = Base64.getDecoder().decode(base64IvAndCiphertext);

        // Extract the IV and ciphertext
        byte[] iv = Arrays.copyOfRange(ivAndCiphertext, 0, IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(ivAndCiphertext, IV_LENGTH, ivAndCiphertext.length);

        // Set up the cipher in decryption mode
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(encryptionKey, "AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, parameterSpec);

        byte[] plaintextBytes = cipher.doFinal(ciphertext);
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }
}
