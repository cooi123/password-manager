package org.example.encryption;

public interface EncryptionService {
    String encrypt(String plaintext) throws Exception;

    String decrypt(String base64IvAndCiphertext) throws Exception;
}
