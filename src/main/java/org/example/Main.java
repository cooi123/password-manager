package org.example;


import org.example.encryption.AESEncryptionService;
import org.example.encryption.EncryptionService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        String masterPassword = "password123";

        List<Credential> credentials = new ArrayList<>();
        HashMap<String, String> credentialMap = new HashMap<>();
        credentialMap.put("testuser", "admin");
        credentialMap.put("admin", "password123");
        credentialMap.put("password", "admin");

        EncryptionService encryptionService;
        byte[] salt = KeyUtil.generateSalt();
        byte[] encryptionKey;
        try {
            encryptionKey = KeyUtil.getKey(masterPassword, salt);
            encryptionService = new AESEncryptionService(encryptionKey);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        try {
            for (String username : credentialMap.keySet()) {
                String encryptedPassword = encryptionService.encrypt(credentialMap.get(username));
                Credential credential = new Credential(username, encryptedPassword, "metadata");
                credentials.add(credential);
            }

            for (Credential credential : credentials) {

                String decryptedPassword = encryptionService.decrypt(credential.getEncryptedPassword());
                System.out.println("Decrypted password for " + credential.getUsername() + ": " + decryptedPassword);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

}


