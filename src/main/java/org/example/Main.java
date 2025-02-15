package org.example;


public class Main {
    public static void main(String[] args) {
        String masterPassword = "password123";
        byte[] salt = KeyUtil.generateSalt();
        byte[] encryptionKey;
        try {
            encryptionKey = KeyUtil.getKey(masterPassword, salt);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        try {
            Credential credential = new Credential("johndoe", "letmein", "metadata", encryptionKey);
            System.out.println(credential);

            String decryptedPassword = EncryptionUtil.decrypt(credential.getEncryptedPassword(), encryptionKey);
            System.out.println("Decrypted password: " + decryptedPassword);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

}


