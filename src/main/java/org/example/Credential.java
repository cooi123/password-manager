package org.example;

public class Credential {
    private String username;
    private String encryptedPassword;
    private String metadata;


    public Credential(String username, String unencryptedPassword, String metadata, byte[] encryptionKey) throws Exception {
        this.username = username;
        this.encryptedPassword = EncryptionUtil.encrypt(unencryptedPassword, encryptionKey);
        this.metadata = metadata;
    }

    public String getUsername() {
        return username;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    @Override
    public String toString() {
        return "Credential{" +
                "username='" + username + '\'' +
                ", encryptedPassword='" + encryptedPassword + '\'' +
                ", metadata='" + metadata + '\'' +
                '}';
    }
}
