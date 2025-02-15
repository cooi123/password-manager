package org.example;

public class Credential {
    private String username;
    private String encryptedPassword;
    private String metadata;


    public Credential(String username, String encryptedPassword, String metadata) {
        this.username = username;
        this.encryptedPassword = encryptedPassword;
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
