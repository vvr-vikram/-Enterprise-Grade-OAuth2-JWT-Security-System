package com.security.system;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BcryptGen {
    @Test
    public void generateHash() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String hash = encoder.encode("password123");
        System.out.println("==================================================");
        System.out.println("BCRYPT HASH FOR 'password123': " + hash);
        System.out.println("==================================================");
    }
}
