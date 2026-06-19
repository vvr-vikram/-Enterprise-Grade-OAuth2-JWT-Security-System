package com.security.system.security;

import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Component
public class RsaKeyManager {

    private static final Logger log = LoggerFactory.getLogger(RsaKeyManager.class);
    private static final String KEY_FILE = "keystore.json";

    private RSAKey rsaKey;

    @PostConstruct
    public void init() {
        try {
            File file = new File(KEY_FILE);
            if (file.exists()) {
                String content = Files.readString(file.toPath());
                this.rsaKey = RSAKey.parse(content);
                log.info("Loaded existing RSA keys from {}", KEY_FILE);
            } else {
                log.info("Generating new RSA Key Pair for token signing...");
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();

                RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
                RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();

                this.rsaKey = new RSAKey.Builder(publicKey)
                        .privateKey(privateKey)
                        .keyID(UUID.randomUUID().toString())
                        .build();

                Files.writeString(file.toPath(), this.rsaKey.toJSONString());
                log.info("Generated and saved RSA key to {}", KEY_FILE);
            }
        } catch (Exception e) {
            log.error("Error initializing RSA keys. Creating in-memory fallback...", e);
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                this.rsaKey = new RSAKey.Builder((RSAPublicKey) kp.getPublic())
                        .privateKey((RSAPrivateKey) kp.getPrivate())
                        .keyID(UUID.randomUUID().toString())
                        .build();
            } catch (Exception ex) {
                throw new IllegalStateException("Could not generate RSA keys", ex);
            }
        }
    }

    public RSAKey getRsaKey() {
        return this.rsaKey;
    }

    public RSAPublicKey getPublicKey() throws Exception {
        return this.rsaKey.toRSAPublicKey();
    }

    public RSAPrivateKey getPrivateKey() throws Exception {
        return this.rsaKey.toRSAPrivateKey();
    }

    public String getKeyId() {
        return this.rsaKey.getKeyID();
    }
}
