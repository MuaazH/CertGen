// This file is part of the i04.libs project by MuaazH
// Copyright (C) MuaazH - All Rights Reserved
// Unauthorized copying of this file, via any medium is strictly prohibited
// Proprietary and confidential
// Written by MuaazH <muaaz.h.is@gmail.com>
package i04.libs.tls;

import sun.security.util.KnownOIDs;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.*;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Vector;

/**
 * @author MuaazH (muaaz.h.is@gmail.com)
 */
public class TlsUtils {

    public static final String PROTOCOL = "TLSv1.3";
    private static final String KEY_ALGORITHM = "EC";
    private static final String KEY_CURVE = "secp384r1";

    public static KeyPair generateKeyPair() throws Exception {
        // Create a KeyPairGenerator for the EC algorithm
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        // Specify the secp384r1 curve
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(KEY_CURVE);
        // Initialize the KeyPairGenerator with the curve specification
        keyPairGenerator.initialize(ecSpec);
        // Generate the key pair
        return keyPairGenerator.generateKeyPair();
    }

    public static void writeKeyToPem(PrivateKey privateKey, char[] password, Writer writer) throws Exception {
        // Use PBE with SHA-1 and DESede to encrypt the private key
//        String algorithm = "PBEWithSHA1AndDESede";
        String algorithm = "PBEWithHMACSHA512AndAES_128";
        int iterationCount = 10000;
        byte[] salt = new byte[8];
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterationCount);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance(algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, keyFac.generateSecret(pbeKeySpec), pbeParamSpec);

        // Encrypt the private key
        byte[] encryptedPrivateKeyBytes = cipher.doFinal(privateKey.getEncoded());

        // Create algorithm parameters for the PBE algorithm
        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance(algorithm);
        algorithmParameters.init(pbeParamSpec);

        // Create EncryptedPrivateKeyInfo
        EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(algorithmParameters, encryptedPrivateKeyBytes);

        // Encode to Base64
        String base64EncodedEncryptedPrivateKey = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encryptedPrivateKeyInfo.getEncoded());

        // Write to PEM file
        writer.write("-----BEGIN ENCRYPTED PRIVATE KEY-----\n");
        writer.write(base64EncodedEncryptedPrivateKey);
        writer.write("\n-----END ENCRYPTED PRIVATE KEY-----\n");
    }

    public static void writeCertificateToPEM(X509Certificate certificate, Writer writer) throws Exception {
        writer.write("-----BEGIN CERTIFICATE-----\n");
        writer.write(Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(certificate.getEncoded()));
        writer.write("\n-----END CERTIFICATE-----\n");
    }

    public static X509Certificate generateCertificate(CertConfig cnf) throws Exception {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + cnf.daysLeft * 24L * 60L * 60L * 1000L); // 5 years of validity

        final String signatureAlgorithm = "SHA256withECDSA";

        CertificateExtensions extensions = new CertificateExtensions();

        // SubjectAltName
        if (cnf.subjectAltName != null && !cnf.subjectAltName.isEmpty()) {
            extensions.setExtension(
                    SubjectAlternativeNameExtension.NAME,
                    new SubjectAlternativeNameExtension(new GeneralNames().add(new GeneralName(new DNSName(cnf.subjectAltName))))
            );
        }

        // Basic constraints (mark as CA)
        if (cnf.isCA) {
            extensions.setExtension(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(true, -1));
        }

        // Key usage
        KeyUsageExtension keyUsageExtension = getKeyUsageExtension(cnf);
        extensions.setExtension(KeyUsageExtension.NAME, keyUsageExtension);

        // Extended key usage
        ExtendedKeyUsageExtension extendedKeyUsageExtension = getExtendedKeyUsageExtension(cnf);
        if (extendedKeyUsageExtension != null) {
            extensions.setExtension(ExtendedKeyUsageExtension.NAME, extendedKeyUsageExtension);
        }

        // O=Organization
        // L=City
        // ST=State
        // C=Country
        X500Name owner = new X500Name("CN=%s, O=%s, L=%s, ST=%s, C=%s".formatted(
                cnf.name.commonName.trim(),
                cnf.name.organization.trim(),
                cnf.name.city.trim(),
                cnf.name.state.trim(),
                cnf.name.country.trim()
        ));

        // O=Organization
        // L=City
        // ST=State
        // C=Country
        X500Name issuer = new X500Name("CN=%s, O=%s, L=%s, ST=%s, C=%s".formatted(
                cnf.issuer.commonName.trim(),
                cnf.issuer.organization.trim(),
                cnf.issuer.city.trim(),
                cnf.issuer.state.trim(),
                cnf.issuer.country.trim()
        ));

        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        X509CertInfo certInfo = new X509CertInfo();
        certInfo.setValidity(new CertificateValidity(startDate, endDate));
        certInfo.setSerialNumber(new CertificateSerialNumber(serialNumber));
        certInfo.setSubject(owner);
        certInfo.setIssuer(issuer);
        certInfo.setKey(new CertificateX509Key(cnf.certKey));
        certInfo.setVersion(new CertificateVersion(CertificateVersion.V3));
        certInfo.setAlgorithmId(new CertificateAlgorithmId(AlgorithmId.get(signatureAlgorithm)));
        certInfo.setExtensions(extensions);

        return X509CertImpl.newSigned(certInfo, cnf.signKey, signatureAlgorithm);
    }

    private static KeyUsageExtension getKeyUsageExtension(CertConfig cnf) throws IOException {
        KeyUsageExtension e = new KeyUsageExtension();
        e.set(KeyUsageExtension.DIGITAL_SIGNATURE, cnf.keyUsage.digitalSignature);
        e.set(KeyUsageExtension.NON_REPUDIATION, cnf.keyUsage.nonRepudiation);
        e.set(KeyUsageExtension.KEY_ENCIPHERMENT, cnf.keyUsage.keyEncipherment);
        e.set(KeyUsageExtension.DATA_ENCIPHERMENT, cnf.keyUsage.dataEncipherment);
        e.set(KeyUsageExtension.KEY_AGREEMENT, cnf.keyUsage.keyAgreement);
        e.set(KeyUsageExtension.KEY_CERTSIGN, cnf.keyUsage.keyCertSign);
        e.set(KeyUsageExtension.CRL_SIGN, cnf.keyUsage.crlSign);
        e.set(KeyUsageExtension.ENCIPHER_ONLY, cnf.keyUsage.encipherOnly);
        e.set(KeyUsageExtension.DECIPHER_ONLY, cnf.keyUsage.decipherOnly);
        return e;
    }

    private static ExtendedKeyUsageExtension getExtendedKeyUsageExtension(CertConfig cnf) throws IOException {
        Vector<ObjectIdentifier> vec = new Vector<>();
        if (cnf.extendedKeyUsage.serverAuth) {
            vec.add(ObjectIdentifier.of(KnownOIDs.serverAuth));
        }
        if (cnf.extendedKeyUsage.clientAuth) {
            vec.add(ObjectIdentifier.of(KnownOIDs.clientAuth));
        }
        if (cnf.extendedKeyUsage.emailProtection) {
            vec.add(ObjectIdentifier.of(KnownOIDs.emailProtection));
        }
        if (vec.isEmpty()) {
            return null;
        }
        return new ExtendedKeyUsageExtension(vec);
    }

    public static PrivateKey loadKey(String keyFile, char[] pass) throws Exception {
        return loadKey(keyFile, pass, KEY_ALGORITHM);
    }

    private static PrivateKey loadUnencryptedKey(String keyFile, String algorithm) throws Exception {
        String key = new String(Files.readAllBytes(Paths.get(keyFile)));

        String base64 = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace(" ", "")
                .replace("\t", "")
                .replace("\r", "")
                .replace("\n", "");

        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64));
        return keyFactory.generatePrivate(encodedKeySpec);
    }

    public static PrivateKey loadKey(String keyFile, char[] pass, String algorithm) throws Exception {
        if (pass == null || pass.length == 0) {
            return loadUnencryptedKey(keyFile, algorithm);
        }
        String base64 = new String(Files.readAllBytes(Paths.get(keyFile)))
                .replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
                .replace("-----END ENCRYPTED PRIVATE KEY-----", "")
                .replace(" ", "")
                .replace("\t", "")
                .replace("\r", "")
                .replace("\n", "");

        EncryptedPrivateKeyInfo pkInfo = new EncryptedPrivateKeyInfo(Base64.getDecoder().decode(base64));
        PBEKeySpec keySpec = new PBEKeySpec(pass); // password
        SecretKeyFactory pbeKeyFactory = SecretKeyFactory.getInstance(pkInfo.getAlgName());
        PKCS8EncodedKeySpec encodedKeySpec = pkInfo.getKeySpec(pbeKeyFactory.generateSecret(keySpec));
        return KeyFactory.getInstance(algorithm).generatePrivate(encodedKeySpec);
    }

    public static java.security.cert.Certificate[] loadCertificates(String certFile) throws Exception {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        try (FileInputStream is = new FileInputStream(certFile)) {
            return fact.generateCertificates(is).toArray(new Certificate[0]);
        }
    }

    public static java.security.cert.Certificate loadCertificate(String certFile) throws Exception {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        try (FileInputStream is = new FileInputStream(certFile)) {
            return fact.generateCertificate(is);
        }
    }

    public static KeyManager[] generateKeyManager(Certificate[] chain, PrivateKey key) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {

        // Set the Entry with PrivateKey and Certificate chain
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null); // Initialize the KeyStore
        keyStore.setKeyEntry("mainKey", key, new char[0], chain);

        // Initialize KeyManagerFactory
        KeyManagerFactory manager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        manager.init(keyStore, new char[0]);
        return manager.getKeyManagers();
    }

    public static TrustManager[] generateTrustManager(Certificate[] list) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        // create an empty manager
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null); // Initialize the KeyStore
        for (int i = 0; i < list.length; i++) {
            keyStore.setCertificateEntry("TRUSTED ROOT " + i, list[i]);
        }

        // Set up the trust manager factory
        TrustManagerFactory manager = TrustManagerFactory.getInstance("SunX509");
        manager.init(keyStore);
        return manager.getTrustManagers();
    }

    public static SSLContext loadTlsCert(String certFile, String keyFile, char[] pass, String caFile) throws Exception {
        Certificate[] chain = TlsUtils.loadCertificates(certFile);
        PrivateKey key = TlsUtils.loadKey(keyFile, pass, chain[0].getPublicKey().getAlgorithm());

        // Set up key manager
        KeyManager[] keyManagers = TlsUtils.generateKeyManager(chain, key);

        // Set up the trust manager factory
        TrustManager[] trustManagers = TlsUtils.generateTrustManager(
                caFile == null ? new Certificate[0] : loadCertificates(caFile)
        );

        // Set up the SSL context
        SSLContext sslContext = SSLContext.getInstance(PROTOCOL);
        sslContext.init(
                keyManagers,
                trustManagers,
                null
        );

        return sslContext;
    }

}
