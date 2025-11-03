// Copyright (C) MuaazH - All Rights Reserved
// Unauthorized copying of this file, via any medium is strictly prohibited
// Proprietary and confidential
// Written by MuaazH <muaaz.h.is@gmail.com>
package i04.certgen;

import i04.libs.tls.*;

import java.io.FileInputStream;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * @author MuaazH (muaaz.h.is@gmail.com)
 */
public class Main {

    private static boolean asBool(String str) {
        str = str.toLowerCase();
        boolean b = str.equals("true") || str.equals("yes") || str.equals("1");
        if (b) {
            return true;
        }
        b = str.equals("false") || str.equals("no") || str.equals("0");
        if (b) {
            return false;
        }
        throw new IllegalArgumentException("Invalid boolean value: " + str);
    }

    private static CertConfig loadCertConfig(String fileName, int depth) throws Exception {
        Properties props = new Properties();
        props.load(new FileInputStream(fileName));

        CertConfig config = new CertConfig();

        config.keyAlgorithm = props.getProperty("key.algorithm");
        if (!config.keyAlgorithm.equals(TlsUtils.KEY_EXCHANGE_ALGORITHM) && !config.keyAlgorithm.equals(TlsUtils.SIGNATURE_ALGORITHM)) {
            throw new IllegalArgumentException("Unsupported key algorithm: " + config.keyAlgorithm);
        }

        config._keyOutput = props.getProperty("output.key");
        config._crtOutput = props.getProperty("output.crt");

        config.subjectAltName = props.getProperty("subject.alt.name").trim();
        System.out.println("config.subjectAltName = " + config.subjectAltName);

        config.name = new CertName();
        config.name.commonName = props.getProperty("name.commonName").trim();
        config.name.organization = props.getProperty("name.organization").trim();
        config.name.city = props.getProperty("name.city").trim();
        config.name.state = props.getProperty("name.state").trim();
        config.name.country = props.getProperty("name.country").trim();

        config._selfSigned = props.getProperty("issuer").equals("self");

        if (config._selfSigned) {
            config.issuer = config.name; // self signed
            config._crtChain = "";
        } else if (depth == 0) {
            CertConfig issuer = loadCertConfig(props.getProperty("issuer"), depth + 1);
            config.issuer = issuer.name;

            System.out.println("Enter issuer private key passphrase: ");
            char[] pass = System.console().readPassword();

            config.signKey = TlsUtils.loadKey(issuer._keyOutput, pass);

            if (asBool(props.getProperty("output.crt.chain"))) {
                System.out.println("Loading issuer cert for chaining");
                config._crtChain = Files.readString(Path.of(issuer._crtOutput));
            } else {
                config._crtChain = "";
            }
        }

        config.daysLeft = Integer.parseInt(props.getProperty("daysLeft"));
        config.isCA = asBool(props.getProperty("isCA"));

        config.keyUsage = new KeyUsage();
        config.keyUsage.digitalSignature = asBool(props.getProperty("keyUsage.digitalSignature"));
        config.keyUsage.nonRepudiation = asBool(props.getProperty("keyUsage.nonRepudiation"));
        config.keyUsage.keyEncipherment = asBool(props.getProperty("keyUsage.keyEncipherment"));
        config.keyUsage.dataEncipherment = asBool(props.getProperty("keyUsage.dataEncipherment"));
        config.keyUsage.keyAgreement = asBool(props.getProperty("keyUsage.keyAgreement"));
        config.keyUsage.keyCertSign = asBool(props.getProperty("keyUsage.keyCertSign"));
        config.keyUsage.crlSign = asBool(props.getProperty("keyUsage.crlSign"));
        config.keyUsage.encipherOnly = asBool(props.getProperty("keyUsage.encipherOnly"));
        config.keyUsage.decipherOnly = asBool(props.getProperty("keyUsage.decipherOnly"));

        config.extendedKeyUsage = new ExtendedKeyUsage();
        config.extendedKeyUsage.clientAuth = asBool(props.getProperty("extendedKeyUsage.clientAuth"));
        config.extendedKeyUsage.serverAuth = asBool(props.getProperty("extendedKeyUsage.serverAuth"));
        config.extendedKeyUsage.emailProtection = asBool(props.getProperty("extendedKeyUsage.emailProtection"));

        return config;
    }

    static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("Usage: certgen <properties file>");
            System.exit(1);
        }

        System.out.println("Loading properties from " + args[0]);
        CertConfig config = loadCertConfig(args[0], 0);

        System.out.println("Generating key pair");
        KeyPair keyPair = TlsUtils.generateKeyPair(config.keyAlgorithm);

        config.certKey = keyPair.getPublic();
        if (config._selfSigned) {
            config.signKey = keyPair.getPrivate();
        }

        System.out.println("Generating Certificate");
        X509Certificate ca = TlsUtils.generateCertificate(config);

        System.out.println("Saving private key, Please enter passphrase: ");
        char[] keyPassword = System.console().readPassword();
        try (FileWriter writer = new FileWriter(config._keyOutput)) {
            TlsUtils.writeKeyAsPem(keyPair.getPrivate(), keyPassword, writer);
            writer.flush();
        }

        System.out.println("Saving certificate");
        try (FileWriter writer = new FileWriter(config._crtOutput)) {
            TlsUtils.writeCertificateToPem(ca, writer);
            writer.write(config._crtChain);
            writer.flush();
        }
    }
}
