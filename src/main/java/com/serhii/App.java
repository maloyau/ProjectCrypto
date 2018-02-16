package com.serhii;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

public class App
{
    private static final String STORENAME = "D:/store.p12";
    private static final String STOREPASSWORD = "password";

    public static void main(String[] args) throws Exception {
        KeyStore keyStore = loadKeyStore();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        X509Certificate x509Certificate = generateCertificate(keyPair);
        System.out.println(x509Certificate.toString());

    }

    private static X509Certificate generateCertificate(KeyPair keyPair) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, InvalidKeyException, SignatureException, OperatorCreationException, IOException {
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                new X500Name("CN=Serhii Herashchenko, O=PSJC VBR, L=Kyiv City, ST=Kyiv State, C=UA"),
                BigInteger.valueOf(new Random().nextInt()), new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)), new X500Name("CN=Serhii Herashchenko, O=PSJC VBR, L=Kyiv City, ST=Kyiv State, C=UA"), SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = builder.build(keyPair.getPrivate());

        byte[] certBytes = certBuilder.build(signer).getEncoded();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));
    }



    private static KeyStore loadKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        FileInputStream fileInputStream = null;
        char[] password = STOREPASSWORD.toCharArray();
        try {
            fileInputStream = new FileInputStream(STORENAME);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            createKeyStore();
        }
        keyStore.load(fileInputStream, password);
        return keyStore;
    }

    private static void createKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] password = STOREPASSWORD.toCharArray();
        keyStore.load(null, password);
        FileOutputStream fileOutputStream = new FileOutputStream(STORENAME);
        keyStore.store(fileOutputStream, STOREPASSWORD.toCharArray());
        fileOutputStream.close();
    }

}
