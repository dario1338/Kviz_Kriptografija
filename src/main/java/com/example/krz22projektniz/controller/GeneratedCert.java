package com.example.krz22projektniz.controller;

import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.FileSystems;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class GeneratedCert {

    private static final String separator = FileSystems.getDefault().getSeparator();
    public final PrivateKey privateKey;
    public final X509Certificate certificate;

    public GeneratedCert(PrivateKey privateKey, X509Certificate certificate) {
        this.privateKey = privateKey;
        this.certificate = certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    static GeneratedCert createCertificate(String cnName, GeneratedCert issuer) throws Exception {

        // Generate the key-pair with the official Java API's
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair certKeyPair = keyGen.generateKeyPair();
        //savePrivateKey(certKeyPair, cnName);

        X500Name name = new X500Name("CN=" + cnName);
        // If you issue more than just test certificates, you might want a decent serial number schema ^.^
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Instant validFrom = Instant.now();
        Instant validUntil = validFrom.plus(10 * 360, ChronoUnit.DAYS);
        // If there is no issuer, we self-sign our certificate.
        X500Name issuerName;
        PrivateKey issuerKey;
        if (issuer == null) {
            issuerName = name;
            issuerKey = certKeyPair.getPrivate();
        } else {
            issuerName = new X500Name(issuer.certificate.getSubjectX500Principal().getName());
            issuerKey = issuer.privateKey;
        }
        RDN[] rdns = issuerName.getRDNs();
        for(int i = 0; i < rdns.length; i++) {
            AttributeTypeAndValue[] atts = rdns[i].getTypesAndValues();
            for(int j = 0; j < atts.length; j++) {
                if(atts[j].getType().equals(BCStyle.CN)){
                    atts[j] = new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String(cnName));
                    rdns[i] = new RDN(atts);
                } else if(atts[j].getType().equals(BCStyle.EmailAddress)) {
                    atts[i] = new AttributeTypeAndValue(BCStyle.EmailAddress, new DERUTF8String(cnName + "@mail.com"));
                    rdns[i] = new RDN(atts);
                }
            }
        }
        X500Name example = new X500Name(rdns);
        // The cert builder to build up our certificate information
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                Date.from(validFrom), Date.from(validUntil),
                example, certKeyPair.getPublic());

        final JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        //builder.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(certKeyPair.getPublic()));
        //builder.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(certKeyPair.getPublic()));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyAgreement));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(issuerKey);
        X509CertificateHolder certHolder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);

        return new GeneratedCert(certKeyPair.getPrivate(), cert);
    }

    public static void savePrivateKey(KeyPair keyPair, String username) throws IOException {

        String path = "private" + separator + username + ".key";
        PrivateKey privateKey = keyPair.getPrivate();
        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                privateKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(path);
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();
    }

}
