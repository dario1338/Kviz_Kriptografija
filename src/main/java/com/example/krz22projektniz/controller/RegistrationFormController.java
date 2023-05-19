package com.example.krz22projektniz.controller;

import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.HPos;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Priority;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.stage.Window;
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
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Random;

public class RegistrationFormController {

    private String username;
    private String password;
    private byte[] salt;
    private byte[] hashPassword;
    private byte[] hashUsername;
    private static final Random RANDOM = new SecureRandom();
    private static final String separator = FileSystems.getDefault().getSeparator();
    private static final String path = "C:\\Users\\Korisnik\\FAX\\3-Treca godina\\Kriptografija_i_racunarska_zastita\\ProjektniZadatakKriptografijaKviz";
    static final char pass = 's';


    public GridPane createRegistrationFormPane() {
        // Instantiate a new Grid Pane
        GridPane gridPane = new GridPane();
        // Position the pane at the center of the screen, both vertically and horizontally
        gridPane.setAlignment(Pos.CENTER);
        // Set a padding of 20px on each side
        gridPane.setPadding(new Insets(40, 40, 40, 40));
        // Set the horizontal gap between columns
        gridPane.setHgap(10);
        // Set the vertical gap between rows
        gridPane.setVgap(10);
        // columnOneConstraints will be applied to all the nodes placed in column one.
        ColumnConstraints columnOneConstraints = new ColumnConstraints(100, 100, Double.MAX_VALUE);
        columnOneConstraints.setHalignment(HPos.RIGHT);
        // columnTwoConstraints will be applied to all the nodes placed in column two.
        ColumnConstraints columnTwoConstrains = new ColumnConstraints(200,200, Double.MAX_VALUE);
        columnTwoConstrains.setHgrow(Priority.ALWAYS);

        gridPane.getColumnConstraints().addAll(columnOneConstraints, columnTwoConstrains);

        return gridPane;
    }

    public void addUIControls(GridPane gridPane) {
        // Add Header
        Label headerLabel = new Label("Registration Form");
        headerLabel.setFont(Font.font("Arial", FontWeight.BOLD, 24));
        gridPane.add(headerLabel, 0,0,2,1);
        GridPane.setHalignment(headerLabel, HPos.CENTER);
        GridPane.setMargin(headerLabel, new Insets(20, 0,20,0));
        // Add Name Label
        Label nameLabel = new Label("Username : ");
        gridPane.add(nameLabel, 0,1);
        // Add Name Text Field
        TextField nameField = new TextField();
        nameField.setPrefHeight(40);
        gridPane.add(nameField, 1,1);
        // Add Password Label
        Label passwordLabel = new Label("Password : ");
        gridPane.add(passwordLabel, 0, 3);
        // Add Password Field
        PasswordField passwordField = new PasswordField();
        passwordField.setPrefHeight(40);
        gridPane.add(passwordField, 1, 3);
        // Add Submit Button
        Button submitButton = new Button("Submit");
        submitButton.setPrefHeight(40);
        submitButton.setDefaultButton(true);
        submitButton.setPrefWidth(100);
        gridPane.add(submitButton, 0, 4, 2, 1);
        GridPane.setHalignment(submitButton, HPos.CENTER);
        GridPane.setMargin(submitButton, new Insets(20, 0,20,0));

        submitButton.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                if (nameField.getText().isEmpty()) {
                    showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), "Form Error!", "Please enter your name");
                    return;
                } else {
                    username = nameField.getText();
                    try {
                        hashUsername = getHashUsername(username);
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    }
                }
                if (passwordField.getText().isEmpty()) {
                    showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), "Form Error!", "Please enter a password");
                    return;
                } else {
                    password = passwordField.getText();
                    salt = getNextSalt();
                    try {
                        hashPassword = getHashPassword(password, salt);
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    }
                }
                ((Node) (event.getSource())).getScene().getWindow().hide();
                String encodedHashUsername = Base64.getEncoder().encodeToString(hashUsername);

                String path = "C:\\Users\\Korisnik\\FAX\\3-Treca godina\\Kriptografija_i_racunarska_zastita\\ProjektniZadatakKriptografijaKviz\\data\\users.txt";
                File file = new File(path);
                boolean userNameExists = false;
                try {
                    BufferedReader in = new BufferedReader(new FileReader(file.getAbsolutePath()));
                    String[] data;
                    String line;
                    while ((line = in.readLine()) != null) {
                        data = line.split(" ");
                        byte[] userNameDataHash = Base64.getDecoder().decode(data[0]);
                        if (Arrays.equals(hashUsername, userNameDataHash)) {
                            userNameExists = true;
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
                if (!userNameExists) {
                    String encodedHashPassword = Base64.getEncoder().encodeToString(hashPassword);
                    String encodedSalt = Base64.getEncoder().encodeToString(salt);

                    int numberOfLogging = 0;
                    String numOfLoggingStr = Integer.toString(numberOfLogging);
                    String numberOfLoggingEnc;
                    numberOfLoggingEnc = Base64.getEncoder().encodeToString(numOfLoggingStr.getBytes(StandardCharsets.UTF_8));

                    PrintWriter writer;
                    try {
                        writer = new PrintWriter(new BufferedWriter(new FileWriter(file.getAbsolutePath(), true)));
                        writer.append(encodedHashUsername).append(" ");
                        writer.append(encodedSalt).append(" ");
                        writer.append(encodedHashPassword).append(" ");
                        writer.append(numberOfLoggingEnc);
                        writer.append("\n");
                        writer.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    Random rand = new Random();
                    boolean ca = rand.nextBoolean();
                    if (ca) {
                        X509Certificate cert = loadCertificate("caA");
                        PrivateKey key = loadPrivateKey("privatecaA");
                        GeneratedCert issuer = new GeneratedCert(key, cert);
                        try {
                            GeneratedCert generatedCert = GeneratedCert.createCertificate(username, issuer);
                            char[] emptyPassword = new char[0];
//                                emptyPassword [0] = pass;
                            KeyStore keyStore = KeyStore.getInstance("PKCS12");
                            keyStore.load(null, emptyPassword);
                            keyStore.setKeyEntry(username, generatedCert.privateKey, emptyPassword,
                                    new X509Certificate[]{generatedCert.certificate});
                            File myCert = new File("./certs/" + username + ".p12");
                            try (FileOutputStream store = new FileOutputStream(myCert)) {
                                keyStore.store(store, emptyPassword);
                                System.out.println(myCert.getAbsolutePath());
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        X509Certificate cert = loadCertificate("caB");
                        PrivateKey key = loadPrivateKey("privatecaB");
                        GeneratedCert issuer = new GeneratedCert(key, cert);
                        try {
                            GeneratedCert generatedCert = GeneratedCert.createCertificate(username, issuer);
//                                char[] emptyPassword = new char[1];
//                                emptyPassword [0] = pass;
                            //prethodne dvije linije odkomentarisemo, a liniju ispod zakomentarisemo kada hocemo da zakljucamo keystore sa certifikatom
                            char[] emptyPassword = new char[0];
                            KeyStore keyStore = KeyStore.getInstance("PKCS12");
                            keyStore.load(null, emptyPassword);
                            keyStore.setKeyEntry(username, generatedCert.privateKey, emptyPassword,
                                    new X509Certificate[]{generatedCert.certificate});
                            File myCert = new File("./certs/" + username + ".p12");
                            try (FileOutputStream store = new FileOutputStream(myCert)) {
                                keyStore.store(store, emptyPassword);
                                System.out.println(myCert.getAbsolutePath());
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                    showAlert(Alert.AlertType.CONFIRMATION, gridPane.getScene().getWindow(), "Registration Successful!", "Welcome " + nameField.getText());
                } else {
                    showAlert(Alert.AlertType.CONFIRMATION, gridPane.getScene().getWindow(), "Registration not Successful!", "User " + username + " alredy exists");
                }
            }
            });
    }

    private void showAlert(Alert.AlertType alertType, Window owner, String title, String message) {
        Alert alert = new Alert(alertType);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.initOwner(owner);
        alert.show();
    }

    public static byte[] getNextSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }

    public static byte[] getHashUsername(String username) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        digest.reset();
        return digest.digest(username.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] getHashPassword(String password, byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.reset();
        digest.update(salt);
        return digest.digest(password.getBytes(StandardCharsets.UTF_8));
    }

    public static KeyPair keyPairGenerate() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public X509Certificate loadCertificate(String fromUser) {
        String certLocation = "certs" + separator + fromUser + ".crt";
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(new FileInputStream(certLocation));
            return certificate;
        } catch (CertificateException | FileNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    static PrivateKey loadPrivateKey(String fromUser) {
        String keyPath = "private" + separator + fromUser + ".key";

        try (PEMParser parser = new PEMParser(new BufferedReader(new FileReader(keyPath)))) {
            PEMKeyPair pemKeyPair = (PEMKeyPair) parser.readObject();
            KeyPair keyPair = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
            return keyPair.getPrivate();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void saveCertificate(X509Certificate cert, String username) throws CertificateEncodingException, IOException {
        String path = "certs" + separator + username + ".crt";
        // Read Private Key.
        File file = new File(path);
        byte[] buf = cert.getEncoded();
        //assert file != null;
        FileOutputStream os = new FileOutputStream(file);
        os.write(buf);
        os.close();

        Writer wr = new OutputStreamWriter(os, StandardCharsets.UTF_8);
        wr.write(new String (Base64.getEncoder().encode(buf)));
        //wr.flush();
    }

    public X509Certificate createCert(String cnName, GeneratedCert issuer) throws Exception{
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

        return cert;
    }

}
