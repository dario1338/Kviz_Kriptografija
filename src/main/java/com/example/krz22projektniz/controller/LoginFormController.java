package com.example.krz22projektniz.controller;

import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.HPos;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Priority;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.Window;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.util.*;

public class LoginFormController {

    private final RegistrationFormController registrationFormController = new RegistrationFormController();
    private final UserController userController = new UserController();
    private static final String separator = FileSystems.getDefault().getSeparator();
    private final String path = "C:\\Users\\Korisnik\\FAX\\3-Treca godina\\Kriptografija_i_racunarska_zastita\\ProjektniZadatakKriptografijaKviz\\paSSword";
    //private final String crlPath = "C:\\Users\\Korisnik\\FAX\\3-Treca godina\\Kriptografija_i_racunarska_zastita\\ProjektniZadatak\\crl\\novaCrl.crl";
    private static final String crlLocation = "crl" + separator + "crl_list";

    public GridPane createLoginFormPane() {
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
        // Add Column Constraints
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
        Label headerLabel = new Label("Login Form");
        headerLabel.setFont(Font.font("Arial", FontWeight.BOLD, 24));
        gridPane.add(headerLabel, 0, 0, 2, 1);
        GridPane.setHalignment(headerLabel, HPos.CENTER);
        GridPane.setMargin(headerLabel, new Insets(20, 0, 20, 0));
        // Add Name Label
        Label nameLabel = new Label("Username : ");
        gridPane.add(nameLabel, 0, 1);
        // Add Name Text Field
        TextField nameField = new TextField();
        nameField.setPrefHeight(40);
        gridPane.add(nameField, 1, 1);
        // Add Password Label
        Label passwordLabel = new Label("Password : ");
        gridPane.add(passwordLabel, 0, 2);
        // Add Password Field
        PasswordField passwordField = new PasswordField();
        passwordField.setPrefHeight(40);
        gridPane.add(passwordField, 1, 2);
        // Add Submit Button
        Button loginButton = new Button("Login");
        loginButton.setPrefHeight(40);
        loginButton.setDefaultButton(true);
        loginButton.setPrefWidth(100);
        gridPane.add(loginButton, 0, 4, 2, 1);
        GridPane.setHalignment(loginButton, HPos.CENTER);
        GridPane.setMargin(loginButton, new Insets(20, 0, 20, 0));

        loginButton.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                if (nameField.getText().isEmpty()) {
                    showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), "Form Error!", "Please enter your name");
                    return;
                }
                if (passwordField.getText().isEmpty()) {
                    showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), "Form Error!", "Please enter a password");
                    return;
                }

                String username = nameField.getText();
                String password = passwordField.getText();
                boolean usernameExist = false;
                String fileUsers = "C:\\Users\\Korisnik\\FAX\\3-Treca godina\\Kriptografija_i_racunarska_zastita\\ProjektniZadatakKriptografijaKviz\\data\\users.txt";
                File pathUsers = new File(fileUsers);
                try {
                    BufferedReader in = new BufferedReader(new FileReader(pathUsers.getAbsolutePath()));
                    String[] data;
                    String line;
                    StringBuffer stringBuffer = new StringBuffer();
                    while ((line = in.readLine()) != null) {
                        data = line.split(" ");
                        byte[] userNameDataHash = Base64.getDecoder().decode(data[0]);
                        byte[] usernameHash = RegistrationFormController.getHashUsername(username);
                        if (Arrays.equals(usernameHash, userNameDataHash)) {
                            usernameExist = true;
                            byte[] decodeSalt = Base64.getDecoder().decode(data[1]);
                            byte[] decodeHashPassword = Base64.getDecoder().decode(data[2]);
                            byte[] hashPassword = RegistrationFormController.getHashPassword(password, decodeSalt);
                            byte[] numOfLoggingByte = Base64.getDecoder().decode(data[3]);
                            String numOfLoggingString = new String(numOfLoggingByte);
                            int numOfLogging = Integer.parseInt(numOfLoggingString);
                            System.out.println(numOfLogging + 1);

                            if (Arrays.equals(decodeHashPassword, hashPassword)) {
                                if (validateCertificate(username)) {
                                    numOfLogging++;
                                    String numOfLoggingStr = Integer.toString(numOfLogging);
                                    String numberOfLoggingEnc = null;
                                    numberOfLoggingEnc = Base64.getEncoder().encodeToString(numOfLoggingStr.getBytes(StandardCharsets.UTF_8));
                                    stringBuffer.append(data[0]).append(" ").append(data[1]).append(" ").append(data[2]).append(" ").append(numberOfLoggingEnc).append("\n");
                                    if (numOfLogging == 3) {
                                        String certLocation = "certs" + separator + username + ".p12";
                                        try {
                                            KeyStore keystore = KeyStore.getInstance("PKCS12");
                                            InputStream loadKeystore = new FileInputStream(certLocation);
//                                            keystore.load(loadKeystore, new char[]{RegistrationFormController.pass});
                                            keystore.load(loadKeystore, new char[0]);
                                            X509Certificate certificate = (X509Certificate) keystore.getCertificate(username);

                                            if (revokeCertificate(certificate)) {
                                                InputStream inputStream = null;
                                                try {
                                                    inputStream = new FileInputStream("./crl/novaCrl.crl");
                                                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                                                    X509CRLHolder crl = new X509CRLHolder(inputStream);
                                                    X509CRL crlNew = new JcaX509CRLConverter().setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()).getCRL(crl);
                                                    listCRLEntry(crlNew);
                                                } catch (CertificateException | IOException e) {
                                                    e.printStackTrace();
                                                }
                                            }
                                        } catch (Exception e) {
                                            e.printStackTrace();
                                        }
                                    }
                                    ((Node) (event.getSource())).getScene().getWindow().hide();
                                    Stage stage = new Stage();
                                    BorderPane borderPane = userController.createMainMenuFormPane(username);
                                    Scene scene = new Scene(borderPane, 800, 500);
                                    stage.setScene(scene);
                                    stage.show();
                                } else {
                                    stringBuffer.append(line).append("\n");
                                    showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), "Form Error!", "Certificate is not valid.");
                                }
                            } else {
                                showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), "Form Error!", "Wrong password!");
                            }
                        } else {
                            stringBuffer.append(line).append("\n");
                        }
                    }
                    if(!usernameExist){
                            showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), "Form Error!", "User " + username + " does not exist.");
                    }
                    String newData = stringBuffer.toString();
                    FileOutputStream file = new FileOutputStream(pathUsers.getAbsolutePath());
                    file.write(newData.getBytes());
                    file.close();
                } catch (IOException | NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
            }
        });

        Button registrationButton = new Button("Registration");
        registrationButton.setPrefHeight(40);
        registrationButton.setDefaultButton(true);
        registrationButton.setPrefWidth(100);
        gridPane.add(registrationButton, 0, 5, 2, 1);
        GridPane.setHalignment(registrationButton, HPos.CENTER);
        GridPane.setMargin(registrationButton, new Insets(20, 0, 20, 0));

        registrationButton.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent actionEvent) {
                Stage stage = new Stage();
                stage.initModality(Modality.APPLICATION_MODAL);
                RegistrationFormController registrationFormController1 = new RegistrationFormController();
                GridPane gridPane1 = registrationFormController.createRegistrationFormPane();
                registrationFormController.addUIControls(gridPane1);
                Scene scene = new Scene(gridPane1, 800, 500);
                stage.setScene(scene);
                stage.show();
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

    private void saveKeyToKeystore(int randNumber) {
        System.out.println("create a keystore");
        System.out.println("load the keystore and store a secret key");
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream("./keys/keystore.p12"), "sigurnost".toCharArray());

            Path keyLocation = Paths.get("./keys/" + randNumber + ".key");
            byte[] encodedKey = Files.readAllBytes(keyLocation);

            PrivateKey privateKey = RegistrationFormController.loadPrivateKey("private4096");

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            SecretKey secretKey = new SecretKeySpec(cipher.doFinal(encodedKey), "AES");

            keyStore.setKeyEntry(Integer.toString(randNumber) ,secretKey , "sigurnost".toCharArray(), null);
            // save the keystore
            keyStore.store(new FileOutputStream("./keys/keystore.p12"), "sigurnost".toCharArray());
            System.out.println("KLJUC" + randNumber);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private boolean validateCertificate(String fromUser) {
        String certLocation = "certs" + separator + fromUser + ".p12";
        try {
            PublicKey rootPubKey;
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            InputStream loadKeystore = new FileInputStream(certLocation);
            //dodamo liniju koda ispod kad hocemo da zakljucamo keystore i liniju ispod ove zakomentarisemo, ispraviti i u regFormControler
            //keystore.load(loadKeystore, new char[]{RegistrationFormController.pass});
            keystore.load(loadKeystore, new char[0]);
            X509Certificate certificate = (X509Certificate) keystore.getCertificate(fromUser);
           // String issuerName = certificate.getIssuerX500Principal().getName();  //s ovom linijom koda dobijamo kompletan DN iz issuer - a
            X500Name x500Name = new JcaX509CertificateHolder(certificate).getIssuer();
            RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
            String issuerName = IETFUtils.valueToString(cn.getFirst().getValue());
            if (issuerName.equalsIgnoreCase("caA")) {
                rootPubKey = loadPublicKey("caA");
            } else {
                rootPubKey = loadPublicKey("caB");
            }
            certificate.verify(rootPubKey);
            certificate.checkValidity(new Date(System.currentTimeMillis()));

            Path crlPath = Paths.get("./crl/novaCrl.crl");
            if (Files.exists(crlPath)) {
                X509CRLEntry revokedCertificate;
                X509CRL crl = (X509CRL) factory.generateCRL(new DataInputStream(new FileInputStream("./crl/novaCrl.crl")));
                revokedCertificate = crl.getRevokedCertificate(certificate.getSerialNumber());
                return revokedCertificate == null;
            }
            return true;
        } catch (CertificateException | FileNotFoundException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException | CRLException e) {
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    static PublicKey loadPublicKey(String fromUser) {
        String certLocation = "certs" + separator + fromUser + ".crt";
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(new FileInputStream(certLocation));
            return certificate.getPublicKey();
        } catch (CertificateException | FileNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void listCRLEntry(X509CRL crl) throws CertificateException, IOException {
        Set s = crl.getRevokedCertificates();
        if (s != null && !s.isEmpty()) {
            Iterator t = s.iterator();
            while (t.hasNext()) {
                X509CRLEntry entry = (X509CRLEntry) t.next();
                System.out.println("serial number = " + entry.getSerialNumber().toString(16));
                System.out.println("revocation date = " + entry.getRevocationDate());
                System.out.println("extensions = " + entry.hasExtensions());
                System.out.println("reason = " + entry.getRevocationReason());
            }
        }
    }

    private static X509CRLHolder createCRL(X509Certificate cert) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        Calendar calendar = Calendar.getInstance();
        Date currentDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        Date nextYear = calendar.getTime();
        calendar.add(Calendar.YEAR, -1);
        calendar.add(Calendar.SECOND, -30);
        Date revokeDate = calendar.getTime();

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(
                new X500Name(cert.getIssuerX500Principal().getName()),
                currentDate
        );
        crlBuilder.addExtension(
                Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(cert.getPublicKey())
        );
        crlBuilder.addExtension(
                Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(4110))
        );
        crlBuilder.addCRLEntry(
                new BigInteger(String.valueOf(cert.getSerialNumber())),
                revokeDate,
                CRLReason.cessationOfOperation
        );

        X500Name x500Name = new JcaX509CertificateHolder(cert).getIssuer();
        RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
        String issuerName = IETFUtils.valueToString(cn.getFirst().getValue());

        PrivateKey key = loadPrivateKey("private" + issuerName);
        return crlBuilder.setNextUpdate(nextYear).build(
                new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC")
                        .build(key)
        );
    }

    public static boolean revokeCertificate(X509Certificate cert) throws IOException {
       try {
           Calendar calendar = Calendar.getInstance();
           Date currentDate = calendar.getTime();
           calendar.add(Calendar.YEAR, 1);
           Date nextYear = calendar.getTime();
           calendar.add(Calendar.YEAR, -1);
           calendar.add(Calendar.SECOND, -30);
           Date revokeDate = calendar.getTime();

           X500Name x500Name = new JcaX509CertificateHolder(cert).getIssuer();
           RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
           String issuerName = IETFUtils.valueToString(cn.getFirst().getValue());

           X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(
                   new X500Name(cert.getIssuerX500Principal().getName()),
                   currentDate
           );
               InputStream inputStream = null;
               try {
                   inputStream = new FileInputStream("./crl/novaCrl.crl");
                   CertificateFactory cf = CertificateFactory.getInstance("X.509");
                   X509CRLHolder crl = new X509CRLHolder(inputStream);
                   crlBuilder.addCRL(crl);
                   //System.out.println("dodoaje staru crl u bilder");
               } catch (CertificateException | IOException e) {
                   e.printStackTrace();
               }
           crlBuilder.addCRLEntry(
                   new BigInteger(String.valueOf(cert.getSerialNumber())),
                   revokeDate,
                   CRLReason.cessationOfOperation
           );

           PrivateKey key = loadPrivateKey("private" + issuerName);
           System.out.println(issuerName);

           ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()).build(key);
           X509CRLHolder crlHolder = crlBuilder.build(signer);

           try (OutputStream fos = new FileOutputStream("./crl/novaCrl.crl")) {
               fos.write(crlHolder.getEncoded());
           } catch (IOException e) {
               e.printStackTrace();
           }
           return true;
       }catch (OperatorCreationException | CertificateEncodingException e) {
           e.printStackTrace();
       }
       return false;
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

}
