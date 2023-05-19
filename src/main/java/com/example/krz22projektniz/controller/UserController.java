package com.example.krz22projektniz.controller;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.image.PixelReader;
import javafx.scene.image.PixelWriter;
import javafx.scene.image.WritableImage;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.util.Pair;

import javax.crypto.*;
import java.io.*;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.function.Function;
import java.util.stream.IntStream;

import static java.io.File.separator;

public class UserController {

    private static final String ROOT_FOLDER = "C:\\Users\\Korisnik\\FAX\\3-Treca godina\\Kriptografija_i_racunarska_zastita\\ProjektniZadatakKriptografijaKviz\\users";// TODO: change or make selectable
    private static final String PATH_QUESTIONS = "C:\\Users\\Korisnik\\FAX\\3-Treca godina\\Kriptografija_i_racunarska_zastita\\ProjektniZadatakKriptografijaKviz\\questions\\";
    BorderPane border = new BorderPane();
    TreeItem<FilePath> rootTreeItem;
    TreeView<FilePath> treeView;
    private int num = 0;
    private static int rezultat = 0;
    private boolean dodijeliBodove = false;
    public Button buttonNext = new Button("Next");
    public Button buttonShow = new Button("Show");

    public String readQuestion(int randNumber) {
        Image image = new Image(PATH_QUESTIONS + randNumber + ".jpg");
        String decryptedMessage = decode(image);
        byte[] encryptedData = Base64.getDecoder().decode(decryptedMessage);

        Key secretKey = loadKeyFromKeystore(randNumber);

        byte[] decryptedData = decrypt(encryptedData, secretKey);

        if (decryptedData != null) {
            return new String(decryptedData);
        } else {
            System.out.println("greska");
        }
        return null;
    }

    private Key loadKeyFromKeystore(int num) {
        //System.out.println("load secret key from keystore");
        Key keyLoad = null;
        try{
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream("./keys/keystore.p12"), "sigurnost".toCharArray());
            keyLoad = keyStore.getKey(Integer.toString(num), "sigurnost".toCharArray());
            return keyLoad;
        } catch (Exception ex){
            ex.printStackTrace();
        }
        return null;

    }

    public BorderPane createMainMenuFormPane(String username) throws IOException {
        //BorderPane border = new BorderPane();
        HBox hbox = addHBox(username);
        border.setBottom(hbox);
        border.setLeft(addVBox(username));
        border.setCenter(addGridPane(num));
        num++;

        return border;
    }

    public HBox addHBox(String username) {
        HBox hbox = new HBox();
        hbox.setPadding(new Insets(15, 12, 15, 12));
        hbox.setSpacing(10);
        hbox.setStyle("-fx-background-color: #336699;");
        FileChooser fil_chooser = new FileChooser();
        // set title
        fil_chooser.setTitle("Select File");
        // set initial File
        fil_chooser.setInitialDirectory(new File(ROOT_FOLDER + separator + username));
        Button buttonOpen = new Button("Open");
        buttonOpen.setPrefSize(100, 20);
        EventHandler<ActionEvent> event =
                new EventHandler<ActionEvent>() {

                    public void handle(ActionEvent e)
                    {
                        fil_chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("*.png", "*.jpg"));
                        File selectedFile = fil_chooser.showOpenDialog(border.getScene().getWindow());
                    }
                };

        buttonShow.setPrefSize(100, 20);
        buttonShow.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                try {
                    border.setCenter(addGridPaneAllResults());
                } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
                    e.printStackTrace();
                }
                buttonShow.setVisible(false);
            }
        });
        buttonNext.setPrefSize(100, 20);
        buttonNext.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                if(num < 4) {
                    buttonNext.setVisible(false);
                    border.setCenter(addGridPane(num));
                    if(dodijeliBodove)
                        rezultat += 5;
                    num++;

                } else if(num == 4) {
                    if(dodijeliBodove)
                        rezultat += 5;
                    buttonNext.setVisible(false);
                    border.setCenter(addGridPaneLastQuestion(num));
                    num++;
                }else {
                    try {
                        border.setCenter(addGridPaneResult(rezultat, username));
                    } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | UnrecoverableKeyException e) {
                        e.printStackTrace();
                    }
                    buttonNext.setVisible(false);
                    buttonShow.setVisible(true);

                }
            }
        });

        buttonNext.setVisible(false);
        buttonShow.setVisible(false);
        hbox.getChildren().add(buttonNext);
        hbox.getChildren().add(buttonShow);
        return hbox;
    }

    public VBox addVBox(String username) throws IOException {

        VBox root = new VBox();
        Text user = new Text(username);
        user.setFont(Font.font("Arial", FontWeight.BOLD, 15));
        root.getChildren().add(user);
        root.setAlignment(Pos.TOP_CENTER);
        root.setSpacing(10);
        root.setPadding(new Insets(20));
        BackgroundFill backgroundFill = new BackgroundFill(Color.DEEPSKYBLUE, CornerRadii.EMPTY, Insets.EMPTY);
        Background background = new Background(backgroundFill);
        root.setBackground(background);

        return root;
    }

    public GridPane addGridPaneAllResults() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(0, 10, 0, 10));
        FileReader fr=new FileReader("./result/rezultati" + ".txt");
        BufferedReader br=new BufferedReader(fr);
        String line;
        Key loadKey = loadKeyFromKeystoreResults();
        TextArea textArea = new TextArea();
        while((line=br.readLine())!=null)
        {
            byte[] decryptedResult = decryptResults(line, loadKey);
            assert decryptedResult != null;
            textArea.appendText(new String(decryptedResult));
            textArea.appendText("\n");
        }
        fr.close();
        Label label = new Label("Ukupni rezultati");
        label.setFont(Font.font("Arial", FontWeight.BOLD, 30));
        grid.add(label, 1, 0);
        grid.add(textArea, 1, 1);

        return grid;
    }

    public GridPane addGridPaneResult(int rez, String username) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UnrecoverableKeyException {
        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(0, 10, 0, 10));

        Label label = new Label("Ukupan rezultat");
        label.setFont(Font.font("Arial", FontWeight.BOLD, 30));
        grid.add(label, 12, 0);
        String rezultat = Integer.toString(rez);
        Label label1 = new Label(rezultat);
        label1.setFont(Font.font("Arial", FontWeight.BOLD,100));
        grid.add(label1, 12, 6);

        PrintWriter outRezultati = new PrintWriter(new BufferedWriter(new FileWriter("./result/rezultati" + ".txt", true)));
        SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yy_hh_mm_ss");
        String time = sdf.format(new Date());
        String rezultatForm = String.format("%-25s %21s %10s", username, time, rezultat);
        //String rezultatForm = String.format("%-25s %-21s %10s", "KORISNICKO_IME", "VRIJEME", "REZULTAT");
        Key loadSecretKey = loadKeyFromKeystoreResults();

        byte[] encryptResult = encrypt(rezultatForm.getBytes(), loadSecretKey);
        String encryptResultEncode = Base64.getEncoder().encodeToString(encryptResult);
        outRezultati.append("\n").append(encryptResultEncode);
        outRezultati.close();

        return grid;
    }

    private Key loadKeyFromKeystoreResults() {
        //System.out.println("load secret key from keystore");
        Key keyLoad = null;
        try{
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream("./result/results.p12"), "sigurnost".toCharArray());
            keyLoad = keyStore.getKey("results", "sigurnost".toCharArray());
            return keyLoad;
        } catch (Exception ex){
            ex.printStackTrace();
        }
        return null;
    }

    private byte[] decryptResults(String toDecrypt, Key key) {
        try {
            Cipher deCipher = Cipher.getInstance("AES");
            deCipher.init(Cipher.DECRYPT_MODE, key);
            return deCipher.doFinal(Base64.getDecoder()
                    .decode(toDecrypt));
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            return null;
        }
    }

    public static void encryptFile(Key key, File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        inputStream.close();
        outputStream.close();
    }

    public static byte[] decryptFile(Key key, File inputFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        FileInputStream inputStream = new FileInputStream(inputFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        byte[] output = null;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                //outputStream.write(output);
                inputStream.close();
                return output;
            }
        }
        inputStream.close();
        return null;
    }

    public GridPane addGridPaneLastQuestion(int num) {
        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(0, 10, 0, 10));

        int number = num * 4;
        Random rand = new Random();
        int numberOfQuestion = rand.nextInt(number + 1, number + 5);
        //TilePane tilePane = new TilePane();
        Label label = new Label((num + 1) + "." + "Pitanje");
        label.setFont(Font.font("Arial", FontWeight.BOLD, 20));
        String[] odgovori = readQuestion(numberOfQuestion).split("#");
        Text question = new Text(odgovori[0]);

        TextField answerField = new TextField();
        answerField.setPrefHeight(40);

        grid.add(label, 1, 0);
        grid.add(question, 1, 1);
        grid.add(answerField, 1, 2);

        answerField.textProperty().addListener(new ChangeListener<String>() {
            @Override
            public void changed(ObservableValue<? extends String> observable, String oldValue, String newValue) {
                if(answerField.getText() != null) {
                    buttonNext.setVisible(true);
                    if(answerField.getText().compareToIgnoreCase(odgovori[1]) == 0) {
                        rezultat += 10;
                    }
                }
            }
        });
        return grid;
    }

    public GridPane addGridPane(int num) {
        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(0, 10, 0, 10));

        int number = num * 4;
        Random rand = new Random();
        int numberOfQuestion = rand.nextInt(number + 1, number + 5);
            Label label = new Label((num + 1) + "." + "Pitanje");
            label.setFont(Font.font("Arial", FontWeight.BOLD, 20));
            String[] odgovori = readQuestion(numberOfQuestion).split("#");
            Text question = new Text(odgovori[0]);
            String correctAnswer = odgovori[1];
            String[] offeredAnswers = {odgovori[1], odgovori[2], odgovori[3], odgovori[4]};
            List<String> list = Arrays.asList(offeredAnswers);
            Collections.shuffle(list);
            list.toArray(offeredAnswers);
            //System.out.println(Arrays.toString(offeredAnswers));

            ToggleGroup tg = new ToggleGroup();
            //create radio buttons
            RadioButton radioButton1 = new RadioButton(offeredAnswers[1]);
            RadioButton radioButton2 = new RadioButton(offeredAnswers[2]);
            RadioButton radioButton3 = new RadioButton(offeredAnswers[3]);
            RadioButton radioButton4 = new RadioButton(offeredAnswers[0]);
            //add radio buttons to toggle group
            radioButton1.setToggleGroup(tg);
            radioButton2.setToggleGroup(tg);
            radioButton3.setToggleGroup(tg);
            radioButton4.setToggleGroup(tg);

            radioButton1.setUserData(offeredAnswers[1]);
            radioButton2.setUserData(offeredAnswers[2]);
            radioButton3.setUserData(offeredAnswers[3]);
            radioButton4.setUserData(offeredAnswers[0]);

            grid.add(label, 1, 0);
            grid.add(question, 1, 1);
            grid.add(radioButton1, 1, 2);
            grid.add(radioButton2, 1, 3);
            grid.add(radioButton3, 1, 4);
            grid.add(radioButton4, 1, 5);

            tg.selectedToggleProperty().addListener(new ChangeListener<Toggle>() {
                @Override
                public void changed(ObservableValue<? extends Toggle> observable, Toggle oldValue, Toggle newValue) {
                    if(tg.getSelectedToggle() != null){
                        buttonNext.setVisible(true);
                        dodijeliBodove = tg.getSelectedToggle().getUserData().toString().equalsIgnoreCase(correctAnswer);

                    }
                }
            });
        return grid;
    }

    private void createTree(String username) throws IOException {
        // create root
        rootTreeItem = createTreeRoot(username);
        // create tree structure recursively
        createTree( rootTreeItem);
        // sort tree structure by name
        rootTreeItem.getChildren().sort( Comparator.comparing(new Function<TreeItem<FilePath>, String>() {
            @Override
            public String apply(TreeItem<FilePath> t) {
                return t.getValue().toString().toLowerCase();
            }
        }));
    }

    public static void createTree(TreeItem<FilePath> rootItem) throws IOException {

        try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(rootItem.getValue().getPath())) {

            for (Path path : directoryStream) {

                TreeItem<FilePath> newItem = new TreeItem<FilePath>( new FilePath( path));
                newItem.setExpanded(true);

                rootItem.getChildren().add(newItem);

                if (Files.isDirectory(path)) {
                    createTree(newItem);
                }
            }
        }
        catch( Exception ex) {
            ex.printStackTrace();
        }
    }

    private void filter(TreeItem<FilePath> root, String filter, TreeItem<FilePath> filteredRoot) {

        for (TreeItem<FilePath> child : root.getChildren()) {
            TreeItem<FilePath> filteredChild = new TreeItem<>( child.getValue());
            filteredChild.setExpanded(true);
            filter(child, filter, filteredChild );
            if (!filteredChild.getChildren().isEmpty() || isMatch(filteredChild.getValue(), filter)) {
                filteredRoot.getChildren().add(filteredChild);
            }
        }
    }

    private boolean isMatch(FilePath value, String filter) {
        return value.toString().toLowerCase().contains( filter.toLowerCase()); // TODO: optimize or change (check file extension, etc)
    }

    private void filterChanged(String filter, String username) {
        if (filter.isEmpty()) {
            treeView.setRoot(rootTreeItem);
        }
        else {
            TreeItem<FilePath> filteredRoot = createTreeRoot(username);
            filter(rootTreeItem, filter, filteredRoot);
            treeView.setRoot(filteredRoot);
        }
    }

    private TreeItem<FilePath> createTreeRoot(String username) {
        TreeItem<FilePath> root = new TreeItem<FilePath>( new FilePath( Paths.get( ROOT_FOLDER + separator + username)));
        root.setExpanded(true);
        return root;
    }

    private static class FilePath {
        Path path;
        String text;
        public FilePath( Path path) {
            this.path = path;

            if( path.getNameCount() == 0) {
                this.text = path.toString();
            }
            else {
                this.text = path.getName( path.getNameCount() - 1).toString();
            }
        }

        public Path getPath() {
            return path;
        }

        public String toString() {
            return text;
        }
    }

    private Image encode(Image original, String message) {
        int width = (int) original.getWidth();
        int height = (int) original.getHeight();

        WritableImage copy = new WritableImage(original.getPixelReader(), width, height);
        PixelWriter writer = copy.getPixelWriter();
        PixelReader reader = original.getPixelReader();

        byte[] data = message.getBytes();
        boolean[] bits = new boolean[32 + data.length * 8];

        String binary = Integer.toBinaryString(data.length);
        while (binary.length() < 32) {
            binary = "0" + binary;
        }
        for (int i = 0; i < 32; i++) {
            bits[i] = binary.charAt(i) == '1';
        }
        for (int i = 0; i < data.length; i++) {
            byte b = data[i];
            for (int j = 0; j < 8; j++) {
                bits[32 + i * 8 + j] = ((b >> (7 - j)) & 1) == 1;
            }
        }
        IntStream.range(0, bits.length)
                .mapToObj(i -> new Pair<>(i, reader.getArgb(i % width, i / width)))
                .map(pair -> new Pair<>(pair.getKey(), bits[pair.getKey()] ? pair.getValue() | 1 : pair.getValue() & ~1))
                .forEach(pair -> {
                    int x = pair.getKey() % width;
                    int y = pair.getKey() / width;

                    writer.setArgb(x, y, pair.getValue());
                });
        return copy;
    }

    private String decode(Image image) {
        int width = (int) image.getWidth();
        int height = (int) image.getHeight();

        PixelReader reader = image.getPixelReader();

        boolean[] bits = new boolean[width * height];

        IntStream.range(0, width * height)
                .mapToObj(i -> new Pair<>(i, reader.getArgb(i % width, i / width)))
                .forEach(pair -> {
                    String binary = Integer.toBinaryString(pair.getValue());
                    bits[pair.getKey()] = binary.charAt(binary.length() - 1) == '1';
                });
        int length = 0;
        for (int i = 0; i < 32; i++) {
            if (bits[i]) {
                length |= (1 << (31 - i));
            }
        }

        byte[] data = new byte[length];

        for (int i = 0; i < length; i++) {
            for (int j = 0; j < 8; j++) {
                if (bits[32 + i * 8 + j]) {
                    data[i] |= (1 << (7 - j));
                }
            }
        }

        return new String(data);
    }

    public static byte[] encrypt(byte[] toEncrypt, Key key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(toEncrypt);
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }

    private byte[] decrypt(byte[] toDecrypt, Key key) {
        try {
            Cipher deCipher = Cipher.getInstance("AES");
            deCipher.init(Cipher.DECRYPT_MODE, key);
            return deCipher.doFinal(toDecrypt);
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            return null;
        }
    }

    private SecretKey generateSecretKey(String toUser, String saveTo) {
        SecureRandom sr = new SecureRandom();
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256, sr);
            SecretKey secretKey = kg.generateKey();

            PublicKey pubKey = LoginFormController.loadPublicKey(toUser);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] encryptedKey = cipher.doFinal(secretKey.getEncoded());

            try (FileOutputStream fos = new FileOutputStream(saveTo)) {
                fos.write(encryptedKey);
            } catch (IOException e) {
                e.printStackTrace();
            }

            return secretKey;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static KeyStore createKeyStore(String username) {
        try{
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream("./users/" + username + "/" + username + "aeskey.p12"), "sigurnost".toCharArray());
            return keyStore;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Key createKey(String username) throws NoSuchAlgorithmException, KeyStoreException {
        KeyStore keyStore = createKeyStore(username);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        Key key = keyGenerator.generateKey();
        assert keyStore != null;
        keyStore.setKeyEntry("username", key, "sigurnost".toCharArray(), null);
        return key;
    }

    public Key loadKey(String username) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("./users/" + username + "/" + username + "aeskey.p12"), "sigurnost".toCharArray());
        Key keyLoad = keyStore.getKey(username, "sigurnost".toCharArray());
        return keyLoad;
    }

}
