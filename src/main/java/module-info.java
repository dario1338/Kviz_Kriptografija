module com.example.krz22projektniz {
    requires javafx.controls;
    requires javafx.fxml;
    requires org.bouncycastle.provider;
    //requires bcprov.jdk15on;
    requires javafx.swing;
    requires org.bouncycastle.pkix;
    requires java.desktop;
    requires org.jetbrains.annotations;


    opens com.example.krz22projektniz to javafx.fxml;
    exports com.example.krz22projektniz;
}