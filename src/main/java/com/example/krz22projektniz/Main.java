package com.example.krz22projektniz;

import com.example.krz22projektniz.controller.LoginFormController;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.layout.GridPane;
import javafx.stage.Stage;

public class Main extends Application {

    private final LoginFormController loginFormController = new LoginFormController();

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Login Form JavaFX Application");
        // Create the registration form grid pane
        GridPane gridPane = loginFormController.createLoginFormPane();
        // Add UI controls to the registration form grid pane
        loginFormController.addUIControls(gridPane);
        // Create a scene with registration form grid pane as the root node
        Scene scene = new Scene(gridPane, 800, 500);
        // Set the scene in primary stage
        primaryStage.setScene(scene);

        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}

