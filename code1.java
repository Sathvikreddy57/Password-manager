import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class PasswordManagerApp extends JFrame {
    private JTextField websiteField;
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JTextArea outputArea;
    private Map<String, String> passwordDatabase;
    private SecretKey secretKey;

    private final String FILE_NAME = "passwords.txt";

    public PasswordManagerApp() {
        passwordDatabase = new HashMap<>();

        setTitle("Password Manager");
        setSize(500, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        // Prompt user for encryption key
        String key = JOptionPane.showInputDialog(this, "Enter a key for encryption/decryption:", "Security Key", JOptionPane.PLAIN_MESSAGE);
        if (key != null && !key.trim().isEmpty()) {
            secretKey = generateKey(key);
            loadPasswords(); // Load existing passwords from file
        } else {
            JOptionPane.showMessageDialog(this, "A key is required to proceed.", "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }

        // Set up layout
        setLayout(new BorderLayout());

        // Create a panel for buttons
        JPanel buttonPanel = new JPanel(new GridLayout(1, 4, 10, 10));
        JButton saveButton = new JButton("Save Password");
        JButton retrieveButton = new JButton("Retrieve Password");
        JButton deleteButton = new JButton("Delete Password");
        JButton generateButton = new JButton("Generate Password");

        buttonPanel.add(saveButton);
        buttonPanel.add(retrieveButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(generateButton);

        add(buttonPanel, BorderLayout.NORTH);

        // Create input panel
        JPanel inputPanel = new JPanel(new GridLayout(4, 2, 10, 10));
        inputPanel.add(new JLabel("Website:"));
        websiteField = new JTextField();
        inputPanel.add(websiteField);

        inputPanel.add(new JLabel("Username:"));
        usernameField = new JTextField();
        inputPanel.add(usernameField);

        inputPanel.add(new JLabel("Password:"));
        passwordField = new JPasswordField();
        inputPanel.add(passwordField);

        add(inputPanel, BorderLayout.CENTER);

        // Create output area
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        add(new JScrollPane(outputArea), BorderLayout.SOUTH);

        // Add button listeners
        saveButton.addActionListener(new SaveButtonListener());
        retrieveButton.addActionListener(new RetrieveButtonListener());
        deleteButton.addActionListener(new DeleteButtonListener());
        generateButton.addActionListener(new GenerateButtonListener());
    }

    // Listener for saving a password
    private class SaveButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String website = websiteField.getText().trim();
            String username = usernameField.getText().trim();
            String password = new String(passwordField.getPassword()).trim();

            if (!website.isEmpty() && !username.isEmpty() && !password.isEmpty()) {
                String key = website + ":" + username;
                try {
                    String encryptedPassword = encrypt(password, secretKey);
                    passwordDatabase.put(key, encryptedPassword);
                    savePasswords(); // Save to file
                    outputArea.setText("Password saved for " + website);
                } catch (Exception ex) {
                    outputArea.setText("Error encrypting the password.");
                    ex.printStackTrace(); // Print the stack trace for debugging
                }
            } else {
                outputArea.setText("Please fill in all fields.");
            }
        }
    }

    // Listener for retrieving a password
    private class RetrieveButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String website = websiteField.getText().trim();
            String username = usernameField.getText().trim();

            if (!website.isEmpty() && !username.isEmpty()) {
                String key = website + ":" + username;
                String encryptedPassword = passwordDatabase.get(key);

                if (encryptedPassword != null) {
                    try {
                        String decryptedPassword = decrypt(encryptedPassword, secretKey);
                        outputArea.setText("Password for " + website + " is: " + decryptedPassword);
                    } catch (Exception ex) {
                        outputArea.setText("Error decrypting the password.");
                        ex.printStackTrace(); // Print the stack trace for debugging
                    }
                } else {
                    outputArea.setText("No password found for " + website);
                }
            } else {
                outputArea.setText("Please enter both website and username.");
            }
        }
    }

    // Listener for deleting a password
    private class DeleteButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String website = websiteField.getText().trim();
            String username = usernameField.getText().trim();

            if (!website.isEmpty() && !username.isEmpty()) {
                String key = website + ":" + username;
                if (passwordDatabase.remove(key) != null) {
                    savePasswords(); // Update file
                    outputArea.setText("Password deleted for " + website);
                } else {
                    outputArea.setText("No password found to delete.");
                }
            } else {
                outputArea.setText("Please enter both website and username.");
            }
        }
    }

    // Listener for generating a random password
    private class GenerateButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String generatedPassword = generatePassword(8);
            passwordField.setText(generatedPassword);
            outputArea.setText("Generated Password: " + generatedPassword);
        }
    }

    // Save passwords to a file
    private void savePasswords() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(FILE_NAME))) {
            for (Map.Entry<String, String> entry : passwordDatabase.entrySet()) {
                writer.write(entry.getKey() + "=" + entry.getValue());
                writer.newLine();
            }
        } catch (IOException e) {
            outputArea.setText("Error saving passwords.");
            e.printStackTrace(); // Print the stack trace for debugging
        }
    }

    // Load passwords from a file
    private void loadPasswords() {
        try (BufferedReader reader = new BufferedReader(new FileReader(FILE_NAME))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("=");
                if (parts.length == 2) {
                    passwordDatabase.put(parts[0], parts[1]);
                }
            }
        } catch (IOException e) {
            outputArea.setText("No existing passwords found.");
            e.printStackTrace(); // Print the stack trace for debugging
        }
    }

    // Generate a random alphanumeric password
    private String generatePassword(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            password.append(chars.charAt(random.nextInt(chars.length())));
        }

        return password.toString();
    }

    // Generate SecretKey from user input (AES-128 bit key length)
    private SecretKey generateKey(String key) {
        byte[] keyBytes = key.getBytes();
        byte[] paddedKeyBytes = new byte[16]; // AES-128 bit key length
        System.arraycopy(keyBytes, 0, paddedKeyBytes, 0, Math.min(keyBytes.length, paddedKeyBytes.length));
        return new SecretKeySpec(paddedKeyBytes, "AES");
    }

    // Encrypt password using AES
    private String encrypt(String data, SecretKey key) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedBytes = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace(); // Print the stack trace for debugging
            throw new Exception("Encryption error: " + e.getMessage()); // Throw a more detailed exception
        }
    }

    // Decrypt password using AES
    private String decrypt(String encryptedData, SecretKey key) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace(); // Print the stack trace for debugging
            throw new Exception("Decryption error: " + e.getMessage()); // Throw a more detailed exception
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            PasswordManagerApp app = new PasswordManagerApp();
            app.setVisible(true);
        });
    }
}
