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
    // GUI components
    private JTextField websiteField;
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JTextArea outputArea;

    // Data structure to store passwords
    private Map<String, String> passwordDatabase;

    // Secret key for encryption/decryption
    private SecretKey secretKey;

    // File name to save/load passwords
    private final String FILE_NAME = "passwords.txt";

    // Constructor to set up the GUI and initialize the app
    public PasswordManagerApp() {
        passwordDatabase = new HashMap<>(); // Initialize the password database

        // Set up the main window
        setTitle("Password Manager");
        setSize(500, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        // Prompt user for the encryption key at the start
        String key = JOptionPane.showInputDialog(this, "Enter a key for encryption/decryption:", "Security Key", JOptionPane.PLAIN_MESSAGE);
        if (key != null && !key.trim().isEmpty()) {
            secretKey = generateKey(key); // Generate the secret key based on user input
            loadPasswords(); // Load existing passwords from the file
        } else {
            JOptionPane.showMessageDialog(this, "A key is required to proceed.", "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(0); // Exit if no key is provided
        }

        // Set up the layout of the main window
        setLayout(new BorderLayout());

        // Create a panel for buttons at the top
        JPanel buttonPanel = new JPanel(new GridLayout(1, 4, 10, 10));
        JButton saveButton = new JButton("Save Password");
        JButton retrieveButton = new JButton("Retrieve Password");
        JButton deleteButton = new JButton("Delete Password");
        JButton generateButton = new JButton("Generate Password");

        // Add buttons to the panel
        buttonPanel.add(saveButton);
        buttonPanel.add(retrieveButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(generateButton);

        // Add the button panel to the top of the main window
        add(buttonPanel, BorderLayout.NORTH);

        // Create a panel for input fields (website, username, password)
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

        // Add the input panel to the center of the main window
        add(inputPanel, BorderLayout.CENTER);

        // Create a text area for displaying output/messages
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        add(new JScrollPane(outputArea), BorderLayout.SOUTH);

        // Attach listeners to buttons
        saveButton.addActionListener(new SaveButtonListener());
        retrieveButton.addActionListener(new RetrieveButtonListener());
        deleteButton.addActionListener(new DeleteButtonListener());
        generateButton.addActionListener(new GenerateButtonListener());
    }

    // Listener for saving a password
    private class SaveButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            // Get input values
            String website = websiteField.getText().trim();
            String username = usernameField.getText().trim();
            String password = new String(passwordField.getPassword()).trim();

            // Check if all fields are filled
            if (!website.isEmpty() && !username.isEmpty() && !password.isEmpty()) {
                String key = website + ":" + username;
                try {
                    // Encrypt the password
                    String encryptedPassword = encrypt(password, secretKey);
                    // Store the encrypted password in the database
                    passwordDatabase.put(key, encryptedPassword);
                    // Save the updated database to the file
                    savePasswords();
                    // Show success message
                    outputArea.setText("Password saved for " + website);
                } catch (Exception ex) {
                    // Handle encryption errors
                    outputArea.setText("Error encrypting the password.");
                    ex.printStackTrace(); // Print the stack trace for debugging
                }
            } else {
                // Show error message if fields are empty
                outputArea.setText("Please fill in all fields.");
            }
        }
    }

    // Listener for retrieving a password
    private class RetrieveButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            // Get input values
            String website = websiteField.getText().trim();
            String username = usernameField.getText().trim();

            // Check if website and username are provided
            if (website.isEmpty() || username.isEmpty()) {
                outputArea.setText("Please enter both website and username.");
                return;
            }

            // Construct the key for retrieving the password
            String key = website + ":" + username;
            String encryptedPassword = passwordDatabase.get(key);

            // Check if password is found in the database
            if (encryptedPassword == null) {
                // Handle case where password is not found
                if (isKeyCorrect()) { // Assume a method to check if the key is correct
                    outputArea.setText("No password found for " + website);
                } else {
                    outputArea.setText("Wrong key entered, cannot retrieve.");
                }
            } else {
                try {
                    // Decrypt the password
                    String decryptedPassword = decrypt(encryptedPassword, secretKey);
                    // Show the retrieved password
                    outputArea.setText("Password for " + website + " is: " + decryptedPassword);
                } catch (Exception ex) {
                    // Handle decryption errors
                    outputArea.setText("Error decrypting the password.");
                    ex.printStackTrace(); // Print the stack trace for debugging
                }
            }
        }

        // This method needs to be implemented based on how you determine the key validity
        private boolean isKeyCorrect() {
            // Logic to check if the current key is correct
            // For example, you might have a method to verify key correctness
            return true; // Placeholder return value
        }
    }

    // Listener for deleting a password
    private class DeleteButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            // Get input values
            String website = websiteField.getText().trim();
            String username = usernameField.getText().trim();

            // Check if website and username are provided
            if (website.isEmpty() || username.isEmpty()) {
                outputArea.setText("Please enter both website and username.");
                return;
            }

            // Construct the key for deleting the password
            String key = website + ":" + username;
            String encryptedPassword = passwordDatabase.get(key);

            // Check if the password is found in the database
            if (encryptedPassword == null) {
                outputArea.setText("No password found to delete.");
                return;
            }

            try {
                // Attempt to decrypt the password to verify the key
                decrypt(encryptedPassword, secretKey);

                // If decryption is successful, proceed with deletion
                passwordDatabase.remove(key);
                savePasswords(); // Update the file
                outputArea.setText("Password deleted for " + website);
                
            } catch (Exception ex) {
                // If decryption fails, the key is wrong
                outputArea.setText("Wrong key entered, cannot delete.");
                // Optionally, you can log the exception for debugging
                // ex.printStackTrace();
            }
        }
    }

    // Listener for generating a random password
    private class GenerateButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            // Generate a random password with a length of 8 characters
            String generatedPassword = generatePassword(8);
            // Set the generated password in the password field
            passwordField.setText(generatedPassword);
            // Display the generated password in the output area
            outputArea.setText("Generated Password: " + generatedPassword);
        }
    }

    // Save passwords to a file
    private void savePasswords() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(FILE_NAME))) {
            // Write each key-value pair (website:username=password) to the file
            for (Map.Entry<String, String> entry : passwordDatabase.entrySet()) {
                writer.write(entry.getKey() + "=" + entry.getValue());
                writer.newLine();
            }
        } catch (IOException e) {
            // Handle file I/O errors
            outputArea.setText("Error saving passwords.");
            e.printStackTrace(); // Print the stack trace for debugging
        }
    }

    // Load passwords from a file
    private void loadPasswords() {
        try (BufferedReader reader = new BufferedReader(new FileReader(FILE_NAME))) {
            String line;
            // Read each line from the file
            while ((line = reader.readLine()) != null) {
                // Split the line into key and value (website:username=password)
                String[] parts = line.split("=");
                if (parts.length == 2) {
                    // Store the key-value pair in the password database
                    passwordDatabase.put(parts[0], parts[1]);
                }
            }
        } catch (IOException e) {
            // Handle case where no existing passwords are found
            outputArea.setText("No existing passwords found.");
            e.printStackTrace(); // Print the stack trace for debugging
        }
    }

    // Generate a random alphanumeric password
    private String generatePassword(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder(length);

        // Generate a random password of the specified length
        for (int i = 0; i < length; i++) {
            password.append(chars.charAt(random.nextInt(chars.length())));
        }

        return password.toString(); // Return the generated password
    }

    // Generate SecretKey from user input (AES-128 bit key length)
    private SecretKey generateKey(String key) {
        byte[] keyBytes = key.getBytes(); // Convert the input key to bytes
        byte[] paddedKeyBytes = new byte[16]; // AES-128 bit key length (16 bytes)
        System.arraycopy(keyBytes, 0, paddedKeyBytes, 0, Math.min(keyBytes.length, paddedKeyBytes.length));
        return new SecretKeySpec(paddedKeyBytes, "AES"); // Return the generated SecretKey
    }

    // Encrypt password using AES
    private String encrypt(String data, SecretKey key) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("AES"); // Create a Cipher instance for AES
            cipher.init(Cipher.ENCRYPT_MODE, key); // Initialize the cipher for encryption
            byte[] encryptedBytes = cipher.doFinal(data.getBytes()); // Encrypt the data
            return Base64.getEncoder().encodeToString(encryptedBytes); // Encode and return the encrypted data as a string
        } catch (Exception e) {
            e.printStackTrace(); // Print the stack trace for debugging
            throw new Exception("Encryption error: " + e.getMessage()); // Throw a more detailed exception
        }
    }

    // Decrypt password using AES
    private String decrypt(String encryptedData, SecretKey key) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("AES"); // Create a Cipher instance for AES
            cipher.init(Cipher.DECRYPT_MODE, key); // Initialize the cipher for decryption
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedData); // Decode the encrypted data
            byte[] decryptedBytes = cipher.doFinal(decodedBytes); // Decrypt the data
            return new String(decryptedBytes); // Return the decrypted data as a string
        } catch (Exception e) {
            e.printStackTrace(); // Print the stack trace for debugging
            throw new Exception("Decryption error: " + e.getMessage()); // Throw a more detailed exception
        }
    }

    // Main method to run the application
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            PasswordManagerApp app = new PasswordManagerApp(); // Create an instance of the PasswordManagerApp
            app.setVisible(true); // Make the application window visible
        });
    }
}
