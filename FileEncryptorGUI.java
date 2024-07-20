import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

public class FileEncryptorGUI extends JFrame {
    private JTextField filePathField, passwordField;
    private JButton encryptButton, decryptButton;

    public FileEncryptorGUI() {
        setTitle("File Security Tool");
        setSize(400, 200);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JPanel panel = new JPanel();
        add(panel);
        placeComponents(panel);

        setVisible(true);
    }

    private void placeComponents(JPanel panel) {
        panel.setLayout(null);

        JLabel fileLabel = new JLabel("Select File:");
        fileLabel.setBounds(10, 20, 80, 25);
        panel.add(fileLabel);

        filePathField = new JTextField(20);
        filePathField.setBounds(100, 20, 200, 25);
        panel.add(filePathField);

        JButton chooseFileButton = new JButton("Choose File");
        chooseFileButton.setBounds(310, 20, 150, 25);
        chooseFileButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                chooseFile();
            }
        });
        panel.add(chooseFileButton);

        JLabel passwordLabel = new JLabel("Password:");
        passwordLabel.setBounds(10, 50, 80, 25);
        panel.add(passwordLabel);

        passwordField = new JPasswordField(20);
        passwordField.setBounds(100, 50, 200, 25);
        panel.add(passwordField);

        encryptButton = new JButton("Encrypt File");
        encryptButton.setBounds(10, 80, 150, 25);
        encryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                encrypt();
            }
        });
        panel.add(encryptButton);

        decryptButton = new JButton("Decrypt File");
        decryptButton.setBounds(170, 80, 150, 25);
        decryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                decrypt();
            }
        });
        panel.add(decryptButton);
    }

    private void chooseFile() {
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            filePathField.setText(selectedFile.getAbsolutePath());
        }
    }

    private void encrypt() {
        String filePath = filePathField.getText();
        String password = passwordField.getText();

        try {
            byte[] fileBytes = readFile(filePath);
            byte[] encryptedBytes = encryptFile(fileBytes, password);
            saveToFile(filePath, encryptedBytes);

            JOptionPane.showMessageDialog(this, "File successfully encrypted");
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Error encrypting the file");
        }
    }

    private void decrypt() {
        String filePath = filePathField.getText();
        String password = passwordField.getText();

        try {
            byte[] encryptedBytes = readFile(filePath);
            byte[] decryptedBytes = decryptFile(encryptedBytes, password);
            saveToFile(filePath, decryptedBytes);

            JOptionPane.showMessageDialog(this, "File successfully decrypted");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Wrong password or error decrypting the file");
        }
    }

    private byte[] readFile(String filePath) throws IOException {
        FileInputStream fis = new FileInputStream(filePath);
        byte[] fileBytes = new byte[(int) new File(filePath).length()];
        fis.read(fileBytes);
        fis.close();
        return fileBytes;
    }

    private void saveToFile(String filePath, byte[] data) throws IOException {
        FileOutputStream fos = new FileOutputStream(filePath);
        fos.write(data);
        fos.close();
    }

    private byte[] encryptFile(byte[] input, String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        Key key = deriveKey(password);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input);
    }

    private byte[] decryptFile(byte[] input, String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        Key key = deriveKey(password);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(input);
    }

    private Key deriveKey(String password) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), password.getBytes(), 65536, 256);
        SecretKey secretKey = factory.generateSecret(spec);
        return new SecretKeySpec(secretKey.getEncoded(), "AES");
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new FileEncryptorGUI();
            }
        });
    }
}