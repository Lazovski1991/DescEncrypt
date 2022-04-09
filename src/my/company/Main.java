package my.company;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) {
        JTextField field1 = new JTextField();
        JTextField field2 = new JTextField();
        JTextField field3 = new JTextField();

        JPanel panel = new JPanel(new GridLayout(0, 1));
        panel.add(new JLabel("Текст:"));
        panel.add(field1);
        panel.add(new JLabel("Тип:"));
        panel.add(field2);
        panel.add(new JLabel("Ключ"));
        panel.add(field3);
        Object[] options1 = {"Зашифровать ", "Расшифровать", "Выйти"};

        int result = JOptionPane.showOptionDialog(null, panel, "Test", JOptionPane.YES_NO_CANCEL_OPTION,
                JOptionPane.OK_CANCEL_OPTION, null, options1, options1[0]);

        show(result, field1, field2, field3);
    }

    public static void show(int result, JTextField field1, JTextField field2, JTextField field3) {
        Object[] options = {"Спасибо)"};
        if (result == JOptionPane.OK_OPTION) {
            try {
                JOptionPane.showOptionDialog(null, encrypt(field1.getText(), field3.getText(), field2.getText()), "Результат", JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.OK_CANCEL_OPTION, null, options, options[0]);
            } catch (Exception e) {
                JOptionPane.showConfirmDialog(null, "Сорри, я устал(" + e.getMessage(), "Упал", JOptionPane.OK_CANCEL_OPTION);
            }

        } else if (result == JOptionPane.NO_OPTION) {
            try {
                JOptionPane.showOptionDialog(null, decrypt(field1.getText(), field3.getText(), field2.getText()), "Результат", JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.OK_CANCEL_OPTION, null, options, options[0]);
            } catch (Exception e) {
                JOptionPane.showConfirmDialog(null, "Сорри, я устал(" + e.getMessage(), "Упал", JOptionPane.OK_CANCEL_OPTION);
            }
        } else {

        }
    }

    public static String encrypt(String text, String secretKey, String cipherTransformation) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(cipherTransformation);
        byte[] iv = new byte[cipher.getBlockSize()];
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));
        byte[] decryptedBytes = text.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = cipher.doFinal(decryptedBytes);
        return Base64.encodeBase64URLSafeString(encryptedBytes);
    }

    public static String decrypt(String text, String secretKey, String cipherTransformation) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(cipherTransformation);
        byte[] iv = new byte[cipher.getBlockSize()];
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));
        byte[] encryptedBytes = Base64.decodeBase64(text);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
