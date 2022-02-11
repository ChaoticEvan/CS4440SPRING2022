
import java.awt.*;
import java.io.*;
import java.util.Random;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;


public class CryptUtil {

    private static int NUMCUPS = 32;
    private static int SUGARVALUE = 0x9E3779B9;
    private static int UNSUGARVALUE = 0xC6EF3720;


    public static byte[] createSha1(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        InputStream fis = new FileInputStream(file);
        int n = 0;
        byte[] buffer = new byte[8192];
        while (n != -1) {
            n = fis.read(buffer);
            if (n > 0) {
                digest.update(buffer, 0, n);
            }
        }
        fis.close();
        return digest.digest();
    }

    public static boolean compareSha1(String filename1, String filename2) throws Exception {
        File file1 = new File(filename1);
        File file2 = new File(filename2);
        byte[] fsha1 = CryptUtil.createSha1(file1);
        byte[] fsha2 = CryptUtil.createSha1(file2);
        return Arrays.equals(fsha1, fsha2);
    }

    public static double getShannonEntropy(String s) {
        int n = 0;
        Map<Character, Integer> occ = new HashMap<>();

        for (int c_ = 0; c_ < s.length(); ++c_) {
            char cx = s.charAt(c_);
            if (occ.containsKey(cx)) {
                occ.put(cx, occ.get(cx) + 1);
            } else {
                occ.put(cx, 1);
            }
            ++n;
        }

        double e = 0.0;
        for (Map.Entry<Character, Integer> entry : occ.entrySet()) {
            char cx = entry.getKey();
            double p = (double) entry.getValue() / n;
            e += p * log2(p);
        }
        return -e;
    }

    public static double getShannonEntropy(byte[] data) {

        if (data == null || data.length == 0) {
            return 0.0;
        }

        int n = 0;
        Map<Byte, Integer> occ = new HashMap<>();

        for (int c_ = 0; c_ < data.length; ++c_) {
            byte cx = data[c_];
            if (occ.containsKey(cx)) {
                occ.put(cx, occ.get(cx) + 1);
            } else {
                occ.put(cx, 1);
            }
            ++n;
        }

        double e = 0.0;
        for (Map.Entry<Byte, Integer> entry : occ.entrySet()) {
            byte cx = entry.getKey();
            double p = (double) entry.getValue() / n;
            e += p * log2(p);
        }
        return -e;
    }

    public static double getFileShannonEntropy(String filePath) {
        try {
            byte[] content;
            content = Files.readAllBytes(Paths.get(filePath));
            return CryptUtil.getShannonEntropy(content);
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }

    }

    private static double log2(double a) {
        return Math.log(a) / Math.log(2);
    }

    public static void doCopy(InputStream is, OutputStream os) throws IOException {
        byte[] bytes = new byte[64];
        int numBytes;
        while ((numBytes = is.read(bytes)) != -1) {
            os.write(bytes, 0, numBytes);
        }
        os.flush();
        os.close();
        is.close();
    }

    public static Byte randomKey() {
        int leftLimit = 48; // numeral '0'
        int rightLimit = 122; // letter 'z'
        int targetStringLength = 8;
        Random random = new Random();
        String generatedString = random.ints(leftLimit, rightLimit + 1)
                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
        return generatedString.getBytes()[0];
    }

    /**
     * Encryption (Bytes)
     *
     * @param data
     * @param key
     * @return encrypted bytes
     */
    public static byte[] cs4440Encrypt(byte[] data, Byte key) {
        int[] fullKey = prepareKey(key);
        int paddingSize = ((data.length / 8) + (((data.length % 8) == 0) ? 0 : 1)) * 2;
        int[] result = new int[paddingSize + 1];
        result[0] = data.length;
        setup(data, result, 1);
        brew(result, fullKey);
        return unsetup(result, 0, result.length * 4);
    }

    /**
     * Helper method to convert 1 byte key into 16 byte key for ease of translation of TEA
     *
     * @param key key to convert to 16 byte key
     * @return array containing full key
     */
    private static int[] prepareKey(Byte key) {
        int[] fullKey = new int[16];
        int[] result = new int[4];
        Arrays.fill(fullKey, key);
        int offset = 0;
        for (int i = 0; i < 4; ++i) {
            result[i] = ((fullKey[offset] & 0xff)) |
                    ((fullKey[offset + 1] & 0xff) << 8) |
                    ((fullKey[offset + 2] & 0xff) << 16) |
                    ((fullKey[offset + 3] & 0xff) << 24);
            offset += 4;
        }
        return result;
    }

    /**
     * Helper method to setup encryption process
     * @param data data to encrypt
     * @param result array to hold resulting array
     * @param dataOffset offset index
     */
    private static void setup(byte[] data, int[] result, int dataOffset) {
        int shiftNum = 24;
        int i = 0;
        int j = dataOffset;
        result[j] = 0;
        while (i < data.length) {
            result[j] |= ((data[i] & 0xff) << shiftNum);
            if (shiftNum == 0) {
                shiftNum = 24;
                j++;
                if (j < result.length) {
                    result[j] = 0;
                }
            } else {
                shiftNum -= 8;
            }
            i++;
        }
    }

    /**
     * Helper method to reverse the setup process
     * @param data data array to edit
     * @param offset offset index
     * @param length length of resulting array
     * @return returns unsetup byte[]
     */
    private static byte[] unsetup(int[] data, int offset, int length) {
        byte[] result = new byte[length];
        int i = offset;
        int count = 0;
        for (int j = 0; j < result.length; j++) {
            result[j] = (byte) ((data[i] >> (24 - (8 * count))) & 0xff);
            count++;
            if (count == 4) {
                count = 0;
                i++;
            }
        }
        return result;
    }

    /**
     * Helper method to encrypt plaintext
     * @param result plaintext to encrypt
     * @param key to use in encryption process
     */
    private static void brew(int[] result, int[] key) {
        int numCups, temp0, temp1, sum;
        for (int i = 1; i < result.length; i += 2) {
            numCups = NUMCUPS;
            temp0 = result[i];
            temp1 = result[i + 1];
            sum = 0;
            for (; numCups > 0; --numCups) {
                sum += SUGARVALUE;
                temp0 += ((temp1 << 4) + key[0] ^ temp1) + (sum ^ (temp1 >>> 5)) + key[1];
                temp1 += ((temp0 << 4) + key[2] ^ temp0) + (sum ^ (temp0 >>> 5)) + key[3];
            }
            result[i] = temp0;
            result[i + 1] = temp1;
        }
    }

    /**
     * Helper method used to decrypt the cipher text
     * @param result ciphertext to decrypt
     * @param key key to decrypt
     */
    private static void unbrew(int[] result, int[] key) {

        int numCups, temp0, temp1, sum;
        for (int i = 1; i < result.length; i += 2) {
            numCups = NUMCUPS;
            temp0 = result[i];
            temp1 = result[i + 1];
            sum = UNSUGARVALUE;
            for (; numCups > 0; --numCups) {
                temp1 -= ((temp0 << 4) + key[2] ^ temp0) + (sum ^ (temp0 >>> 5)) + key[3];
                temp0 -= ((temp1 << 4) + key[0] ^ temp1) + (sum ^ (temp1 >>> 5)) + key[1];
                sum -= SUGARVALUE;
            }
            result[i] = temp0;
            result[i + 1] = temp1;
        }
    }

    /**
     * Encryption (file)
     *
     * @param plainfilepath
     * @param cipherfilepath
     * @param key
     */
    public static int encryptDoc(String plainfilepath, String cipherfilepath, Byte key) {
        try {
            // Init file
            File file = new File(plainfilepath);
            byte[] content = Files.readAllBytes(file.toPath());

            // Pad array if needed
            if(content.length < 8) {
                content = padding(content);
            }

            // Cipher block chaining
            File outputFile = new File(cipherfilepath);
            byte[] outputContent = cs4440Encrypt(content, key);
            try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
                outputStream.write(outputContent);
            }
            return 0;

        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Helper method to pad out byte[] via PKCS5
     * @param content byte array to pad
     * @return returns padded byte array
     */
    private static byte[] padding(byte[] content) {
        int diff = 8 - content.length;
        byte[] result = new byte[8];
        switch (diff) {
            case 1:
                result[0] = content[0];
                result[1] = content[1];
                result[2] = content[2];
                result[3] = content[3];
                result[4] = content[4];
                result[5] = content[5];
                result[6] = content[6];
                result[7] = 0x01;
                return result;
            case 2:
                result[0] = content[0];
                result[1] = content[1];
                result[2] = content[2];
                result[3] = content[3];
                result[4] = content[4];
                result[5] = content[5];
                result[6] = 0x02;
                result[7] = 0x02;
                return result;
            case 3:
                result[0] = content[0];
                result[1] = content[1];
                result[2] = content[2];
                result[3] = content[3];
                result[4] = content[4];
                result[5] = 0x03;
                result[6] = 0x03;
                result[7] = 0x03;
                return result;
            case 4:
                result[0] = content[0];
                result[1] = content[1];
                result[2] = content[2];
                result[3] = content[3];
                result[4] = 0x04;
                result[5] = 0x04;
                result[6] = 0x04;
                result[7] = 0x04;
                return result;
            case 5:
                result[0] = content[0];
                result[1] = content[1];
                result[2] = content[2];
                result[3] = 0x05;
                result[4] = 0x05;
                result[5] = 0x05;
                result[6] = 0x05;
                result[7] = 0x05;
                return result;
            case 6:
                result[0] = content[0];
                result[1] = content[1];
                result[2] = 0x06;
                result[3] = 0x06;
                result[4] = 0x06;
                result[5] = 0x06;
                result[6] = 0x06;
                result[7] = 0x06;
                return result;
            case 7:
                result[0] = content[0];
                result[1] = 0x07;
                result[2] = 0x07;
                result[3] = 0x07;
                result[4] = 0x07;
                result[5] = 0x07;
                result[6] = 0x07;
                result[7] = 0x07;
                return result;
        }
        // We only get here if diff is 8, meaning that content is empty
        return content;
    }

    /**
     * decryption
     *
     * @param data
     * @param key
     * @return decrypted content
     */

    public static byte[] cs4440Decrypt(byte[] data, Byte key) {
        int[] fullKey = prepareKey(key);
        int[] result = new int[data.length / 4];
        setup(data, result, 0);
        unbrew(result, fullKey);
        return unsetup(result, 1, result[0]);
    }

    /**
     * Decryption (file)
     *
     * @param plainfilepath
     * @param cipherfilepath
     * @param key
     */
    public static int decryptDoc(String cipherfilepath, String plainfilepath, Byte key) {
        try {
            File file = new File(cipherfilepath);
            byte[] cipher = Files.readAllBytes(file.toPath());

            File outputFile = new File(plainfilepath);
            byte[] outputContent = cs4440Decrypt(cipher, key);
            try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
                outputStream.write(outputContent);
            }

            return 0;
        }
        catch (Exception e) {
            return -1;
        }
    }

    public static void main(String[] args) {

        String targetFilepath = "";
        String encFilepath = "";
        String decFilepath = "";
        if (args.length == 3) {
            try {
                File file1 = new File(args[0].toString());
                if (file1.exists() && !file1.isDirectory()) {
                    targetFilepath = args[0].toString();
                } else {
                    System.out.println("File does not exist!");
                    System.exit(1);
                }

                encFilepath = args[1].toString();
                decFilepath = args[2].toString();
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(1);
            }
        } else {
            // targetFilepath = "cs4440-a1-testcase1.html";
            System.out.println("Usage: java CryptoUtil file_to_be_encrypted encrypted_file decrypted_file");
            System.exit(1);
        }

        Byte key = randomKey();
        String src = "ABCDEFGH";
        System.out.println("[*] Now testing plain sample： " + src);
        try {
            byte[] encrypted = CryptUtil.cs4440Encrypt(src.getBytes(), key);
            StringBuilder encsb = new StringBuilder();
            for (byte b : encrypted) {
                encsb.append(String.format("%02X ", b));
            }
            System.out.println("[*] The  encrypted sample  [Byte Format]： " + encsb);
            double entropyStr = CryptUtil.getShannonEntropy(encrypted.toString());
            System.out.printf("[*] Shannon entropy of the text sample (to String): %.12f%n", entropyStr);
            double entropyBytes = CryptUtil.getShannonEntropy(encrypted);
            System.out.printf("[*] Shannon entropy of encrypted message (Bytes): %.12f%n", entropyBytes);

            byte[] decrypted = CryptUtil.cs4440Decrypt(encrypted, key);
            if (Arrays.equals(decrypted, src.getBytes())) {
                System.out.println("[+] It works!  decrypted ： " + decrypted);
            } else {
                System.out.println("Decrypted message does not match!");
            }

            // File Encryption
            System.out.printf("[*] Encrypting target file: %s \n", targetFilepath);
            System.out.printf("[*] The encrypted file will be: %s \n", encFilepath);
            System.out.printf("[*] The decrypted file will be: %s \n", decFilepath);

            CryptUtil.encryptDoc(targetFilepath, encFilepath, key);
            CryptUtil.decryptDoc(encFilepath, decFilepath, key);

            System.out.printf("[+] [File] Entropy of the original file: %s \n",
                    CryptUtil.getFileShannonEntropy(targetFilepath));
            System.out.printf("[+] [File] Entropy of encrypted file: %s \n",
                    CryptUtil.getFileShannonEntropy(encFilepath));

            if (CryptUtil.compareSha1(targetFilepath, decFilepath)) {
                System.out.println("[+] The decrypted file is the same as the source file");
            } else {
                System.out.println("[+] The decrypted file is different from the source file.");
                System.out.println("[+] $ cat '<decrypted file>' to to check the differences");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}