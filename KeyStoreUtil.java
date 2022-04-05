// Decompiled with: CFR 0.151
// Class Version: 8
package bin.mt.keystore;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.zip.CRC32;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyStoreUtil {
    private static final int MAGIC = -1395514454;
    private static final String FILE_NAME = "FileName";
    private static final String KEYSTORE_PASSWORD = "KeystorePassword";
    private static final String ALIAS_NAME = "AliasName";
    private static final String ALIAS_PASSWORD = "AliasPassword";
    private static final String KEY_PASSWORD = "KeyPassword";

    public static void main(String[] args) {
        try {
            File dir = new File(System.getProperty("java.class.path")).getParentFile();
            File ini = new File(dir, "mtkeytool.ini");
            HashMap<String, String> map = new HashMap<String, String>();
            KeyStoreUtil.readIni(map, ini);
            if (!map.containsKey(FILE_NAME)) {
                throw new NullPointerException("FileName not found");
            }
            if (!map.containsKey(KEYSTORE_PASSWORD)) {
                throw new NullPointerException("KeystorePassword not found");
            }
            if (!map.containsKey(ALIAS_NAME)) {
                throw new NullPointerException("AliasName not found");
            }
            if (!map.containsKey(ALIAS_PASSWORD)) {
                throw new NullPointerException("AliasPassword not found");
            }
            String name = map.get(FILE_NAME);
            String password = map.get(KEYSTORE_PASSWORD);
            String alias = map.get(ALIAS_NAME);
            String aliasPass = map.get(ALIAS_PASSWORD);
            File file = new File(dir, name);
            File outDir = new File(dir, "keys");
            outDir.mkdirs();
            KeyStore keyStore = KeyStoreUtil.loadKeyStore(file, password);
            System.err.println("Output:");
            if (map.containsKey(KEY_PASSWORD) && map.get(KEY_PASSWORD).length() > 0) {
                String keyPass = map.get(KEY_PASSWORD);
                File out = new File(outDir, KeyStoreUtil.getName(file.getName()) + ".aes");
                KeyStoreUtil.encryptSplit(keyStore, out, keyPass, alias, aliasPass);
            } else {
                KeyStoreUtil.split(keyStore, KeyStoreUtil.getName(file.getName()), outDir, alias, aliasPass);
            }
            System.err.println();
            System.out.println("succeed.");
        }
        catch (Exception e) {
            System.err.println();
            e.printStackTrace();
        }
        try {
            System.in.read();
        }
        catch (IOException iOException) {
            // empty catch block
        }
    }

    private static String getName(String string) {
        int i = string.lastIndexOf(46);
        if (i == -1) {
            return string;
        }
        return string.substring(0, i);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private static void readIni(HashMap<String, String> map, File ini) throws IOException {
        BufferedReader br = null;
        try {
            String line;
            br = new BufferedReader(new FileReader(ini));
            while ((line = br.readLine()) != null) {
                int separator = (line = line.replaceAll("^#.*$", "").replaceAll("^//.*$", "").replaceAll("[ \\t]+$", "")).indexOf(61);
                if (separator == -1) continue;
                String head = line.substring(0, separator).trim();
                String body = line.substring(separator + 1).trim();
                map.put(head, body);
            }
        }
        finally {
            if (br != null) {
                try {
                    br.close();
                }
                catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private static KeyStore loadKeyStore(File file, String passWord) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream(file), passWord.toCharArray());
        return keyStore;
    }

    private static void split(KeyStore keyStore, String name, File dir, String alias, String passWord) throws Exception {
        Certificate pubkey = keyStore.getCertificate(alias);
        Key key = keyStore.getKey(alias, passWord.toCharArray());
        KeyPair kp = new KeyPair(pubkey.getPublicKey(), (PrivateKey)key);
        FileOutputStream m_fos_x509 = new FileOutputStream(new File(dir, name + ".x509.pem"));
        m_fos_x509.write("-----BEGIN CERTIFICATE-----\n".getBytes());
        m_fos_x509.write(Base64.getEncoder().encode(pubkey.getEncoded()));
        m_fos_x509.write("\n-----END CERTIFICATE-----".getBytes());
        m_fos_x509.close();
        System.out.println("-> keys/" + name + ".x509.pem");
        FileOutputStream m_fos_pk8 = new FileOutputStream(new File(dir, name + ".pk8"));
        m_fos_pk8.write(kp.getPrivate().getEncoded());
        m_fos_pk8.close();
        System.out.println("-> keys/" + name + ".pk8");
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private static void encryptSplit(KeyStore keyStore, File outFile, String filePassWord, String alias, String passWord) throws Exception {
        Certificate pubkey = keyStore.getCertificate(alias);
        Key key = keyStore.getKey(alias, passWord.toCharArray());
        KeyPair kp = new KeyPair(pubkey.getPublicKey(), (PrivateKey)key);
        FilterOutputStream dos = null;
        FileOutputStream fos = null;
        CRC32 crc32 = new CRC32();
        try {
            fos = new FileOutputStream(outFile);
            dos = new DataOutputStream(fos);
            ((DataOutputStream)dos).writeInt(-1395514454);
            byte[] data = ("-----BEGIN CERTIFICATE-----\n" + Base64.getEncoder().encodeToString(pubkey.getEncoded()) + "\n-----END CERTIFICATE-----").getBytes();
            crc32.update(data);
            data = KeyStoreUtil.encrypt(data, filePassWord);
            ((DataOutputStream)dos).writeInt(data.length);
            dos.write(data);
            data = kp.getPrivate().getEncoded();
            crc32.update(data);
            data = KeyStoreUtil.encrypt(data, filePassWord);
            ((DataOutputStream)dos).writeInt(data.length);
            dos.write(data);
            ((DataOutputStream)dos).writeLong(crc32.getValue());
            ((DataOutputStream)dos).flush();
            System.out.println("-> keys/" + outFile.getName());
        }
        finally {
            try {
                if (dos != null) {
                    dos.close();
                }
            }
            catch (IOException iOException) {}
            try {
                if (fos != null) {
                    fos.close();
                }
            }
            catch (IOException iOException) {}
        }
    }

    private static byte[] encrypt(byte[] data, String password) throws Exception {
        MessageDigest mdInst = MessageDigest.getInstance("MD5");
        byte[] pass = new byte[16];
        byte[] md5 = mdInst.digest(password.getBytes());
        System.arraycopy(md5, 0, pass, 0, 16);
        SecretKeySpec key = new SecretKeySpec(pass, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        md5 = mdInst.digest(md5);
        System.arraycopy(md5, 0, pass, 0, 16);
        cipher.init(1, (Key)key, new IvParameterSpec(pass));
        return cipher.doFinal(data);
    }
}