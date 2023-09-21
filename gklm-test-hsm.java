import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class TestHSM {

	public static final String DEFAULT_PKCS11_PROVIDER = "IBMPKCS11Impl-TKLM";
	protected static final String KEYSTORE_TYPE_PKCS11 = "PKCS11IMPLKS";
	protected static final String KEYSTORE_ALIAS = "tklmcipherkey2";
	public static String filepath = "C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\2\\pkcs11-calls.log";

	public static void main(String[] args) throws Exception {

		File src = new File(filepath);
		String libPath = "C:\\luna.cfg";
		char[] cipherPassword = "SKLM@admin123".toCharArray();

		System.out.println(" 1) Initialise pkcs11 provider");
		com.ibm.crypto.pkcs11impl.provider.IBMPKCS11Impl p = new com.ibm.crypto.pkcs11impl.provider.IBMPKCS11Impl(
				libPath);
		p.Init(libPath, cipherPassword);
		System.out.println(" add the provider to the system");
		Security.addProvider(p);
		
		copyFile(src, new File(filepath +".1"));

		System.out.println(" 2) Load Keystore ");
		KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE_PKCS11, DEFAULT_PKCS11_PROVIDER);
		ks.load(null, cipherPassword);
		
		copyFile(src, new File(filepath +".2"));

		System.out.println(" 3) Generate secret key and push to hsm");
		KeyGenerator kg = KeyGenerator.getInstance("AES", DEFAULT_PKCS11_PROVIDER);
		kg.init(256);
		SecretKey sKey = kg.generateKey();
		
		copyFile(src, new File(filepath +".3"));

		System.out.println(" 4) Push secret key to hsm");
		SecretKeyFactory skf = SecretKeyFactory.getInstance("AES", DEFAULT_PKCS11_PROVIDER);
		Key keyTran = skf.translateKey(sKey);
		// Now Store the key on the card using the keystore API.
		ks.setKeyEntry(KEYSTORE_ALIAS, keyTran, cipherPassword, null);

		copyFile(src, new File(filepath +".4"));
		
		System.out.println(" 4)a Print all aliases");
		Enumeration<String> aliases = ks.aliases();
		while (aliases.hasMoreElements()) {
			String alias =  aliases.nextElement();
			System.out.println("alias=" + alias);
		}
		
		copyFile(src, new File(filepath +".4a"));
		
		System.out.println(" 5) Encrypt/ decrypt data using master key");
		SecretKey key = (SecretKey) ks.getKey(KEYSTORE_ALIAS, cipherPassword);
		Cipher cipher = Cipher.getInstance("AES", DEFAULT_PKCS11_PROVIDER);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		
		
		KeyGenerator kgtest = KeyGenerator.getInstance("AES");
		kgtest.init(256);
		SecretKey testKey = kgtest.generateKey();
		
		
		byte[] encryptedBytes = cipher.doFinal(testKey.getEncoded());
		System.out.println("encoded bytes=" + base64Encode(encryptedBytes));
		
		copyFile(src, new File(filepath +".5"));
		
		System.out.println(" 6) Delete alias from from keystore");
		ks.deleteEntry(KEYSTORE_ALIAS);
		
		copyFile(src, new File(filepath +".6"));
	}

	public static void copyFile(File src, File dest) throws IOException, InterruptedException {
		     
        // using copy(InputStream,Path Target); method
        Files.copy(src.toPath(), dest.toPath());
        //Thread.sleep(2000);
        //Files.delete(src.toPath());
	}
	public static final String base64Encode(byte[] b) {
		BASE64Encoder encoder = new BASE64Encoder();
		return encoder.encode(b);
	}

	public static final byte[] base64Decode(String s) throws IOException {
		BASE64Decoder decoder = new BASE64Decoder();
		return decoder.decodeBuffer(s);
	}

}
