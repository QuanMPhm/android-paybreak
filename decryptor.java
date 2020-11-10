import java.io.*;
import java.util.*;
import java.util.Base64;
import java.lang.Object;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import io.pkts;

public class decryptor{

	//public static final int DEFAULT = 0;

	public static void main(String[] args) throws Throwable {
		Scanner scanner = new Scanner(System.in);
		String txtfile = scanner.next();
		String keyfile = scanner.next();

		BufferedReader txtbr = new BufferedReader(new InputStreamReader(new FileInputStream(txtfile)));
		BufferedReader keybr = new BufferedReader(new InputStreamReader(new FileInputStream(keyfile)));

		byte[] iv = Base64.getDecoder().decode(keybr.readLine());
		String mode = keybr.readLine();
		byte[] key = Base64.getDecoder().decode(keybr.readLine());
		String keymode = keybr.readLine();

		String extra;
		String encrypted = txtbr.readLine();
		while ((extra = txtbr.readLine()) != null) {
            encrypted = encrypted.concat("\n");
            encrypted = encrypted.concat(extra);
        }

		System.out.println(encrypted);

		byte[] bytetxt = Base64.getDecoder().decode(encrypted);

		String decrypted = decrypt(bytetxt, iv, mode, key, keymode);

		System.out.println(decrypted);
	}

	static String decrypt(byte[] txt, byte[] iv, String mode, byte[] key, String keymode) throws Throwable {
		SecretKeySpec skeySpec = new SecretKeySpec(key, keymode); //Get key
        Cipher decipher = Cipher.getInstance(mode); //Set algorhythm
        GCMParameterSpec ivspec = new GCMParameterSpec(key.length*8,iv); //Get IV
        decipher.init(Cipher.DECRYPT_MODE, skeySpec, ivspec); //Intialize with all parameters
        byte[] decryptedData = decipher.doFinal(txt); //Decrypt
        String decrytedText = new String(decryptedData);
        return decrytedText;
	}
}