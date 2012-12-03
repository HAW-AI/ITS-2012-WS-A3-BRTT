import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;


public class RSAKeyCreation {

	/**
	 * @param args
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeySpecException 
	 * @throws IOException 
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException, IOException {
		if (args.length != 1) {
			System.out.println("Usage: java RSAKeyCreation <name>");
		}
		
		String name = args[0];
		
		// Beispiel: java RSAKeyCreation KMueller
		// erzeugt die Ausgabedateien KMueller.pub und  KMueller.prv
		RSAKeyGenParameterSpec rsaKeyGenParameterSpec = new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4);
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(rsaKeyGenParameterSpec);
		
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		KeyFactory keyFac = KeyFactory.getInstance("RSA");
		
		X509EncodedKeySpec x509 = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
		PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
		
		PublicKey pubKey = keyFac.generatePublic(x509);
		PrivateKey prvKey = keyFac.generatePrivate(pkcs8);
		
		File pub = new File(String.format("%s.pub",name));
		File prv = new File(String.format("%s.prv",name));
		
		FileWriter pubWriter = new FileWriter(pub);
		FileWriter prvWriter = new FileWriter(prv);
		
		pubWriter.write(pubKey.toString());
		prvWriter.write(prvKey.toString());
		
		pubWriter.close();
		prvWriter.close();
	}

}
