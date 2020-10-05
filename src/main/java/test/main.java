package test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import org.bouncycastle.openpgp.PGPException;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.Feature;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeyFlag;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeySpec;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeySpecBuilder;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.Passphrase;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.RSAForEncryptionKeyType;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.RSAForSigningKeyType;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.length.RsaLength;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.*;;

public class main {

	private final static String UID_JULIET = "Juliet Capulet <juliet@example.com>";
    private final static String EMAIL_JULIET = "juliet@example.com";
    private final static String PASSPHRASE = "hello23";
    private final static String FILEPATH = "/Users/harshakushtagi/Desktop/dev/bouncy-pgp/certs/"; 
	  public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			BouncyGPG.registerProvider();
			final KeyringConfig rsaKeyRing = BouncyGPG.createSimpleKeyring()
			        .simpleRsaKeyRing(UID_JULIET, RsaLength.RSA_3072_BIT);
			
			System.out.println(rsaKeyRing.toString());
			try {
				persistGeneratedKeys();
			} catch (SignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (PGPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	  
  public static void persistGeneratedKeys() throws NoSuchAlgorithmException, IOException, NoSuchProviderException, SignatureException, PGPException, InvalidAlgorithmParameterException {

        // 1. Create a new keyring with new keys
        KeyringConfig createdKeyRing = createComplexKeyRing(UID_JULIET.getBytes(), PASSPHRASE);

        // 2. Get the persisted keys in a binary format
        ByteArrayOutputStream pubKeyRingBuffer = new ByteArrayOutputStream();
        createdKeyRing.getPublicKeyRings().encode(pubKeyRingBuffer);
        pubKeyRingBuffer.close();
        byte[] publicKey = pubKeyRingBuffer.toByteArray();
        System.out.println(publicKey.toString());
       
        

        ByteArrayOutputStream secretKeyRingBuffer = new ByteArrayOutputStream();
        createdKeyRing.getSecretKeyRings().encode(secretKeyRingBuffer);
        secretKeyRingBuffer.close();
        byte[] secretKey = secretKeyRingBuffer.toByteArray();
        System.out.println(secretKey.toString());
       
        
        
        try { 
        	  
            // Initialize a pointer 
            // in file using OutputStream 
        	 File file_pk = new File(FILEPATH+"pk.gpg"); 
        	 File file_prk = new File(FILEPATH+"prk.gpg"); 
            
        	 OutputStream os  = new FileOutputStream(file_pk);
        	 os.write(publicKey); 
        	 os.close(); 
        	 
        	 os =  new FileOutputStream(file_prk);
        	 os.write(secretKey); 
        	 os.close(); 
        	 
           
        } 
  
        catch (Exception e) { 
            System.out.println("Exception: " + e); 
        } 
        
        // 3. load the persisted keys
        InMemoryKeyring memoryKeyring = KeyringConfigs.forGpgExportedKeys(keyId -> PASSPHRASE.toCharArray());
        memoryKeyring.addPublicKey(publicKey);
        memoryKeyring.addSecretKey(secretKey);

       
    }
	  
  public static KeyringConfig createComplexKeyRing(byte[] uid, String passphrase)
          throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException {

      // 1024 BIT IS NOT SECURE! The key length of 1024 bit is used to speed up the process.
      final KeySpec signingSubey = KeySpecBuilder
              .newSpec(RSAForSigningKeyType.withLength(RsaLength.RSA_2048_BIT))
              .allowKeyToBeUsedTo(KeyFlag.SIGN_DATA)
              .withDefaultAlgorithms();

      // 1024 BIT IS NOT SECURE! The key length of 1024 bit is used to speed up the process.
      final KeySpec authenticationSubey = KeySpecBuilder
              .newSpec(RSAForEncryptionKeyType.withLength(RsaLength.RSA_1024_BIT))
              .allowKeyToBeUsedTo(KeyFlag.AUTHENTICATION)
              .withDefaultAlgorithms();

      // 1024 BIT IS NOT SECURE! The key length of 1024 bit is used to speed up the process.
      final KeySpec encryptionSubey = KeySpecBuilder
              .newSpec(RSAForEncryptionKeyType.withLength(RsaLength.RSA_1024_BIT))
              .allowKeyToBeUsedTo(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
              .withDefaultAlgorithms();

      // 1024 BIT IS NOT SECURE! The key length of 1024 bit is used to speed up the process.
      final KeySpec masterKey = KeySpecBuilder.newSpec(
              RSAForSigningKeyType.withLength(RsaLength.RSA_1024_BIT)
      )
              .allowKeyToBeUsedTo(KeyFlag.CERTIFY_OTHER)
              .withDetailedConfiguration()
              .withPreferredSymmetricAlgorithms(
                      PGPSymmetricEncryptionAlgorithms.recommendedAlgorithms()
              )
              .withPreferredHashAlgorithms(
                      PGPHashAlgorithms.recommendedAlgorithms()
              )
              .withPreferredCompressionAlgorithms(
                      PGPCompressionAlgorithms.recommendedAlgorithms()
              )
              .withFeature(Feature.MODIFICATION_DETECTION)
              .done();

      final KeyringConfig complexKeyRing = BouncyGPG
              .createKeyring()
              .withSubKey(signingSubey)
              .withSubKey(authenticationSubey)
              .withSubKey(encryptionSubey)
              .withMasterKey(masterKey)
              .withPrimaryUserId(uid)
              .withPassphrase(Passphrase.fromString(passphrase))
              .build();

  
      return complexKeyRing;
  }

}

 