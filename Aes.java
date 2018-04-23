import javax.crypto.Cipher ;
import java.security.SecureRandom ;
import javax.crypto.spec.GCMParameterSpec ;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import java.security.spec.KeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


import javax.crypto.SecretKey;

import java.util.Base64 ;

import java.security.NoSuchAlgorithmException ;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.IllegalBlockSizeException ;
import javax.crypto.NoSuchPaddingException ;
import java.security.InvalidAlgorithmParameterException ;
import javax.crypto.BadPaddingException ;
import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;

import java.util.Arrays ; 
import java.nio.ByteBuffer;
import java.util.List;
import java.util.ArrayList;

/**
        This class shows how to securely perform AES encryption in GCM mode, with 128 bits key size.
*/
public class Aes {

	public static int AES_KEY_SIZE = 128 ;
	public static int IV_SIZE = 12 ;
  	public static int SALT_SIZE = 8;
	public static int TAG_BIT_LENGTH = 128 ;
	public static int ITERATION_COUNT = 65536;
	public static String ALGO_TRANSFORMATION_STRING = "AES/GCM/PKCS5Padding" ;
	public static String ALGO_PASSWORD_STRING = "PBKDF2WithHmacSHA256"; 
	
	private static SecretKey aesKey = null;
	private static byte[] salt;
	private static byte[] aadData;
	private static GCMParameterSpec gcmParamSpec;

	public static void init(String userPass){
		
		aadData = "random".getBytes() ; // Any random data can be used as tag. Some common examples could be domain name...

		// Use different key+IV pair for encrypting/decrypting different parameters

		// Generating Key
		//TODO get password from User
		char[] password = userPass.toCharArray();
		salt = new byte[SALT_SIZE];
		SecureRandom srand = new SecureRandom();
		srand.nextBytes(salt);
		try {
			
			/* Derive the key, given password and salt. */
			SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGO_PASSWORD_STRING);
			KeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, AES_KEY_SIZE);
			SecretKey tmp = factory.generateSecret(spec);
			aesKey = new SecretKeySpec(tmp.getEncoded(), "AES");
			
		
		} catch(NoSuchAlgorithmException noSuchAlgoExc) { System.out.println("Key being request is for AES algorithm, but this cryptographic algorithm is not available in the environment "  + noSuchAlgoExc) ; System.exit(1) ; }
        catch(InvalidKeySpecException invalidKeySpec) {System.out.println("invalid Key spec being used"); System.exit(1);}
		// Generating IV
		byte iv[] = new byte[IV_SIZE];
		SecureRandom secRandom = new SecureRandom() ;
		secRandom.nextBytes(iv); // SecureRandom initialized using self-seeding
		

		// Initialize GCM Parameters
		gcmParamSpec = new GCMParameterSpec(TAG_BIT_LENGTH, iv) ;      
		
		//byte[] encryptedText = aesEncrypt(messageToEncrypt, aesKey,  gcmParamSpec, aadData, salt) ;          
		
		//System.out.println("Encrypted Text = " + Base64.getEncoder().encodeToString(encryptedText) ) ;

		//byte[] decryptedText = aesDecrypt(encryptedText, aadData) ;

		//System.out.println("Decrypted text " + new String(decryptedText)) ;
	}
	


	public static byte[] aesEncrypt(byte[] message) {
		Cipher c = null ;

		try {
				c = Cipher.getInstance(ALGO_TRANSFORMATION_STRING); // Transformation specifies algortihm, mode of operation and padding
		}catch(NoSuchAlgorithmException noSuchAlgoExc) {System.out.println("Exception while encrypting. Algorithm being requested is not available in this environment " + noSuchAlgoExc); System.exit(1); }
		 catch(NoSuchPaddingException noSuchPaddingExc) {System.out.println("Exception while encrypting. Padding Scheme being requested is not available this environment " + noSuchPaddingExc); System.exit(1); }

		
		try {
			c.init(Cipher.ENCRYPT_MODE, aesKey, gcmParamSpec, new SecureRandom()) ;
		} catch(InvalidKeyException invalidKeyExc) {System.out.println("Exception while encrypting. Key being used is not valid. It could be due to invalid encoding, wrong length or uninitialized " + invalidKeyExc) ; System.exit(1); }
		 catch(InvalidAlgorithmParameterException invalidAlgoParamExc) {System.out.println("Exception while encrypting. Algorithm parameters being specified are not valid " + invalidAlgoParamExc) ; System.exit(1); }

	   try { 
			//c.updateAAD(aadData) ; // add AAD tag data before encrypting
		}catch(IllegalArgumentException illegalArgumentExc) {System.out.println("Exception thrown while encrypting. Byte array might be null " +illegalArgumentExc ); System.exit(1);} 
		catch(IllegalStateException illegalStateExc) {System.out.println("Exception thrown while encrypting. CIpher is in an illegal state " +illegalStateExc); System.exit(1);} 
		catch(UnsupportedOperationException unsupportedExc) {System.out.println("Exception thrown while encrypting. Provider might not be supporting this method " +unsupportedExc); System.exit(1);} 
	   
	   byte[] cipherTextInByteArr = null ;
	   try {
			cipherTextInByteArr = c.doFinal(message) ;
	   } catch(IllegalBlockSizeException illegalBlockSizeExc) {System.out.println("Exception while encrypting, due to block size " + illegalBlockSizeExc) ; System.exit(1); }
		 catch(BadPaddingException badPaddingExc) {System.out.println("Exception while encrypting, due to padding scheme " + badPaddingExc) ; System.exit(1); }
		
      // prepend salt and iv to cipherTextByteArr
		byte[] ivPW = new byte[IV_SIZE]; 
		ivPW = gcmParamSpec.getIV();
		byte[] ivNSalt = new byte[ivPW.length + salt.length];
		//System.arraycopy(src, srcPos, des, desPos, copyLength);
      	System.arraycopy(salt, 0, ivNSalt, 0            , salt.length);
      	System.arraycopy(ivPW  , 0, ivNSalt, salt.length, ivPW.length);
      	
      	byte[] appendedCipherText = new byte[ivNSalt.length + cipherTextInByteArr.length];
      	System.arraycopy(ivNSalt            , 0, appendedCipherText, 0             , ivNSalt.length);
      	System.arraycopy(cipherTextInByteArr, 0, appendedCipherText, ivNSalt.length, cipherTextInByteArr.length); 
		
	   return appendedCipherText ;
	}


	public static byte[] aesDecrypt(byte[] encryptedMessage, String userPass) {
	   Cipher c = null ;
		//encryptedMessage looks like (Salt)(IV)(cipherText) (8Bytes)(128Bytes)(?Bytes)
		byte[] splicedEncryptedMessage = new byte[encryptedMessage.length - IV_SIZE - SALT_SIZE];
		byte[] iv = new byte[IV_SIZE];
		byte[] salt = new byte[SALT_SIZE];
		//TODO get password from User
		char[] password = userPass.toCharArray();
		SecretKey aesKey = null;
		
		System.arraycopy(encryptedMessage, SALT_SIZE + IV_SIZE, splicedEncryptedMessage, 0, encryptedMessage.length - SALT_SIZE - IV_SIZE  );
		System.arraycopy(encryptedMessage, 0                  , salt                   , 0, SALT_SIZE);
		System.arraycopy(encryptedMessage, SALT_SIZE          , iv                     , 0, IV_SIZE);
		
		GCMParameterSpec gcmParamSpec = new GCMParameterSpec(TAG_BIT_LENGTH, iv);
		try {
			
			/* Derive the key, given password and salt. */
			SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGO_PASSWORD_STRING);
			KeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, AES_KEY_SIZE);
			SecretKey tmp = factory.generateSecret(spec);
			aesKey = new SecretKeySpec(tmp.getEncoded(), "AES");
			
		
		} catch(NoSuchAlgorithmException noSuchAlgoExc) { System.out.println("Key being request is for AES algorithm, but this cryptographic algorithm is not available in the environment "  + noSuchAlgoExc) ; System.exit(1) ; }
        catch(InvalidKeySpecException invalidKeySpec) {System.out.println("invalid Key spec being used"); System.exit(1);}
		
		 
	   try {
		   c = Cipher.getInstance(ALGO_TRANSFORMATION_STRING); // Transformation specifies algortihm, mode of operation and padding
		} catch(NoSuchAlgorithmException noSuchAlgoExc) {System.out.println("Exception while decrypting. Algorithm being requested is not available in environment " + noSuchAlgoExc); System.exit(1); }
		 catch(NoSuchPaddingException noSuchAlgoExc) {System.out.println("Exception while decrypting. Padding scheme being requested is not available in environment " + noSuchAlgoExc); System.exit(1); }  

		try {
			c.init(Cipher.DECRYPT_MODE, aesKey, gcmParamSpec, new SecureRandom()) ;
		} catch(InvalidKeyException invalidKeyExc) {System.out.println("Exception while encrypting. Key being used is not valid. It could be due to invalid encoding, wrong length or uninitialized " + invalidKeyExc) ; System.exit(1); }
		 catch(InvalidAlgorithmParameterException invalidParamSpecExc) {System.out.println("Exception while encrypting. Algorithm Param being used is not valid. " + invalidParamSpecExc) ; System.exit(1); }

		try {
			//c.updateAAD(aadData) ; // Add AAD details before decrypting
		}catch(IllegalArgumentException illegalArgumentExc) {System.out.println("Exception thrown while encrypting. Byte array might be null " +illegalArgumentExc ); System.exit(1);}
		catch(IllegalStateException illegalStateExc) {System.out.println("Exception thrown while encrypting. CIpher is in an illegal state " +illegalStateExc); System.exit(1);}
		
		byte[] plainTextInByteArr = null ;
		
		try {
			plainTextInByteArr = c.doFinal(splicedEncryptedMessage) ;
		} catch(IllegalBlockSizeException illegalBlockSizeExc) {System.out.println("Exception while decryption, due to block size " + illegalBlockSizeExc) ; System.exit(1); }
		 catch(BadPaddingException badPaddingExc) {System.out.println("Exception while decryption, due to padding scheme " + badPaddingExc) ; System.exit(1); }
		  catch(AEADBadTagException aeadBadTagExc) {System.out.println("You entered the wrong password. Please try again." + badPaddingExc) ; System.exit(1); }
		 
		return plainTextInByteArr ;
	}
}