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
import javax.crypto.IllegalBlockSizeException ;
import javax.crypto.NoSuchPaddingException ;
import java.security.InvalidAlgorithmParameterException ;
import javax.crypto.BadPaddingException ;
import javax.crypto.ShortBufferException;

import java.util.Arrays ; 
import java.nio.ByteBuffer;
import java.util.List;
import java.util.ArrayList;

/**
        This class shows how to securely perform AES encryption in GCM mode, with 256 bits key size.
*/
public class AESEncryption {

	public static int AES_KEY_SIZE = 128 ;
	public static int IV_SIZE = 12 ;
	public static int TAG_BIT_LENGTH = 128 ;
	public static String ALGO_TRANSFORMATION_STRING = "AES/GCM/PKCS5Padding" ;
	public static String ALGO_PASSWORD_STRING = "PBKDF2WithHmacSHA256"; 

	public static void main(String args[]) {
		String messageToEncrypt = args[0] ;
		
		byte[] aadData = "random".getBytes() ; // Any random data can be used as tag. Some common examples could be domain name...

		// Use different key+IV pair for encrypting/decrypting different parameters

		// Generating Key
		SecretKey aesKey = null ;
		char[] password = "Mar333lol.".toCharArray();
		byte[] salt = new byte[8];
		SecureRandom srand = new SecureRandom();
		srand.nextBytes(salt);
		try {
			KeyGenerator keygen = KeyGenerator.getInstance("AES") ; // Specifying algorithm key will be used for 
			keygen.init(AES_KEY_SIZE) ; // Specifying Key size to be used, Note: 256 or > need JCE Unlimited Strength to be installed explicitly 
			
			/* Derive the key, given password and salt. */
			SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGO_PASSWORD_STRING);
			KeySpec spec = new PBEKeySpec(password, salt, 65536, 128);
			SecretKey tmp = factory.generateSecret(spec);
			aesKey = new SecretKeySpec(tmp.getEncoded(), "AES");
			
			//aesKey = keygen.generateKey() ;
		} catch(NoSuchAlgorithmException noSuchAlgoExc) { System.out.println("Key being request is for AES algorithm, but this cryptographic algorithm is not available in the environment "  + noSuchAlgoExc) ; System.exit(1) ; }

		// Generating IV
		byte iv[] = new byte[IV_SIZE];
		SecureRandom secRandom = new SecureRandom() ;
		secRandom.nextBytes(iv); // SecureRandom initialized using self-seeding
		

		// Initialize GCM Parameters
		GCMParameterSpec gcmParamSpec = new GCMParameterSpec(TAG_BIT_LENGTH, iv) ;      
		
		byte[] encryptedText = aesEncrypt(messageToEncrypt, aesKey,  gcmParamSpec, aadData, salt) ;          
		
		System.out.println("Encrypted Text = " + Base64.getEncoder().encodeToString(encryptedText) ) ;

		byte[] decryptedText = aesDecrypt(encryptedText, aesKey, gcmParamSpec, aadData) ; // Same key, IV and GCM Specs for decryption as used for encryption.

		System.out.println("Decrypted text " + new String(decryptedText)) ;

		// Make sure not to repeat Key + IV pair, for encrypting more than one plaintext.
		secRandom.nextBytes(iv);
	}


	public static byte[] aesEncrypt(String message, SecretKey aesKey, GCMParameterSpec gcmParamSpec, byte[] aadData, byte[] saltPW) {
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
			c.updateAAD(aadData) ; // add AAD tag data before encrypting
		}catch(IllegalArgumentException illegalArgumentExc) {System.out.println("Exception thrown while encrypting. Byte array might be null " +illegalArgumentExc ); System.exit(1);} 
		catch(IllegalStateException illegalStateExc) {System.out.println("Exception thrown while encrypting. CIpher is in an illegal state " +illegalStateExc); System.exit(1);} 
		catch(UnsupportedOperationException unsupportedExc) {System.out.println("Exception thrown while encrypting. Provider might not be supporting this method " +unsupportedExc); System.exit(1);} 
	   
	   byte[] cipherTextInByteArr = null ;
	   try {
			cipherTextInByteArr = c.doFinal(message.getBytes()) ;
	   } catch(IllegalBlockSizeException illegalBlockSizeExc) {System.out.println("Exception while encrypting, due to block size " + illegalBlockSizeExc) ; System.exit(1); }
		 catch(BadPaddingException badPaddingExc) {System.out.println("Exception while encrypting, due to padding scheme " + badPaddingExc) ; System.exit(1); }
		// prepend salt and iv to cipherTextByteArr
		byte[] ivPW = new byte[IV_SIZE]; 
		ivPW = gcmParamSpec.getIV();
		//TODO list byte throws compile errors figure it out or change method
		List<Byte> list = new ArrayList<Byte>(Arrays.<Byte>asList(saltPW));
		list.addAll(Arrays.<Byte>asList(ivPW));
		list.addAll(Arrays.<Byte>asList(cipherTextInByteArr));
		
		byte[] appendedCipherText = list.toArray(new byte[list.size()]);
		
		
	   return appendedCipherText ;
	}


	public static byte[] aesDecrypt(byte[] encryptedMessage, SecretKey aesKey, GCMParameterSpec gcmParamSpec, byte[] aadData) {
	   Cipher c = null ;
		//encryptedMessage looks like (Salt)(IV)(cipherText) (8Bytes)(128Bytes)(?Bytes)
	    //TODO get rid of aesKey param NEEDS to be created from salt prepened to encrypted message
		//TODO get rid of gcmParamSpec param NEEDS to be created from iv prepended to encrypted message.
		//ByteBuffer bb = ByteBuffer.allocate(128);
		 
	   try {
		   c = Cipher.getInstance(ALGO_TRANSFORMATION_STRING); // Transformation specifies algortihm, mode of operation and padding
		} catch(NoSuchAlgorithmException noSuchAlgoExc) {System.out.println("Exception while decrypting. Algorithm being requested is not available in environment " + noSuchAlgoExc); System.exit(1); }
		 catch(NoSuchPaddingException noSuchAlgoExc) {System.out.println("Exception while decrypting. Padding scheme being requested is not available in environment " + noSuchAlgoExc); System.exit(1); }  

		try {
			c.init(Cipher.DECRYPT_MODE, aesKey, gcmParamSpec, new SecureRandom()) ;
		} catch(InvalidKeyException invalidKeyExc) {System.out.println("Exception while encrypting. Key being used is not valid. It could be due to invalid encoding, wrong length or uninitialized " + invalidKeyExc) ; System.exit(1); }
		 catch(InvalidAlgorithmParameterException invalidParamSpecExc) {System.out.println("Exception while encrypting. Algorithm Param being used is not valid. " + invalidParamSpecExc) ; System.exit(1); }

		try {
			c.updateAAD(aadData) ; // Add AAD details before decrypting
		}catch(IllegalArgumentException illegalArgumentExc) {System.out.println("Exception thrown while encrypting. Byte array might be null " +illegalArgumentExc ); System.exit(1);}
		catch(IllegalStateException illegalStateExc) {System.out.println("Exception thrown while encrypting. CIpher is in an illegal state " +illegalStateExc); System.exit(1);}
		
		byte[] plainTextInByteArr = null ;
		
		try {
			plainTextInByteArr = c.doFinal(encryptedMessage) ;
		} catch(IllegalBlockSizeException illegalBlockSizeExc) {System.out.println("Exception while decryption, due to block size " + illegalBlockSizeExc) ; System.exit(1); }
		 catch(BadPaddingException badPaddingExc) {System.out.println("Exception while decryption, due to padding scheme " + badPaddingExc) ; System.exit(1); }

		return plainTextInByteArr ;
	}
}