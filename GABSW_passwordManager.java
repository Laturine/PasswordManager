import java.util.Map;
import java.util.HashMap;
import java.util.Scanner;
import java.lang.Math; 
import java.io.*;

public class GABSW_passwordManager
{
  public static void main(String[] args)
  {
	  if(args.length == 0){
		  System.out.println("Proper usage is: java program command");
		  System.exit(0);
	  }
	  File file;
	  String filePath;
	  //get userPass
	  Scanner sc = new Scanner(System.in);
	  System.out.println("Please enter your secret code");
	  String userPass = new String(sc.next());
	  //initilizing Encryption class 
	  Aes.init(userPass);
	  sc.close();
	  
	  DatabasePW db = new DatabasePW();
	  filePath = new File("data.ser").getAbsolutePath();
	  file = new File(filePath);
	  if(file.isFile()){
		db = decryptNDeserialize(userPass);
	  }
	  //add method
	  if(args[0].equals("add")){
		  db.addEntry(args[1],args[2],args[3]);
	  }
	  //TODO delete method
	  if(args[0].equals("delete")){
		  db.deleteEntry(args[1]);
	  }
	  //TODO update method
	  if(args[0].equals("update")){
		  db.updateEntry(args[1],args[2],args[3]);
	  }
	  //TODO show method 
	  if(args[0].equals("show")){
		  db.show(args[1]);
	  }
	  //TODO showAll method
	  if(args[0].equals("showAll")){
		  db.print();
	  }
	  
	  SerializeNEncrypt(db);
	 
  }
  public static void SerializeNEncrypt(DatabasePW myObject){
	  
	//DatabasePW myObject = new DatabasePW();
	File file;
	String filePath;
	try {
		//serializing database
		 filePath = new File("data.ser").getAbsolutePath();
		 file = new File(filePath);
         FileOutputStream fileOut = new FileOutputStream(file);
         ObjectOutputStream out = new ObjectOutputStream(fileOut);
         out.writeObject(myObject);
         out.close();
         fileOut.close();
		 
         System.out.printf("Serialized data is saved in \n" + filePath);
		 System.out.println("\nnow encrypting...");
		 
		 //encrypting database
		 byte[] serializedText = new byte[(int) file.length()];
		 FileInputStream fis = new FileInputStream(file);
		 fis.read(serializedText);
		 fis.close();
		 
		 byte[] encryptedText = Aes.aesEncrypt(serializedText);
		 System.out.println("... all done.");
		 //writing to data.ser
		 fileOut = new FileOutputStream(file);
		 fileOut.write(encryptedText);
		 fileOut.close();
      } catch (IOException i) {
         i.printStackTrace();
      }
  }
  
  public static DatabasePW decryptNDeserialize(String userPass){
	  File file;
	  String filePath;
	  DatabasePW database = null;
	  try{
		  filePath = new File("data.ser").getAbsolutePath();
		  file = new File(filePath);
		  
		  //decryption
		  byte[] deserializedText = new byte[(int) file.length()];
		  FileInputStream fis = new FileInputStream(file);
		  fis.read(deserializedText);
		  fis.close();
		  
		  byte[] plainText = Aes.aesDecrypt(deserializedText, userPass);
		  
		  //writing to data.ser
		  FileOutputStream fileOut = new FileOutputStream(file);
		  fileOut.write(plainText);
		  fileOut.close();
		  
		  //deserialization
		  FileInputStream fileIn = new FileInputStream(file);
		  ObjectInputStream in = new ObjectInputStream(fileIn);
		  database = (DatabasePW) in.readObject();
		  in.close();
		  fileIn.close();
		  
		  
	  } catch(IOException i) {
		  i.printStackTrace();
	  } catch(ClassNotFoundException c){
		  c.printStackTrace();
	  }
	  return database;
  }
}