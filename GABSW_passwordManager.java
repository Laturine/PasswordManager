import java.util.Map;
import java.util.HashMap;
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
	  char[] pass = null; 
	  boolean fileExists = false;
	  DatabasePW db = new DatabasePW();
	  filePath = new File("data.ser").getAbsolutePath();
	  file = new File(filePath);
	  
	  if(file.isFile()){
		fileExists = true;
	  }
	  //add method
	  if(args[0].equals("add")){
		  if(args.length == 4){
			  if(fileExists){
				  pass = getPassNInit();
				  db = decryptNDeserialize(pass);
				  db.addEntry(args[1],args[2],args[3]);
				  SerializeNEncrypt(db);
			  }
			  else{
				  System.out.println("You're creating a fresh database! \nPlease create a master password to protect your passwords");
				  pass = getPassNInit();
				  db.addEntry(args[1],args[2],args[3]);
				  SerializeNEncrypt(db);
			  }
		  }
		  else{System.out.println("add usage: add [website] [username] [password]");}
	  }
	  //delete method
	  if(args[0].equals("delete")){
		  if(args.length == 2){
			  if(fileExists){
				  pass = getPassNInit();
				  db = decryptNDeserialize(pass);
				  db.deleteEntry(args[1]);
				  SerializeNEncrypt(db);
			  }
			  else{
				  System.out.println("You're creating a fresh database! \nPlease create a master password to protect your passwords");
				  pass = getPassNInit();
				  db.deleteEntry(args[1]);
				  SerializeNEncrypt(db);
			  }
			
		  }
		  else{System.out.println("delete usage: delete [website]");}
	  }
	  //update method
	  if(args[0].equals("update")){
		  if(args.length == 4){
			  if(fileExists){
				  pass = getPassNInit();
				  db = decryptNDeserialize(pass);
				  db.updateEntry(args[1],args[2],args[3]);
				  SerializeNEncrypt(db); 
			  }
			  else{System.out.println("A database does not exist yet! \nPlease use command add to start a fresh database");}
		  }
		  else{System.out.println("update usage: update [website] [NewUsername] [NewPassword]");}
	  }
	  //show method 
	  if(args[0].equals("show")){
		  
		  if(args.length == 2){
			  if(fileExists){
				  pass = getPassNInit();
				  db = decryptNDeserialize(pass);
				  db.show(args[1]);
				  SerializeNEncrypt(db);
			  }
			  else{System.out.println("A database does not exist yet! \nPlease use command add to start a fresh database");}
		}
		else{System.out.println("show usage: show [website]");}
	  }
	  //showAll method
	  if(args[0].equals("showAll")){
		  if(args.length == 1){
			  if(fileExists){
				  pass = getPassNInit();
				  db = decryptNDeserialize(pass);
				  db.print();
				  SerializeNEncrypt(db);
			  }
			  else{System.out.println("A database does not exist yet! \nPlease use command add to start a fresh database");}
			  
		  }
		  else{System.out.println("showAll usage: showAll");}
	  }
	 
  }
  private static char[] getPassNInit(){
	  //get userPass
	  System.out.println("Please enter your secret code");
	  Console console = System.console();
	  char[] userPass = console.readPassword();
	  Aes.init(userPass);
	  return userPass;
  }
  private static void SerializeNEncrypt(DatabasePW myObject){
	  
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
		 
         System.out.printf("\nSerialized data is saved in \n" + filePath);
		 System.out.println("\nnow encrypting...");
		 
		 //encrypting database
		 byte[] serializedText = new byte[(int) file.length()];
		 FileInputStream fis = new FileInputStream(file);
		 fis.read(serializedText);
		 fis.close();
		 //exactly where encryption occurs
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
  
  private static DatabasePW decryptNDeserialize(char[] userPass){
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
		  //TODO userPass = Aes.erasePass(userPass);
		  
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