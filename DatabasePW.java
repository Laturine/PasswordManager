import java.io.*;
import java.util.Map;
import java.util.HashMap;

public class DatabasePW implements Serializable{
  Map<String, UserInfo> dictionary;
   DatabasePW(){
  	dictionary = new HashMap<>(); 
   }
   
   public void addEntry(String key, String val1, String val2){
	   if(!dictionary.containsKey(key)){
		   dictionary.put(key, new UserInfo(val1, val2));
	   }
	   else{System.out.println("Please use update to change Key's values");}
   }
   public void updateEntry(String key, String val1, String val2){
	   dictionary.replace(key, new UserInfo(val1, val2));
   }
   public void deleteEntry(String key){
	   dictionary.remove(key);
   }
   public void show(String key){
	   System.out.println(dictionary.get(key));
   }
   public void print(){
	   System.out.println(String.format("%-20s %-15s %-15s", "WEBSITE", "USERNAME", "PASSWORD"));
	   dictionary.forEach((k,v) -> System.out.println(String.format("%-20s %-15s %-15s", k, v.getUser(), v.getPw())));
   }

  }