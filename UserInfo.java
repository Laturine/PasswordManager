import java.io.*;

public class UserInfo implements Serializable{
	String user;
  	String pw;

  public String getUser(){
    return user;
  }
  public String getPw(){
    return pw;
  }
  public UserInfo(String user, String pw){
    this.user = user;
    this.pw = pw;
  }
  @Override
  public String toString(){
    return user +", "+ pw;
  }
}