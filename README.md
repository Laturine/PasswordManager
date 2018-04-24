Steps to Compile and Create Jar

javac GABSW_passwordManager.java

jar -cfe pw.jar GABSW_passwordManager *.class

To use jar:
	java -jar pw.jar command [args]