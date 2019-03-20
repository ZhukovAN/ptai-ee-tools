package app01;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

public class Debug {
	public static String MD5(String theData) {
		if (null == theData) return "";
		final StringBuilder l_objSB = new StringBuilder();
		byte[] l_intData = theData.getBytes();

		MessageDigest l_objMD5;
		try {
			l_objMD5 = MessageDigest.getInstance("MD5");
			byte[] l_intMD5 = l_objMD5.digest(l_intData);
			for (byte l_intByte : l_intMD5)
				l_objSB.append(String.format("%02x", l_intByte));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return l_objSB.toString();
	}

	public static void getLogFile(String theFile, HttpServletResponse theResponse)
			throws ServletException, IOException {
		// According to log4j.appender.FILE.File setting from log4j.properties
		// Only the log files are needed, 
		String l_strLogFolder = System.getProperty("catalina.base") + "/logs/";
		File l_objLogFile = new File(l_strLogFolder + theFile);
		// Read the log file
		theResponse.setContentType("application/octet-stream");
		// String l_strName = l_objLogFile.getName().replaceAll("\\W", "");
		
		theResponse.setHeader("Content-Disposition", "filename=\"" + l_objLogFile.getName().replaceAll("\\W", "") + "\"");
		FileInputStream l_objInStream = new FileInputStream(l_objLogFile);
		OutputStream l_objOutStream = theResponse.getOutputStream();

		byte[] l_intBuf = new byte[4096];
		int l_intBytesRead = -1;

		while ((l_intBytesRead = l_objInStream.read(l_intBuf)) != -1)
			l_objOutStream.write(l_intBuf, 0, l_intBytesRead);

		l_objInStream.close();
		l_objOutStream.close();
	}
	
	public static void testLabel(int theData) {
		boolean t = true;
		first:
	    {
			second:
			{
				third:
				{
					System.out.println("Перед оператором break.");
					if (t) {
						break second;
					}
					System.out.println("Данный оператор никогда не выполнится");
				}
				System.out.println("Данный оператор никогда не выполнится ");
			}
			System.out.println("Данный оператор размещен после блока second.");
	    }
	}
}
