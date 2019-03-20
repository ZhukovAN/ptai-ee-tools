package app01;

import org.owasp.esapi.ESAPI;

public class Security {
	public static String safeFilterOutput(String theData) {
		return ESAPI.encoder().encodeForHTML(theData);		
	}

	public static String unsafeFilterOutput(String theData) {
		return theData;		
	}
}
