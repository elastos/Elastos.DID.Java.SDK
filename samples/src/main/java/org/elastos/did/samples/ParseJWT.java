package org.elastos.did.samples;

import org.elastos.did.DIDBackend;
import org.elastos.did.crypto.Base64;
import org.elastos.did.jwt.Claims;
import org.elastos.did.jwt.Jws;
import org.elastos.did.jwt.JwtParser;
import org.elastos.did.jwt.JwtParserBuilder;

public class ParseJWT {
	private static final int OPT = Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP;

	private static void printJwt(String token) {
		String [] toks = token.split("\\.");

		if (toks.length != 2 && toks.length != 3) {
			System.out.println("Invalid token: " + token);
			return;
		}

		StringBuilder sb = new StringBuilder(512);
		sb.append(new String(Base64.decode(toks[0], OPT))).append(".")
			.append(new String(Base64.decode(toks[1], OPT))).append(".");
		if (toks.length == 3)
			sb.append(toks[2]);

		System.out.println("Token: " + token);
		System.out.println("Plain: " + sb.toString());
	}



	public static void main(String[] args) throws Exception {
		// Initializa the DID backend globally.
		DIDBackend.initialize(new AssistDIDAdapter("testnet"));

		String token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1OTU5MDM1MjUsImV4cCI6MTU5NTk4OTkyNSwiaXNzIjoiZGlkOmVsYXN0b3M6aVlwUU13aGVEeHlTcWl2b2NTSmFvcHJjb0RUcVFzRFlBdSIsImNvbW1hbmQiOiJ2b3RlZm9ycHJvcG9zYWwiLCJkYXRhIjp7InByb3Bvc2FsSGFzaCI6ImY0MTRkMjUzODY0NDQ2NDNiYTE2NzZlYmZjZjU0ODJjNmZlYjNkMDI1OTlmNjE0NTJlYTYwMDg5OWQ4ZDdiZWUifX0.AsKlYyG3RyMBXBiDWkjZ4etbhCNjEp9MKIy8ySW2rBvCD9xFUiKUrjbsB4V0YI7eV47aqso4y8OdSXxc9yfoCw";
		printJwt(token);

		JwtParser jp = new JwtParserBuilder().build();
		Jws<Claims> jwt = jp.parseClaimsJws(token);

		System.out.println(jwt.toString());
	}

}
