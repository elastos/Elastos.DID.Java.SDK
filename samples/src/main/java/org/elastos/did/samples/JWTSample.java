/*
 * Copyright (c) 2019 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package org.elastos.did.samples;

import java.util.Calendar;
import java.util.Date;

import org.elastos.did.DIDBackend;
import org.elastos.did.exception.DIDException;
import org.elastos.did.jwt.Claims;
import org.elastos.did.jwt.Header;
import org.elastos.did.jwt.Jws;
import org.elastos.did.jwt.JwtException;
import org.elastos.did.jwt.JwtParser;
import org.elastos.did.jwt.JwtParserBuilder;

/**
 * How to create and read the JWT token.
 */
public class JWTSample {
	public static class Person extends Entity {
		protected Person(String name) throws DIDException {
			super(name);
		}

		public String createJWT(String audience) throws JwtException, DIDException {
			Calendar cal = Calendar.getInstance();
			cal.set(Calendar.MILLISECOND, 0);
			Date iat = cal.getTime();
			Date nbf = cal.getTime();
			cal.add(Calendar.MONTH, 3);
			Date exp = cal.getTime();

			String nonce = "6b1814d2aa08f601e1432a1dac1ddc92";

			// Create JWT token with presentation.
			String token = getDocument().jwtBuilder()
					.addHeader(Header.TYPE, Header.JWT_TYPE)
					.setId("sample-00000001")
					.setAudience(audience)
					.setIssuedAt(iat)
					.setNotBefore(nbf)
					.setExpiration(exp)
					.claim("name", getName())
					.claim("nonce", nonce)
					.sign(getStorePassword())
					.compact();

			System.out.println(getName() + " - created a JWT token: " + token);
			return token;
		}

		public void verifyAndReadJWT(String token) throws JwtException, DIDException {
			JwtParser jp = new JwtParserBuilder().build();
			Jws<Claims> jwt = jp.parseClaimsJws(token);

			String from = jwt.getBody().get("name", String.class);
			String nonce = (String)jwt.getBody().get("nonce");

			System.out.format("%s - got a JWT token from %s with nonce: %s\n", getName(), from, nonce);
		}
	}

	public static void main(String[] args) throws Exception {
		// Initializa the DID backend globally.
		Web3Adapter adapter = new Web3Adapter();
		DIDBackend.initialize(adapter);

		Person alice = new Person("Alice");
		Person bob = new Person("Bob");

		String token = alice.createJWT(bob.getDid().toString());

		bob.verifyAndReadJWT(token);

		adapter.shutdown();
	}
}
