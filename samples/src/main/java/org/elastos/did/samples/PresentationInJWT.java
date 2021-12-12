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

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.elastos.did.DIDBackend;
import org.elastos.did.Issuer;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.VerifiablePresentation;
import org.elastos.did.exception.DIDException;
import org.elastos.did.jwt.Claims;
import org.elastos.did.jwt.Header;
import org.elastos.did.jwt.Jws;
import org.elastos.did.jwt.JwtException;
import org.elastos.did.jwt.JwtParser;
import org.elastos.did.jwt.JwtParserBuilder;

/**
 * How to embedded a verifiable presentation in the JWT token, and how to read it.
 */
public class PresentationInJWT {
	public static class University extends Entity {
		private Issuer issuer;

		public University(String name) throws DIDException {
			super(name);

			issuer = new Issuer(getDocument());
		}

		public VerifiableCredential issueDiplomaFor(Student student) throws DIDException {
			Map<String, Object> subject = new HashMap<String, Object>();
			subject.put("name", student.getName());
			subject.put("degree", "bachelor");
			subject.put("institute", "Computer Science");
			subject.put("university", getName());

			Calendar exp = Calendar.getInstance();
			exp.add(Calendar.YEAR, 5);

			VerifiableCredential.Builder cb = issuer.issueFor(student.getDid());
			VerifiableCredential vc = cb.id("diploma")
				.type("DiplomaCredential", "https://ttech.io/credentials/diploma/v1")
				.properties(subject)
				.expirationDate(exp.getTime())
				.seal(getStorePassword());

			return vc;
		}
	}

	public static class Student extends Entity {
		private String gender;
		private String email;
		private List<VerifiableCredential> vcs;

		public Student(String name, String gender, String email) throws DIDException {
			super(name);
			this.gender = gender;
			this.email = email;

			this.vcs = new ArrayList<VerifiableCredential>(4);
		}

		public VerifiableCredential createSelfProclaimedCredential() throws DIDException {
			Map<String, Object> subject = new HashMap<String, Object>();
			subject.put("name", getName());
			subject.put("gender", gender);
			subject.put("email", email);

			Calendar exp = Calendar.getInstance();
			exp.add(Calendar.YEAR, 1);

			VerifiableCredential.Builder cb = new Issuer(getDocument()).issueFor(getDid());
			VerifiableCredential vc = cb.id("profile")
				.type("SelfProclaimedCredential", "https://elastos.org/credentials/v1")
				.type("ProfileCredential", "https://elastos.org/credentials/profile/v1")
				.type("EmailCredential", "https://elastos.org/credentials/email/v1")
				.properties(subject)
				.expirationDate(exp.getTime())
				.seal(getStorePassword());

			return vc;
		}

		public void addCredential(VerifiableCredential vc) {
			vcs.add(vc);
		}

		public VerifiablePresentation createPresentation() throws DIDException {
			String realm = "sample";
			String nonce = "873172f58701a9ee686f0630204fee59";

			VerifiablePresentation.Builder vpb = VerifiablePresentation.createFor(getDid(), getStore());

			return vpb.credentials(vcs.toArray(new VerifiableCredential[vcs.size()]))
				.realm(realm)
				.nonce(nonce)
				.seal(getStorePassword());
		}


		public String createToken(String audience) throws JwtException, DIDException {
			Calendar cal = Calendar.getInstance();
			cal.set(Calendar.MILLISECOND, 0);
			Date iat = cal.getTime();
			Date nbf = cal.getTime();
			cal.add(Calendar.MONTH, 3);
			Date exp = cal.getTime();

			// Create JWT token with presentation.
			String token = getDocument().jwtBuilder()
					.addHeader(Header.TYPE, Header.JWT_TYPE)
					.setId("sample-00000002")
					.setAudience(audience)
					.setIssuedAt(iat)
					.setNotBefore(nbf)
					.setExpiration(exp)
					.claimWithJson("presentation", createPresentation().toString())
					.sign(getStorePassword())
					.compact();

			System.out.println("JWT Token:");
			System.out.println("  " + token);

			return token;
		}
	}

	public static class Verifier extends Entity {
		protected Verifier(String name) throws DIDException {
			super(name);
		}

		public void verifyAndReadJWT(String token) throws JwtException, DIDException {
			JwtParser jp = new JwtParserBuilder().build();
			Jws<Claims> jwt = jp.parseClaimsJws(token);

			String pre = jwt.getBody().getAsJson("presentation");
			VerifiablePresentation vp = VerifiablePresentation.parse(pre);

			System.out.format("%s - got a JWT token from %s with presentation:\n   %s\n",
					getName(), jwt.getBody().getIssuer(), vp.toString());
		}
	}

	public static void main(String args[]) {
		// Initializa the DID backend globally.
		Web3Adapter adapter = new Web3Adapter();
		DIDBackend.initialize(adapter);

		try {
			University university = new University("Elastos University");
			Student student = new Student("John Smith", "Male", "johnsmith@example.org");
			Verifier verifier = new Verifier("Test verifier");

			VerifiableCredential vc = university.issueDiplomaFor(student);
			System.out.println("The diploma credential:");
			System.out.println("  " + vc);
			student.addCredential(vc);

			vc = student.createSelfProclaimedCredential();
			System.out.println("The profile credential:");
			System.out.println("  " + vc);
			student.addCredential(vc);

			String token = student.createToken(verifier.getDid().toString());

			verifier.verifyAndReadJWT(token);
		} catch (Exception e) {
			e.printStackTrace();
		}

		adapter.shutdown();
	}
}
