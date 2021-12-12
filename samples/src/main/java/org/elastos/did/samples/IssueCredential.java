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
import java.util.HashMap;
import java.util.Map;

import org.elastos.did.DIDBackend;
import org.elastos.did.Issuer;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.exception.DIDException;

/**
 * Sample that shows how to issue a credential.
 */
public class IssueCredential {
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
		public Student(String name) throws DIDException {
			super(name);
		}
	}

	public static void main(String args[]) {
		// Initializa the DID backend globally.		
		Web3Adapter adapter = new Web3Adapter();
		DIDBackend.initialize(adapter);

		try {
			University university = new University("Elastos");
			Student student = new Student("John Smith");

			VerifiableCredential vc = university.issueDiplomaFor(student);
			System.out.println("\nThe diploma credential:");
			System.out.println("  " + vc);

			System.out.println("\nThe credential status:");
			System.out.println("  Genuine: " + vc.isGenuine());
			System.out.println("  Expired: " + vc.isExpired());
			System.out.println("  Valid: " + vc.isValid());
		} catch (DIDException e) {
			e.printStackTrace();
		}
		
		adapter.shutdown();
	}
}