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

package org.elastos.did.examples;

import java.io.File;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.elastos.did.DID;
import org.elastos.did.DIDBackend;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.Issuer;
import org.elastos.did.Mnemonic;
import org.elastos.did.RootIdentity;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.exception.DIDException;

public class IssueCredential {
	public static class Entity {
		// Mnemonic passphrase and the store password should set by the end user.
		private final static String passphrase = "mypassphrase";
		private final static String storepass = "mypassword";

		private String name;
		private DIDStore store;
		private DID did;

		protected Entity(String name) throws DIDException {
			this.name = name;

			initPrivateIdentity();
			initDid();
		}

		private void initPrivateIdentity() throws DIDException {
			final String storePath = System.getProperty("java.io.tmpdir")
					+ File.separator + "exampleStore";

			store = DIDStore.open(storePath);

			// Check the store whether contains the root private identity.
			if (store.containsRootIdentities())
				return; // Already exists

			// Create a mnemonic use default language(English).
			Mnemonic mg = Mnemonic.getInstance();
			String mnemonic = mg.generate();

			System.out.println("Please write down your mnemonic and passwords:");
			System.out.println("  Mnemonic: " + mnemonic);
			System.out.println("  Mnemonic passphrase: " + passphrase);
			System.out.println("  Store password: " + storepass);

			// Initialize the root identity.
			RootIdentity.create(mnemonic, passphrase, store, storepass);
		}

		private void initDid() throws DIDException {
			// Check the DID store already contains owner's DID(with private key).
			List<DID> dids = store.listDids((did) -> {
				try {
					return (store.containsPrivateKeys(did) && did.getMetadata().getAlias().equals("me"));
				} catch (DIDException e) {
					return false;
				}
			});

			if (dids.size() > 0) {
				return; // Already create my DID.
			}

			RootIdentity id = store.loadRootIdentity();
			DIDDocument doc = id.newDid(storepass);
			doc.getMetadata().setAlias("me");
			System.out.println("My new DID created: " + doc.getSubject());
			doc.publish(storepass);
		}

		public DID getDid() {
			return did;
		}

		public DIDDocument getDocument() throws DIDException {
			return store.loadDid(did);
		}

		public String getName() {
			return name;
		}

		protected String getStorePassword() {
			return storepass;
		}
	}

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
				.type("DiplomaCredential")
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
		try {
			// Initializa the DID backend globally.
			DIDBackend.initialize(new AssistDIDAdapter("testnet"));

			University university = new University("Elastos");
			Student student = new Student("John Smith");

			VerifiableCredential vc = university.issueDiplomaFor(student);
			System.out.println("The diploma credential:");
			System.out.println("  " + vc);

			System.out.println("  Genuine: " + vc.isGenuine());
			System.out.println("  Expired: " + vc.isExpired());
			System.out.println("  Valid: " + vc.isValid());
		} catch (DIDException e) {
			e.printStackTrace();
		}
	}
}