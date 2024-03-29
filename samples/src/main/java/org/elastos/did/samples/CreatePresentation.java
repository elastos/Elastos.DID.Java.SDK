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

import java.io.File;
import java.util.ArrayList;
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
import org.elastos.did.VerifiablePresentation;
import org.elastos.did.exception.DIDException;

/**
 * How to create a verifiable presentation.
 */
public class CreatePresentation {
	public static class Entity {
		// Mnemonic passphrase and the store password should set by the end user.
		private final static String passphrase = "mypassphrase";
		private final static String storepass = "mypassword";

		private String name;
		private DIDStore store;
		private DID did;

		protected Entity(String name) throws DIDException {
			this.name = name;

			initRootIdentity();
			initDid();
		}

		protected void initRootIdentity() throws DIDException {
			final String storePath = System.getProperty("java.io.tmpdir")
					+ File.separator + name + ".store";

			store = DIDStore.open(storePath);

			// Check the store whether contains the root private identity.
			if (store.containsRootIdentities())
				return; // Already exists

			// Create a mnemonic use default language(English).
			Mnemonic mg = Mnemonic.getInstance();
			String mnemonic = mg.generate();

			System.out.format("[%s] Please write down your mnemonic and passwords:%n", name);
			System.out.println("  Mnemonic: " + mnemonic);
			System.out.println("  Mnemonic passphrase: " + passphrase);
			System.out.println("  Store password: " + storepass);

			// Initialize the root identity.
			RootIdentity.create(mnemonic, passphrase, store, storepass);
		}

		protected void initDid() throws DIDException {
			// Check the DID store already contains owner's DID(with private key).
			List<DID> dids = store.listDids((did) -> {
				try {
					return (store.containsPrivateKeys(did) && did.getMetadata().getAlias().equals("me"));
				} catch (DIDException e) {
					return false;
				}
			});

			if (dids.size() > 0) {
				did = dids.get(0);
				return; // Already create my DID.
			}

			RootIdentity id = store.loadRootIdentity();
			DIDDocument doc = id.newDid(storepass);
			doc.getMetadata().setAlias("me");
			System.out.println("My new DID created: " + doc.getSubject());
			doc.publish(storepass);
			did = doc.getSubject();
		}

		protected DIDStore getDIDStore() {
			return store;
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

		public VerifiablePresentation createPresentation(String realm, String nonce) throws DIDException {
			VerifiablePresentation.Builder vpb = VerifiablePresentation.createFor(getDid(), getDIDStore());

			return vpb.credentials(vcs.toArray(new VerifiableCredential[vcs.size()]))
				.realm(realm)
				.nonce(nonce)
				.seal(getStorePassword());
		}
	}

	public static void main(String args[]) {
		try {
			// Initializa the DID backend globally.
			DIDBackend.initialize(new AssistAdapter("mainnet"));

			University university = new University("Elastos");
			Student student = new Student("John Smith", "Male", "johnsmith@example.org");

			VerifiableCredential vc = university.issueDiplomaFor(student);
			System.out.println("The diploma credential:");
			System.out.println("  " + vc);
			System.out.println("  Genuine: " + vc.isGenuine());
			System.out.println("  Expired: " + vc.isExpired());
			System.out.println("  Valid: " + vc.isValid());
			student.addCredential(vc);

			vc = student.createSelfProclaimedCredential();
			System.out.println("The profile credential:");
			System.out.println("  " + vc);
			System.out.println("  Genuine: " + vc.isGenuine());
			System.out.println("  Expired: " + vc.isExpired());
			System.out.println("  Valid: " + vc.isValid());
			student.addCredential(vc);

			VerifiablePresentation vp = student.createPresentation("test", "873172f58701a9ee686f0630204fee59");
			System.out.println("The verifiable presentation:");
			System.out.println("  " + vp);
			System.out.println("  Genuine: " + vp.isGenuine());
			System.out.println("  Valid: " + vp.isValid());
		} catch (DIDException e) {
			e.printStackTrace();
		}
	}
}
