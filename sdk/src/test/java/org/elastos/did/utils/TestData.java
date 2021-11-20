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

package org.elastos.did.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import org.elastos.did.DID;
import org.elastos.did.DIDBackend;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.DIDURL;
import org.elastos.did.Issuer;
import org.elastos.did.Mnemonic;
import org.elastos.did.RootIdentity;
import org.elastos.did.TransferTicket;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.VerifiablePresentation;
import org.elastos.did.backend.Web3Adapter;
import org.elastos.did.crypto.HDKey;
import org.elastos.did.exception.DIDException;

public final class TestData {
	// HDKey for temporary key generation
	private static HDKey rootKey;
	private static int index;

	private DIDStore store;
	private String mnemonic;
	private RootIdentity identity;

	private CompatibleData v1;
	private CompatibleData v2;
	private CompatibleData v2_2;
	private InstantData instantData;

	public TestData() throws DIDException {
    	Utils.deleteFile(new File(TestConfig.storeRoot));
		store = DIDStore.open(TestConfig.storeRoot);
	}

	public void cleanup() {
		if (store != null)
			store.close();

		DIDTestExtension.resetData();
		DIDBackend.getInstance().clearCache();
	}

	public static synchronized HDKey generateKeypair()
			throws DIDException {
		if (rootKey == null) {
	    	String mnemonic =  Mnemonic.getInstance().generate();
	    	rootKey = new HDKey(mnemonic, "");
	    	index = 0;
		}

		return rootKey.derive(HDKey.DERIVE_PATH_PREFIX + index++);
	}

	public DIDStore getStore() {
    	return store;
	}

	public DIDStore reOpenStore() throws DIDException {
		if (store != null)
			store.close();

		store = DIDStore.open(TestConfig.storeRoot);
		return store;
	}

	public synchronized RootIdentity getRootIdentity() throws DIDException {
		if (identity == null) {
	    	mnemonic =  Mnemonic.getInstance().generate();
	    	identity = RootIdentity.create(mnemonic, TestConfig.passphrase,
	    			true, store, TestConfig.storePass);
		}

    	return identity;
	}

	public String getMnemonic() {
		return mnemonic;
	}

	public CompatibleData getCompatibleData(String version) {
		switch (version) {
		case "1":
			if (v1 == null)
				v1 = new CompatibleData(version);
			return v1;

		case "2":
			if (v2 == null)
				v2 = new CompatibleData(version);
			return v2;

		case "2.2":
			if (v2_2 == null)
				v2_2 = new CompatibleData(version);
			return v2_2;

		default:
			throw new IllegalArgumentException("Unsupported version");
		}
	}

	public InstantData getInstantData() {
		if (instantData == null)
			instantData = new InstantData();

		return instantData;
	}

	public void waitForWalletAvaliable() throws DIDException {
		// need synchronize?
		if (DIDTestExtension.getAdapter() instanceof Web3Adapter) {
			Web3Adapter adapter = (Web3Adapter)DIDTestExtension.getAdapter();

			System.out.print("Waiting for wallet available...");
			long start = System.currentTimeMillis();
			while (true) {
				if (adapter.isAvailable()) {
					long duration = (System.currentTimeMillis() - start + 500) / 1000;
					System.out.println("OK(" + duration + "s)");
					break;
				}

				try {
					Thread.sleep(5000);
				} catch (InterruptedException ignore) {
				}
			}
		}
	}

	public class CompatibleData {
		private File dataPath;
		private File storePath;
		private Map<String, Object> data;
		private String version;

		public CompatibleData(String version) {
			this.data = new HashMap<String, Object>();

			URL url = this.getClass().getResource("/v" + version);
			File root = new File(url.getPath());

			this.dataPath = new File(root, "/testdata");
			this.storePath = new File(root, "/teststore");
			this.version = version;
		}

		public boolean isLatestVersion() {
			return Float.valueOf(version) >= 2.0;
		}

		private File getDidFile(String name, String type) {
			StringBuffer fileName = new StringBuffer();
			fileName.append(name).append(".id");
			if (type != null)
				fileName.append(".").append(type);
			fileName.append(".json");

			return new File(dataPath, fileName.toString());
		}

		private File getCredentialFile(String did, String vc, String type) {
			StringBuffer fileName = new StringBuffer();
			fileName.append(did).append(".vc.").append(vc);
			if (type != null)
				fileName.append(".").append(type);
			fileName.append(".json");

			return new File(dataPath, fileName.toString());
		}

		private File getPresentationFile(String did, String vp, String type) {
			StringBuffer fileName = new StringBuffer();
			fileName.append(did).append(".vp.").append(vp);
			if (type != null)
				fileName.append(".").append(type);
			fileName.append(".json");

			return new File(dataPath, fileName.toString());
		}

		private File getTransferTicketFile(String name) {
			if (Float.valueOf(version) < 2.0)
				return null;

			return new File(dataPath, name + ".tt.json");
		}

		private String loadText(File file) throws IOException {
			StringBuilder text = new StringBuilder();
			char[] buffer = new char[1024];
			int len;

			BufferedReader input = new BufferedReader(new FileReader(file));
			while ((len = input.read(buffer)) >= 0)
				text.append(buffer, 0, len);

			input.close();

			return text.toString();
		}

		public synchronized DIDDocument getDocument(String did, String type)
				throws DIDException, IOException {
			String baseKey = "res:did:" + did;
			String key = type != null ? baseKey + ":" + type : baseKey;
			if (data.containsKey(key))
				return (DIDDocument)data.get(key);

			// load the document
			DIDDocument doc = DIDDocument.parse(getDidFile(did, type));

			if (!data.containsKey(baseKey)) {
				// If not stored before, store it and load private keys
				store.storeDid(doc);
				File[] kfs = dataPath.listFiles((d, f) -> {
					return (f.startsWith(did + ".id.") && f.endsWith(".sk"));
				});

				for (File kf : kfs) {
					int start = did.length() + 4;
					int end = kf.getName().length() - 3;
					String fragment = kf.getName().substring(start, end);
					DIDURL id = new DIDURL(doc.getSubject(), "#" + fragment);

					byte[] sk = HDKey.deserializeBase58(loadText(kf)).serialize();
					store.storePrivateKey(id, sk, TestConfig.storePass);
				}

				switch (did) {
				case "foobar":
				case "foo":
				case "bar":
				case "baz":
					doc.publish(getDocument("user1").getDefaultPublicKeyId(), TestConfig.storePass);
					break;

				default:
					doc.publish(TestConfig.storePass);
				}
			}

			data.put(key, doc);
			return doc;
		}

		public DIDDocument getDocument(String did)
				throws DIDException, IOException {
			return getDocument(did, null);
		}

		public synchronized String getDocumentJson(String did, String type)
				throws IOException {
			File file = getDidFile(did, type);
			String key = "res:json:" + file.getName();
			if (data.containsKey(key))
				return (String)data.get(key);

			// load the document
			String text = loadText(file);
			data.put(key, text);
			return text;
		}

		public synchronized VerifiableCredential getCredential(String did, String vc, String type)
				throws DIDException, IOException {
			// Load DID document first for verification
			getDocument(did);

			String baseKey = "res:vc:" + did + ":" + vc;
			String key = type != null ? baseKey + ":" + type : baseKey;
			if (data.containsKey(key))
				return (VerifiableCredential)data.get(key);

			// load the credential
			VerifiableCredential credential = VerifiableCredential.parse(
					getCredentialFile(did, vc, type));

			// If not stored before, store it
			if (!data.containsKey(baseKey))
				store.storeCredential(credential);

			data.put(key, credential);
			return credential;
		}

		public VerifiableCredential getCredential(String did, String vc)
				throws DIDException, IOException {
			return getCredential(did, vc, null);
		}

		public synchronized String getCredentialJson(String did, String vc, String type)
				throws IOException {
			File file = getCredentialFile(did, vc, type);
			String key = "res:json:" + file.getName();
			if (data.containsKey(key))
				return (String)data.get(key);

			// load the document
			String text = loadText(file);
			data.put(key, text);
			return text;
		}

		public synchronized VerifiablePresentation getPresentation(String did, String vp, String type)
				throws DIDException, IOException {
			// Load DID document first for verification
			getDocument(did);

			String baseKey = "res:vp:" + did + ":" + vp;
			String key = type != null ? baseKey + ":" + type : baseKey;
			if (data.containsKey(key))
				return (VerifiablePresentation)data.get(key);

			// load the presentation
			VerifiablePresentation presentation = VerifiablePresentation.parse(
					getPresentationFile(did, vp, type));

			data.put(key, presentation);
			return presentation;
		}

		public VerifiablePresentation getPresentation(String did, String vp)
				throws DIDException, IOException {
			return getPresentation(did, vp, null);
		}

		public synchronized String getPresentationJson(String did, String vp, String type)
				throws IOException {
			File file = getPresentationFile(did, vp, type);
			String key = "res:json:" + file.getName();
			if (data.containsKey(key))
				return (String)data.get(key);

			// load the document
			String text = loadText(file);
			data.put(key, text);
			return text;
		}

		public TransferTicket getTransferTicket(String did)
				throws DIDException, IOException {
			if (Float.valueOf(version) < 2.0)
				throw new IOException("Not exists");

			String key = "res:tt:" + did;
			if (data.containsKey(key))
				return (TransferTicket)data.get(key);

			// load the presentation
			TransferTicket tt = TransferTicket.parse(getTransferTicketFile(did));

			data.put(key, tt);
			return tt;
		}

		public File getStoreDir() {
			return storePath;
		}

		public void loadAll() throws DIDException, IOException {
			getDocument("issuer");
			getDocument("user1");
			getDocument("user2");
			getDocument("user3");

			if (Float.valueOf(version) >= 2.0) {
				getDocument("user4");
				getDocument("examplecorp");
				getDocument("foobar");
				getDocument("foo");
				getDocument("bar");
				getDocument("baz");
			}
		}
	}

	public class InstantData {
		private DIDDocument idIssuer;
		private DIDDocument idUser1;
		private DIDDocument idUser2;
		private DIDDocument idUser3;
		private DIDDocument idUser4;

		private VerifiableCredential vcUser1Passport;	// Issued by idIssuer
		private VerifiableCredential vcUser1Twitter;	// Self-proclaimed
		private VerifiableCredential vcUser1Json;		// Issued by idIssuer with complex JSON subject
		private VerifiablePresentation vpUser1Nonempty;
		private VerifiablePresentation vpUser1Empty;

		private DIDDocument idExampleCorp; 	// Controlled by idIssuer
		private DIDDocument idFooBar; 		// Controlled by User1, User2, User3 (2/3)
		private DIDDocument idFoo; 			// Controlled by User1, User2 (2/2)
		private DIDDocument idBar;			// Controlled by User1, User2, User3 (3/3)
		private DIDDocument idBaz;			// Controlled by User1, User2, User3 (1/3)

		private VerifiableCredential vcFooBarServices;	// Self-proclaimed
		private VerifiableCredential vcFooBarLicense;	// Issued by idExampleCorp
		private VerifiableCredential vcFooEmail;		// Issued by idIssuer

		private VerifiablePresentation vpFooBarNonempty;
		private VerifiablePresentation vpFooBarEmpty;

		private VerifiableCredential vcUser1JobPosition;// Issued by idExampleCorp

		private TransferTicket ttFooBar;
		private TransferTicket ttBaz;

		public synchronized DIDDocument getIssuerDocument() throws DIDException {
			if (idIssuer == null) {
				getRootIdentity();

				DIDDocument doc = identity.newDid(TestConfig.storePass);
				doc.getMetadata().setAlias("Issuer");

				Issuer selfIssuer = new Issuer(doc);
				VerifiableCredential.Builder cb = selfIssuer.issueFor(doc.getSubject());

				Map<String, Object> props = new HashMap<String, Object>();
				props.put("name", "Test Issuer");
				props.put("gender", "Male");
				props.put("nationality", "Singapore");
				props.put("email", "issuer@example.com");

				VerifiableCredential vc = cb.id("#profile")
						.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
						.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
						.properties(props)
						.seal(TestConfig.storePass);

				DIDDocument.Builder db = doc.edit();
				db.addCredential(vc);

				HDKey key = TestData.generateKeypair();
		 		DIDURL id = new DIDURL(doc.getSubject(), "#key2");
		 		db.addAuthenticationKey(id, key.getPublicKeyBase58());
		 		store.storePrivateKey(id, key.serialize(), TestConfig.storePass);

		 		// No private key for testKey
				key = TestData.generateKeypair();
				id = new DIDURL(doc.getSubject(), "#testKey");
		 		db.addAuthenticationKey(id, key.getPublicKeyBase58());

		 		// No private key for recovery
				key = TestData.generateKeypair();
				id = new DIDURL(doc.getSubject(), "#recovery");
		 		db.addAuthorizationKey(id, new DID("did:elastos:" + key.getAddress()),
		 				key.getPublicKeyBase58());

				doc = db.seal(TestConfig.storePass);
				store.storeDid(doc);
				doc.publish(TestConfig.storePass);

				idIssuer = doc;
			}

			return idIssuer;
		}

		public synchronized DIDDocument getUser1Document() throws DIDException {
			if (idUser1 == null) {
				getIssuerDocument();

				DIDDocument doc = identity.newDid(TestConfig.storePass);
				doc.getMetadata().setAlias("User1");

				// Test document with two embedded credentials
				DIDDocument.Builder db = doc.edit();

				HDKey temp = TestData.generateKeypair();
				db.addAuthenticationKey("#key2", temp.getPublicKeyBase58());
				store.storePrivateKey(new DIDURL(doc.getSubject(), "#key2"),
						temp.serialize(), TestConfig.storePass);

				temp = TestData.generateKeypair();
				db.addAuthenticationKey("#key3", temp.getPublicKeyBase58());
				store.storePrivateKey(new DIDURL(doc.getSubject(), "#key3"),
						temp.serialize(), TestConfig.storePass);

				temp = TestData.generateKeypair();
				db.addAuthorizationKey("#recovery",
						"did:elastos:" + temp.getAddress(),
						temp.getPublicKeyBase58());

				db.addService("#openid", "OpenIdConnectVersion1.0Service",
						"https://openid.example.com/");
				db.addService("#vcr", "CredentialRepositoryService",
						"https://did.example.com/credentials");

				Map<String, Object> map = new HashMap<String, Object>();
				map.put("abc", "helloworld");
				map.put("foo", 123);
				map.put("bar", "foobar");
				map.put("foobar", "lalala...");
				map.put("date", Calendar.getInstance().getTime());
				map.put("ABC", "Helloworld");
				map.put("FOO", 678);
				map.put("BAR", "Foobar");
				map.put("FOOBAR", "Lalala...");
				map.put("DATE", Calendar.getInstance().getTime());

				Map<String, Object> props = new HashMap<String, Object>();
				props.put("abc", "helloworld");
				props.put("foo", 123);
				props.put("bar", "foobar");
				props.put("foobar", "lalala...");
				props.put("date", Calendar.getInstance().getTime());
				props.put("map", map);
				props.put("ABC", "Helloworld");
				props.put("FOO", 678);
				props.put("BAR", "Foobar");
				props.put("FOOBAR", "Lalala...");
				props.put("DATE", Calendar.getInstance().getTime());
				props.put("MAP", map);

				db.addService("#carrier", "CarrierAddress",
						"carrier://X2tDd1ZTErwnHNot8pTdhp7C7Y9FxMPGD8ppiasUT4UsHH2BpF1d", map);

				Issuer selfIssuer = new Issuer(doc);
				VerifiableCredential.Builder cb = selfIssuer.issueFor(doc.getSubject());

				props = new HashMap<String, Object>();
				props.put("name", "John");
				props.put("gender", "Male");
				props.put("nationality", "Singapore");
				props.put("email", "john@example.com");
				props.put("twitter", "@john");

				VerifiableCredential vcProfile = cb.id("#profile")
						.type("https://ns.elastos.org/credentials/v1#SelfProclaimedCredential")
						.type("https://ns.elastos.org/credentials/profile/v1#ProfileCredential")
						.type("EmailCredential", "https://ns.elastos.org/credentials/email/v1")
						.type("SocialCredential", "https://ns.elastos.org/credentials/social/v1")
						.properties(props)
						.seal(TestConfig.storePass);

				Issuer kycIssuer = new Issuer(idIssuer);
				cb = kycIssuer.issueFor(doc.getSubject());

				props.clear();
				props.put("email", "john@example.com");

				VerifiableCredential vcEmail = cb.id("#email")
						.type("EmailCredential", "https://ns.elastos.org/credentials/email/v1")
						.properties(props)
						.seal(TestConfig.storePass);

				db.addCredential(vcProfile);
				db.addCredential(vcEmail);
				doc = db.seal(TestConfig.storePass);
				store.storeDid(doc);
				doc.publish(TestConfig.storePass);

				idUser1 = doc;
			}

			return idUser1;
		}

		public synchronized VerifiableCredential getUser1PassportCredential() throws DIDException {
			if (vcUser1Passport == null) {
				DIDDocument doc = getUser1Document();

				DIDURL id = new DIDURL(doc.getSubject(), "#passport");

				Issuer selfIssuer = new Issuer(doc);
				VerifiableCredential.Builder cb = selfIssuer.issueFor(doc.getSubject());

				Map<String, Object> props = new HashMap<String, Object>();
				props.put("nationality", "Singapore");
				props.put("passport", "S653258Z07");

				VerifiableCredential vcPassport = cb.id(id)
						.type("https://ns.elastos.org/credentials/v1#SelfProclaimedCredential")
						.properties(props)
						.seal(TestConfig.storePass);
				vcPassport.getMetadata().setAlias("Passport");
				store.storeCredential(vcPassport);

				vcUser1Passport = vcPassport;
			}

			return vcUser1Passport;
		}

		public synchronized VerifiableCredential getUser1TwitterCredential() throws DIDException {
			if (vcUser1Twitter == null) {
				DIDDocument doc = getUser1Document();

				DIDURL id = new DIDURL(doc.getSubject(), "#twitter");

				Issuer kycIssuer = new Issuer(idIssuer);
				VerifiableCredential.Builder cb = kycIssuer.issueFor(doc.getSubject());

				Map<String, Object> props = new HashMap<String, Object>();
				props.put("twitter", "@john");

				VerifiableCredential vcTwitter = cb.id(id)
						.type("SocialCredential", "https://ns.elastos.org/credentials/social/v1")
						.properties(props)
						.seal(TestConfig.storePass);
				vcTwitter.getMetadata().setAlias("Twitter");
				store.storeCredential(vcTwitter);

				vcUser1Twitter = vcTwitter;
			}

			return vcUser1Twitter;
		}

		public synchronized VerifiableCredential getUser1JsonCredential() throws DIDException {
			if (vcUser1Json == null) {
				DIDDocument doc = getUser1Document();

				DIDURL id = new DIDURL(doc.getSubject(), "#json");

				Issuer kycIssuer = new Issuer(idIssuer);
				VerifiableCredential.Builder cb = kycIssuer.issueFor(doc.getSubject());

				String jsonProps = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\",\"booleanValue\":true,\"numberValue\":1234,\"doubleValue\":9.5,\"nationality\":\"Canadian\",\"birthPlace\":{\"type\":\"Place\",\"address\":{\"type\":\"PostalAddress\",\"addressLocality\":\"Vancouver\",\"addressRegion\":\"BC\",\"addressCountry\":\"Canada\"}},\"affiliation\":[{\"type\":\"Organization\",\"name\":\"Futurpreneur\",\"sameAs\":[\"https://twitter.com/futurpreneur\",\"https://www.facebook.com/futurpreneur/\",\"https://www.linkedin.com/company-beta/100369/\",\"https://www.youtube.com/user/CYBF\"]}],\"alumniOf\":[{\"type\":\"CollegeOrUniversity\",\"name\":\"Vancouver Film School\",\"sameAs\":\"https://en.wikipedia.org/wiki/Vancouver_Film_School\",\"year\":2000},{\"type\":\"CollegeOrUniversity\",\"name\":\"CodeCore Bootcamp\"}],\"gender\":\"Male\",\"Description\":\"Technologist\",\"disambiguatingDescription\":\"Co-founder of CodeCore Bootcamp\",\"jobTitle\":\"Technical Director\",\"worksFor\":[{\"type\":\"Organization\",\"name\":\"Skunkworks Creative Group Inc.\",\"sameAs\":[\"https://twitter.com/skunkworks_ca\",\"https://www.facebook.com/skunkworks.ca\",\"https://www.linkedin.com/company/skunkworks-creative-group-inc-\",\"https://plus.google.com/+SkunkworksCa\"]}],\"url\":\"https://jay.holtslander.ca\",\"image\":\"https://s.gravatar.com/avatar/961997eb7fd5c22b3e12fb3c8ca14e11?s=512&r=g\",\"address\":{\"type\":\"PostalAddress\",\"addressLocality\":\"Vancouver\",\"addressRegion\":\"BC\",\"addressCountry\":\"Canada\"},\"sameAs\":[\"https://twitter.com/j_holtslander\",\"https://pinterest.com/j_holtslander\",\"https://instagram.com/j_holtslander\",\"https://www.facebook.com/jay.holtslander\",\"https://ca.linkedin.com/in/holtslander/en\",\"https://plus.google.com/+JayHoltslander\",\"https://www.youtube.com/user/jasonh1234\",\"https://github.com/JayHoltslander\",\"https://profiles.wordpress.org/jasonh1234\",\"https://angel.co/j_holtslander\",\"https://www.foursquare.com/user/184843\",\"https://jholtslander.yelp.ca\",\"https://codepen.io/j_holtslander/\",\"https://stackoverflow.com/users/751570/jay\",\"https://dribbble.com/j_holtslander\",\"http://jasonh1234.deviantart.com/\",\"https://www.behance.net/j_holtslander\",\"https://www.flickr.com/people/jasonh1234/\",\"https://medium.com/@j_holtslander\"]}";

				VerifiableCredential vcJson = cb.id(id)
						.properties(jsonProps)
						.seal(TestConfig.storePass);
				vcJson.getMetadata().setAlias("json");
				store.storeCredential(vcJson);

				vcUser1Json = vcJson;
			}

			return vcUser1Json;
		}

		public synchronized VerifiableCredential getUser1JobPositionCredential() throws DIDException {
			if (vcUser1JobPosition == null) {
				getExampleCorpDocument();

				DIDDocument doc = getUser1Document();

				DIDURL id = new DIDURL(doc.getSubject(), "#email");

				Issuer kycIssuer = new Issuer(idExampleCorp);
				VerifiableCredential.Builder cb = kycIssuer.issueFor(doc.getSubject());

				Map<String, Object> props = new HashMap<String, Object>();
				props.put("title", "CEO");

				VerifiableCredential vc = cb.id(id)
						.type("JobPositionCredential", "https://example.com/credentials/v1")
						.properties(props)
						.seal(TestConfig.storePass);
				store.storeCredential(vc);

				vcUser1JobPosition = vc;
			}

			return vcUser1JobPosition;
		}

		public synchronized VerifiablePresentation getUser1NonemptyPresentation() throws DIDException {
			if (vpUser1Nonempty == null) {
				DIDDocument doc = getUser1Document();

				VerifiablePresentation.Builder pb = VerifiablePresentation.createFor(
						doc.getSubject(), store);

				VerifiablePresentation vp = pb
						.credentials(doc.getCredential("#profile"), doc.getCredential("#email"))
						.credentials(getUser1PassportCredential())
						.credentials(getUser1TwitterCredential())
						.credentials(getUser1JobPositionCredential())
						.realm("https://example.com/")
						.nonce("873172f58701a9ee686f0630204fee59")
						.seal(TestConfig.storePass);

				vpUser1Nonempty = vp;
			}

			return vpUser1Nonempty;
		}

		public synchronized VerifiablePresentation getUser1EmptyPresentation() throws DIDException {
			if (vpUser1Empty == null) {
				DIDDocument doc = getUser1Document();

				VerifiablePresentation.Builder pb = VerifiablePresentation.createFor(
						doc.getSubject(), store);

				VerifiablePresentation vp = pb.realm("https://example.com/")
						.nonce("873172f58701a9ee686f0630204fee59")
						.seal(TestConfig.storePass);

				vpUser1Empty = vp;
			}

			return vpUser1Empty;
		}

		public synchronized DIDDocument getUser2Document() throws DIDException {
			if (idUser2 == null) {
				DIDDocument doc = identity.newDid(TestConfig.storePass);
				doc.getMetadata().setAlias("User2");

				DIDDocument.Builder db = doc.edit();

				Map<String, Object> props = new HashMap<String, Object>();
				props.put("name", "John");
				props.put("gender", "Male");
				props.put("nationality", "Singapore");
				props.put("email", "john@example.com");
				props.put("twitter", "@john");

				String[] types = {
						"https://ns.elastos.org/credentials/v1#SelfProclaimedCredential",
						"https://ns.elastos.org/credentials/profile/v1#ProfileCredential",
						"https://ns.elastos.org/credentials/email/v1#EmailCredential",
						"https://ns.elastos.org/credentials/social/v1#SocialCredential"
					};

				db.addCredential("#profile", types, props, TestConfig.storePass);
				doc = db.seal(TestConfig.storePass);
				store.storeDid(doc);
				doc.publish(TestConfig.storePass);

				idUser2 = doc;
			}

			return idUser2;
		}

		public synchronized DIDDocument getUser3Document() throws DIDException {
			if (idUser3 == null) {
				DIDDocument doc = identity.newDid(TestConfig.storePass);
				doc.getMetadata().setAlias("User3");
				doc.publish(TestConfig.storePass);

				idUser3 = doc;
			}

			return idUser3;
		}

		public synchronized DIDDocument getUser4Document() throws DIDException {
			if (idUser4 == null) {
				DIDDocument doc = identity.newDid(TestConfig.storePass);
				doc.getMetadata().setAlias("User4");
				doc.publish(TestConfig.storePass);

				idUser4 = doc;
			}

			return idUser4;
		}

		public synchronized DIDDocument getExampleCorpDocument() throws DIDException {
			if (idExampleCorp == null) {
				getIssuerDocument();

				DID did = new DID("did:elastos:example");
				DIDDocument doc = idIssuer.newCustomizedDid(did, TestConfig.storePass);

				Issuer selfIssuer = new Issuer(doc);
				VerifiableCredential.Builder cb = selfIssuer.issueFor(doc.getSubject());

				Map<String, Object> props = new HashMap<String, Object>();
				props.put("name", "Example LLC");
				props.put("url", "https://example.com/");
				props.put("email", "contact@example.com");

				VerifiableCredential vc = cb.id("#profile")
						.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
						.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
						.type("EmailCredential", "https://ns.elastos.org/credentials/email/v1")
						.properties(props)
						.seal(TestConfig.storePass);

				DIDDocument.Builder db = doc.edit();
				db.addCredential(vc);

				HDKey key = TestData.generateKeypair();
		 		DIDURL id = new DIDURL(doc.getSubject(), "#key2");
		 		db.addAuthenticationKey(id, key.getPublicKeyBase58());
		 		store.storePrivateKey(id, key.serialize(), TestConfig.storePass);

		 		// No private key for testKey
				key = TestData.generateKeypair();
				id = new DIDURL(doc.getSubject(), "#testKey");
		 		db.addAuthenticationKey(id, key.getPublicKeyBase58());

				doc = db.seal(TestConfig.storePass);
				store.storeDid(doc);
				doc.publish(TestConfig.storePass);

				idExampleCorp = doc;
			}

			return idExampleCorp;
		}

		public synchronized DIDDocument getFooBarDocument() throws DIDException {
			if (idFooBar == null) {
				getExampleCorpDocument();
				getUser1Document();
				getUser2Document();
				getUser3Document();

				DID[] controllers = {idUser1.getSubject(), idUser2.getSubject(), idUser3.getSubject()};
				DID did = new DID("did:elastos:foobar");
				DIDDocument doc = idUser1.newCustomizedDid(did, controllers, 2, TestConfig.storePass);
				DIDURL signKey = idUser1.getDefaultPublicKeyId();

				// Add public keys embedded credentials
				DIDDocument.Builder db = doc.edit(idUser1);

				HDKey temp = TestData.generateKeypair();
				db.addAuthenticationKey("#key2", temp.getPublicKeyBase58());
				store.storePrivateKey(new DIDURL(doc.getSubject(), "#key2"),
						temp.serialize(), TestConfig.storePass);

				temp = TestData.generateKeypair();
				db.addAuthenticationKey("#key3", temp.getPublicKeyBase58());
				store.storePrivateKey(new DIDURL(doc.getSubject(), "#key3"),
						temp.serialize(), TestConfig.storePass);

				db.addService("#vault", "Hive.Vault.Service",
						"https://foobar.com/vault");

				Map<String, Object> map = new HashMap<String, Object>();
				map.put("abc", "helloworld");
				map.put("foo", 123);
				map.put("bar", "foobar");
				map.put("foobar", "lalala...");
				map.put("date", Calendar.getInstance().getTime());
				map.put("ABC", "Helloworld");
				map.put("FOO", 678);
				map.put("BAR", "Foobar");
				map.put("FOOBAR", "Lalala...");
				map.put("DATE", Calendar.getInstance().getTime());

				Map<String, Object> props = new HashMap<String, Object>();
				props.put("abc", "helloworld");
				props.put("foo", 123);
				props.put("bar", "foobar");
				props.put("foobar", "lalala...");
				props.put("date", Calendar.getInstance().getTime());
				props.put("map", map);
				props.put("ABC", "Helloworld");
				props.put("FOO", 678);
				props.put("BAR", "Foobar");
				props.put("FOOBAR", "Lalala...");
				props.put("DATE", Calendar.getInstance().getTime());
				props.put("MAP", map);

				db.addService("#vcr", "CredentialRepositoryService",
						"https://foobar.com/credentials", props);

				Issuer selfIssuer = new Issuer(doc, signKey);
				VerifiableCredential.Builder cb = selfIssuer.issueFor(doc.getSubject());

				props = new HashMap<String, Object>();
				props.put("name", "Foo Bar Inc");
				props.put("nationality", "China");
				props.put("email", "contact@foobar.com");

				VerifiableCredential vcProfile = cb.id("#profile")
						.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
						.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
						.type("EmailCredential", "https://ns.elastos.org/credentials/email/v1")
						.properties(props)
						.seal(TestConfig.storePass);

				Issuer kycIssuer = new Issuer(idExampleCorp);
				cb = kycIssuer.issueFor(doc.getSubject());

				props.clear();
				props.put("email", "foobar@example.com");

				VerifiableCredential vcEmail = cb.id("#email")
						.type("EmailCredential", "https://ns.elastos.org/credentials/email/v1")
						.properties(props)
						.seal(TestConfig.storePass);

				db.addCredential(vcProfile);
				db.addCredential(vcEmail);
				doc = db.seal(TestConfig.storePass);
				doc = idUser3.sign(doc, TestConfig.storePass);
				store.storeDid(doc);
				doc.publish(signKey, TestConfig.storePass);

				idFooBar = doc;
			}

			return idFooBar;
		}

		public synchronized VerifiableCredential getFooBarServiceCredential() throws DIDException {
			if (vcFooBarServices == null) {
				DIDDocument doc = getFooBarDocument();

				DIDURL id = new DIDURL(doc.getSubject(), "#services");

				Issuer selfIssuer = new Issuer(doc, idUser1.getDefaultPublicKeyId());
				VerifiableCredential.Builder cb = selfIssuer.issueFor(doc.getSubject());

				Map<String, Object> props = new HashMap<String, Object>();
				props.put("consultation", "https://foobar.com/consultation");
				props.put("Outsourceing", "https://foobar.com/outsourcing");

				VerifiableCredential vc = cb.id(id)
						.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
						.properties(props)
						.seal(TestConfig.storePass);
				store.storeCredential(vc);

				vcFooBarServices = vc;
			}

			return vcFooBarServices;
		}

		public synchronized VerifiableCredential getFooBarLicenseCredential() throws DIDException {
			if (vcFooBarLicense == null) {
				getExampleCorpDocument();
				getUser1Document();
				getUser2Document();
				getUser3Document();

				DIDDocument doc = getFooBarDocument();

				DIDURL id = new DIDURL(doc.getSubject(), "#license");

				Issuer kycIssuer = new Issuer(idExampleCorp);
				VerifiableCredential.Builder cb = kycIssuer.issueFor(doc.getSubject());

				Map<String, Object> props = new HashMap<String, Object>();
				props.put("license-id", "20201021C889");
				props.put("scope", "Consulting");

				VerifiableCredential vc = cb.id(id)
						.type("LicenseCredential", "https://example.com/credentials/license/v1")
						.properties(props)
						.seal(TestConfig.storePass);
				store.storeCredential(vc);

				vcFooBarLicense = vc;
			}

			return vcFooBarLicense;
		}

		public synchronized VerifiablePresentation getFooBarNonemptyPresentation() throws DIDException {
			if (vpFooBarNonempty == null) {
				DIDDocument doc = getFooBarDocument();

				VerifiablePresentation.Builder pb = VerifiablePresentation.createFor(
						doc.getSubject(), idUser1.getDefaultPublicKeyId(), store);

				VerifiablePresentation vp = pb
						.credentials(doc.getCredential("#profile"),
								doc.getCredential("#email"))
						.credentials(getFooBarServiceCredential())
						.credentials(getFooBarLicenseCredential())
						.realm("https://example.com/")
						.nonce("873172f58701a9ee686f0630204fee59")
						.seal(TestConfig.storePass);

				vpFooBarNonempty = vp;
			}

			return vpFooBarNonempty;
		}

		public synchronized VerifiablePresentation getFooBarEmptyPresentation() throws DIDException {
			if (vpFooBarEmpty == null) {
				DIDDocument doc = getFooBarDocument();

				VerifiablePresentation.Builder pb = VerifiablePresentation.createFor(
						doc.getSubject(), new DIDURL("did:elastos:foobar#key2"), store);

				VerifiablePresentation vp = pb.realm("https://example.com/")
						.nonce("873172f58701a9ee686f0630204fee59")
						.seal(TestConfig.storePass);

				vpFooBarEmpty = vp;
			}

			return vpFooBarEmpty;
		}

		public synchronized TransferTicket getFooBarTransferTicket() throws DIDException {
			if (ttFooBar == null) {
				DIDDocument doc = getFooBarDocument();
				DIDDocument user4 = getUser4Document();

				TransferTicket tt = idUser1.createTransferTicket(doc.getSubject(), user4.getSubject(), TestConfig.storePass);
				tt = idUser3.sign(tt, TestConfig.storePass);

				ttFooBar = tt;
			}

			return ttFooBar;
		}

		public synchronized DIDDocument getFooDocument() throws DIDException {
			if (idFoo == null) {
				getUser1Document();
				getUser2Document();

				DID[] controllers = {idUser2.getSubject()};
				DID did = new DID("did:elastos:foo");
				DIDDocument doc = idUser1.newCustomizedDid(did, controllers, 2, TestConfig.storePass);
				doc = idUser2.sign(doc, TestConfig.storePass);
				store.storeDid(doc);

				doc.setEffectiveController(idUser2.getSubject());
				doc.publish(TestConfig.storePass);
				doc.setEffectiveController(null);

				idFoo = doc;
			}

			return idFoo;
		}

		public synchronized VerifiableCredential getFooEmailCredential() throws DIDException {
			if (vcFooEmail == null) {
				getIssuerDocument();

				DIDDocument doc = getFooDocument();

				DIDURL id = new DIDURL(doc.getSubject(), "#email");

				Issuer kycIssuer = new Issuer(idIssuer);
				VerifiableCredential.Builder cb = kycIssuer.issueFor(doc.getSubject());

				Map<String, Object> props = new HashMap<String, Object>();
				props.put("email", "foo@example.com");

				VerifiableCredential vc = cb.id(id)
						.type("EmailCredential", "https://ns.elastos.org/credentials/email/v1")
						.properties(props)
						.seal(TestConfig.storePass);
				store.storeCredential(vc);

				vcFooEmail = vc;
			}

			return vcFooEmail;
		}

		public synchronized DIDDocument getBarDocument() throws DIDException {
			if (idBar == null) {
				getUser1Document();
				getUser2Document();
				getUser3Document();

				DID[] controllers = {idUser2.getSubject(), idUser3.getSubject()};
				DID did = new DID("did:elastos:bar");
				DIDDocument doc = idUser1.newCustomizedDid(did, controllers, 3, TestConfig.storePass);
				doc = idUser2.sign(doc, TestConfig.storePass);
				doc = idUser3.sign(doc, TestConfig.storePass);
				store.storeDid(doc);
				doc.publish(idUser3.getDefaultPublicKeyId(), TestConfig.storePass);

				idBar = doc;
			}

			return idBar;
		}

		public synchronized DIDDocument getBazDocument() throws DIDException {
			if (idBaz == null) {
				getUser1Document();
				getUser2Document();
				getUser3Document();

				DID[] controllers = {idUser2.getSubject(), idUser3.getSubject()};
				DID did = new DID("did:elastos:baz");
				DIDDocument doc = idUser1.newCustomizedDid(did, controllers, 1, TestConfig.storePass);
				store.storeDid(doc);
				doc.publish(idUser1.getDefaultPublicKeyId(), TestConfig.storePass);

				idBaz = doc;
			}

			return idBaz;
		}

		public synchronized TransferTicket getBazTransferTicket() throws DIDException {
			if (ttBaz == null) {
				DIDDocument doc = getBazDocument();
				DIDDocument user4 = getUser4Document();

				TransferTicket tt = idUser2.createTransferTicket(doc.getSubject(), user4.getSubject(), TestConfig.storePass);

				ttBaz = tt;
			}

			return ttBaz;
		}

		public DIDDocument getDocument(String did) throws DIDException {
			switch (did) {
			case "issuer":
				return getIssuerDocument();

			case "user1":
				return getUser1Document();

			case "user2":
				return getUser1Document();

			case "user3":
				return getUser1Document();

			case "user4":
				return getUser1Document();

			case "examplecorp":
				return getExampleCorpDocument();

			case "foobar":
				return getFooBarDocument();

			case "foo":
				return getFooDocument();

			case "bar":
				return getBarDocument();

			case "baz":
				return getBazDocument();

			default:
				return null;
			}
		}

		public VerifiableCredential getCredential(String did, String vc) throws DIDException {
			switch (did) {
			case "user1":
				switch (vc) {
				case "passport":
					return getUser1PassportCredential();

				case "twitter":
					return getUser1TwitterCredential();

				case "json":
					return getUser1JsonCredential();

				case "jobposition":
					return getUser1JobPositionCredential();

				default:
					return null;
				}

			case "foobar":
				switch (vc) {
				case "services":
					return getFooBarServiceCredential();

				case "license":
					return getFooBarLicenseCredential();

				default:
					return null;
				}

			case "foo":
				switch (vc) {
				case "email":
					return getFooEmailCredential();

				default:
					return null;
				}

			default:
				return null;
			}
		}

		public VerifiablePresentation getPresentation(String did, String vp) throws DIDException {
			switch (did) {
			case "user1":
				switch (vp) {
				case "nonempty":
					return getUser1NonemptyPresentation();

				case "empty":
					return getUser1EmptyPresentation();

				default:
					return null;
				}

			case "foobar":
				switch (vp) {
				case "nonempty":
					return getFooBarNonemptyPresentation();

				case "empty":
					return getFooBarEmptyPresentation();

				default:
					return null;
				}

			default:
				return null;
			}
		}
	}
}
