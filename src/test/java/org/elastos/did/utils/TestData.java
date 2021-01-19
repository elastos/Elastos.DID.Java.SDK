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
import java.util.HashMap;
import java.util.Map;

import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.DIDURL;
import org.elastos.did.Issuer;
import org.elastos.did.Mnemonic;
import org.elastos.did.RootIdentity;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.VerifiablePresentation;
import org.elastos.did.backend.SPVAdapter;
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
	private InstantData instantData;

	public TestData() throws DIDException {
    	Utils.deleteFile(new File(TestConfig.storeRoot));
		store = DIDStore.open(TestConfig.storeRoot);
	}

	public void cleanup() {
		if (store != null)
			store.close();

		DIDTestExtension.resetData();
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

	public synchronized RootIdentity getRootIdentity() throws DIDException {
		if (identity == null) {
	    	mnemonic =  Mnemonic.getInstance().generate();
	    	identity = RootIdentity.create(Mnemonic.ENGLISH, mnemonic,
	    			TestConfig.passphrase, true, store, TestConfig.storePass);
		}

    	return identity;
	}

	public String getMnemonic() {
		return mnemonic;
	}

	public CompatibleData getCompatibleData(int version) {
		switch (version) {
		case 1:
			if (v1 == null)
				v1 = new CompatibleData(version);
			return v1;

		case 2:
			if (v2 == null)
				v2 = new CompatibleData(version);
			return v2;

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
		if (DIDTestExtension.getAdapter() instanceof SPVAdapter) {
			SPVAdapter spvAdapter = (SPVAdapter)DIDTestExtension.getAdapter();

			System.out.print("Waiting for wallet available...");
			long start = System.currentTimeMillis();
			while (true) {
				try {
					Thread.sleep(30000);
				} catch (InterruptedException ignore) {
				}

				if (spvAdapter.isAvailable()) {
					long duration = (System.currentTimeMillis() - start + 500) / 1000;
					System.out.println("OK(" + duration + "s)");
					break;
				}
			}
		}
	}

	public class CompatibleData {
		File dataPath;
		File storePath;
		private Map<String, Object> data;

		public CompatibleData(int version) {
			this.data = new HashMap<String, Object>();

			URL url = this.getClass().getResource("/v" + version);
			File root = new File(url.getPath());

			this.dataPath = new File(root, "/testdata");
			this.storePath = new File(root, "/teststore");
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

		public synchronized DIDDocument getDIDDocument(String did, String type)
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

				doc.publish(TestConfig.storePass);
			}

			data.put(key, doc);
			return doc;
		}

		public DIDDocument getDIDDocument(String did)
				throws DIDException, IOException {
			return getDIDDocument(did, null);
		}

		public synchronized String getDIDDocumentJson(String did, String type)
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
			getDIDDocument(did);

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

		public synchronized VerifiableCredential getCredential(String did, String vc)
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

		public VerifiablePresentation getPresentation(String did, String vp, String type)
				throws DIDException, IOException {
			// Load DID document first for verification
			getDIDDocument(did);

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

		public File getStoreDir() {
			return storePath;
		}
	}

	public class InstantData {
		private DIDDocument idIssuer;
		private DIDDocument idUser1;
		private DIDDocument idUser2;
		private DIDDocument idUser3;
		private VerifiableCredential vcUser1Passport;
		private VerifiableCredential vcUser1Twitter;
		private VerifiableCredential vcUser1Json;
		private VerifiablePresentation vpUser1Nonempty;
		private VerifiablePresentation vpUser1Empty;

		public synchronized DIDDocument getIssuerDocument() throws DIDException, IOException {
			if (idIssuer == null) {
				getRootIdentity();

				DIDDocument doc = identity.newDid(TestConfig.storePass);
				doc.getMetadata().setAlias("Issuer");

				Issuer selfIssuer = new Issuer(doc);
				VerifiableCredential.Builder cb = selfIssuer.issueFor(doc.getSubject());

				Map<String, Object> props = new HashMap<String, Object>();
				props.put("name", "Test Issuer");
				props.put("nation", "Singapore");
				props.put("language", "English");
				props.put("email", "issuer@example.com");

				VerifiableCredential vc = cb.id("profile")
						.type("BasicProfileCredential", "SelfProclaimedCredential")
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
		 		db.addAuthorizationKey(id, identity.getDid(1000), key.getPublicKeyBase58());

				doc = db.seal(TestConfig.storePass);
				store.storeDid(doc);
				doc.publish(TestConfig.storePass);

				idIssuer = doc;
			}

			return idIssuer;
		}

		public synchronized DIDDocument getUser1Document() throws DIDException, IOException {
			if (idUser1 == null) {
				getIssuerDocument();

				DIDDocument doc = identity.newDid(TestConfig.storePass);
				doc.getMetadata().setAlias("User1");

				// Test document with two embedded credentials
				DIDDocument.Builder db = doc.edit();

				HDKey temp = TestData.generateKeypair();
				db.addAuthenticationKey("key2", temp.getPublicKeyBase58());
				store.storePrivateKey(new DIDURL(doc.getSubject(), "key2"),
						temp.serialize(), TestConfig.storePass);

				temp = TestData.generateKeypair();
				db.addAuthenticationKey("key3", temp.getPublicKeyBase58());
				store.storePrivateKey(new DIDURL(doc.getSubject(), "key3"),
						temp.serialize(), TestConfig.storePass);

				temp = TestData.generateKeypair();
				db.addAuthorizationKey("recovery",
						"did:elastos:" + temp.getAddress(),
						temp.getPublicKeyBase58());

				db.addService("openid", "OpenIdConnectVersion1.0Service",
						"https://openid.example.com/");
				db.addService("vcr", "CredentialRepositoryService",
						"https://did.example.com/credentials");
				db.addService("carrier", "CarrierAddress",
						"carrier://X2tDd1ZTErwnHNot8pTdhp7C7Y9FxMPGD8ppiasUT4UsHH2BpF1d");

				Issuer selfIssuer = new Issuer(doc);
				VerifiableCredential.Builder cb = selfIssuer.issueFor(doc.getSubject());

				Map<String, Object> props = new HashMap<String, Object>();
				props.put("name", "John");
				props.put("gender", "Male");
				props.put("nation", "Singapore");
				props.put("language", "English");
				props.put("email", "john@example.com");
				props.put("twitter", "@john");

				VerifiableCredential vcProfile = cb.id("profile")
						.type("BasicProfileCredential", "SelfProclaimedCredential")
						.properties(props)
						.seal(TestConfig.storePass);

				Issuer kycIssuer = new Issuer(idIssuer);
				cb = kycIssuer.issueFor(doc.getSubject());

				props.clear();
				props.put("email", "john@example.com");

				VerifiableCredential vcEmail = cb.id("email")
						.type("BasicProfileCredential",
								"InternetAccountCredential", "EmailCredential")
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

		public synchronized VerifiableCredential getUser1PassportCredential() throws DIDException, IOException {
			if (vcUser1Passport == null) {
				DIDDocument doc = getUser1Document();

				DIDURL id = new DIDURL(doc.getSubject(), "passport");

				Issuer selfIssuer = new Issuer(doc);
				VerifiableCredential.Builder cb = selfIssuer.issueFor(doc.getSubject());

				Map<String, Object> props = new HashMap<String, Object>();
				props.put("nation", "Singapore");
				props.put("passport", "S653258Z07");

				VerifiableCredential vcPassport = cb.id(id)
						.type("BasicProfileCredential", "SelfProclaimedCredential")
						.properties(props)
						.seal(TestConfig.storePass);
				vcPassport.getMetadata().setAlias("Passport");
				store.storeCredential(vcPassport);

				vcUser1Passport = vcPassport;
			}

			return vcUser1Passport;
		}

		public synchronized VerifiableCredential getUser1TwitterCredential() throws DIDException, IOException {
			if (vcUser1Twitter == null) {
				DIDDocument doc = getUser1Document();

				DIDURL id = new DIDURL(doc.getSubject(), "twitter");

				Issuer kycIssuer = new Issuer(idIssuer);
				VerifiableCredential.Builder cb = kycIssuer.issueFor(doc.getSubject());

				Map<String, Object> props = new HashMap<String, Object>();
				props.put("twitter", "@john");

				VerifiableCredential vcTwitter = cb.id(id)
						.type("InternetAccountCredential", "TwitterCredential")
						.properties(props)
						.seal(TestConfig.storePass);
				vcTwitter.getMetadata().setAlias("Twitter");
				store.storeCredential(vcTwitter);

				vcUser1Twitter = vcTwitter;
			}

			return vcUser1Twitter;
		}

		public synchronized VerifiableCredential getUser1JsonCredential() throws DIDException, IOException {
			if (vcUser1Json == null) {
				DIDDocument doc = getUser1Document();

				DIDURL id = new DIDURL(doc.getSubject(), "json");
				System.out.print("Generate credential: " + id + "...");

				Issuer kycIssuer = new Issuer(idIssuer);
				VerifiableCredential.Builder cb = kycIssuer.issueFor(doc.getSubject());

				String jsonProps = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\",\"booleanValue\":true,\"numberValue\":1234,\"doubleValue\":9.5,\"nationality\":\"Canadian\",\"birthPlace\":{\"type\":\"Place\",\"address\":{\"type\":\"PostalAddress\",\"addressLocality\":\"Vancouver\",\"addressRegion\":\"BC\",\"addressCountry\":\"Canada\"}},\"affiliation\":[{\"type\":\"Organization\",\"name\":\"Futurpreneur\",\"sameAs\":[\"https://twitter.com/futurpreneur\",\"https://www.facebook.com/futurpreneur/\",\"https://www.linkedin.com/company-beta/100369/\",\"https://www.youtube.com/user/CYBF\"]}],\"alumniOf\":[{\"type\":\"CollegeOrUniversity\",\"name\":\"Vancouver Film School\",\"sameAs\":\"https://en.wikipedia.org/wiki/Vancouver_Film_School\",\"year\":2000},{\"type\":\"CollegeOrUniversity\",\"name\":\"CodeCore Bootcamp\"}],\"gender\":\"Male\",\"Description\":\"Technologist\",\"disambiguatingDescription\":\"Co-founder of CodeCore Bootcamp\",\"jobTitle\":\"Technical Director\",\"worksFor\":[{\"type\":\"Organization\",\"name\":\"Skunkworks Creative Group Inc.\",\"sameAs\":[\"https://twitter.com/skunkworks_ca\",\"https://www.facebook.com/skunkworks.ca\",\"https://www.linkedin.com/company/skunkworks-creative-group-inc-\",\"https://plus.google.com/+SkunkworksCa\"]}],\"url\":\"https://jay.holtslander.ca\",\"image\":\"https://s.gravatar.com/avatar/961997eb7fd5c22b3e12fb3c8ca14e11?s=512&r=g\",\"address\":{\"type\":\"PostalAddress\",\"addressLocality\":\"Vancouver\",\"addressRegion\":\"BC\",\"addressCountry\":\"Canada\"},\"sameAs\":[\"https://twitter.com/j_holtslander\",\"https://pinterest.com/j_holtslander\",\"https://instagram.com/j_holtslander\",\"https://www.facebook.com/jay.holtslander\",\"https://ca.linkedin.com/in/holtslander/en\",\"https://plus.google.com/+JayHoltslander\",\"https://www.youtube.com/user/jasonh1234\",\"https://github.com/JayHoltslander\",\"https://profiles.wordpress.org/jasonh1234\",\"https://angel.co/j_holtslander\",\"https://www.foursquare.com/user/184843\",\"https://jholtslander.yelp.ca\",\"https://codepen.io/j_holtslander/\",\"https://stackoverflow.com/users/751570/jay\",\"https://dribbble.com/j_holtslander\",\"http://jasonh1234.deviantart.com/\",\"https://www.behance.net/j_holtslander\",\"https://www.flickr.com/people/jasonh1234/\",\"https://medium.com/@j_holtslander\"]}";

				VerifiableCredential vcJson = cb.id(id)
						.type("TestCredential", "JsonCredential")
						.properties(jsonProps)
						.seal(TestConfig.storePass);
				vcJson.getMetadata().setAlias("json");
				store.storeCredential(vcJson);

				vcUser1Json = vcJson;
			}

			return vcUser1Json;
		}

		public synchronized VerifiablePresentation getUser1NonemptyPresentation() throws DIDException, IOException {
			if (vpUser1Nonempty == null) {
				DIDDocument doc = getUser1Document();

				VerifiablePresentation.Builder pb = VerifiablePresentation.createFor(
						doc.getSubject(), store);

				VerifiablePresentation vp = pb
						.credentials(doc.getCredential("#profile"), doc.getCredential("#email"))
						.credentials(getUser1PassportCredential())
						.credentials(getUser1TwitterCredential())
						.realm("https://example.com/")
						.nonce("873172f58701a9ee686f0630204fee59")
						.seal(TestConfig.storePass);

				vpUser1Nonempty = vp;
			}

			return vpUser1Nonempty;
		}

		public synchronized VerifiablePresentation getUser1EmptyPresentation() throws DIDException, IOException {
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

		public synchronized DIDDocument getUser2Document() throws DIDException, IOException {
			if (idUser2 == null) {
				DIDDocument doc = identity.newDid(TestConfig.storePass);
				doc.getMetadata().setAlias("User2");

				DIDDocument.Builder db = doc.edit();

				Map<String, Object> props = new HashMap<String, Object>();
				props.put("name", "John");
				props.put("gender", "Male");
				props.put("nation", "Singapore");
				props.put("language", "English");
				props.put("email", "john@example.com");
				props.put("twitter", "@john");

				db.addCredential("#profile", props, TestConfig.storePass);
				doc = db.seal(TestConfig.storePass);
				store.storeDid(doc);
				doc.publish(TestConfig.storePass);

				idUser2 = doc;
			}

			return idUser2;
		}

		public synchronized DIDDocument createUser3Document() throws DIDException, IOException {
			if (idUser3 == null) {
				DIDDocument doc = identity.newDid(TestConfig.storePass);
				doc.getMetadata().setAlias("User3");
				doc.publish(TestConfig.storePass);

				idUser3 = doc;
			}

			return idUser3;
		}
	}
}
