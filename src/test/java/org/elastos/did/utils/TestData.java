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
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
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

	private CompatibleData compatibleData;
	private InstantData instantData;

	public TestData(boolean simulated) throws DIDException {
    	Utils.deleteFile(new File(TestConfig.storeRoot));
		store = DIDStore.open(TestConfig.storeRoot);
	}

	public TestData() throws DIDException {
		this(TestConfig.network.equalsIgnoreCase("simnet"));
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

	public RootIdentity getRootIdentity() {
		return identity;
	}

	public String getMnemonic() {
		return mnemonic;
	}

	public CompatibleData getCompatibleData() {
		if (compatibleData == null)
			compatibleData = new CompatibleData();

		return compatibleData;
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

	public RootIdentity initIdentity() throws DIDException {
    	mnemonic =  Mnemonic.getInstance().generate();
    	identity = RootIdentity.create(Mnemonic.ENGLISH, mnemonic,
    			TestConfig.passphrase, true, store, TestConfig.storePass);

    	return identity;
	}

	public class CompatibleData {
		private DIDDocument testIssuer;
		private String issuerCompactJson;
		private String issuerNormalizedJson;

		private DIDDocument testDocument;
		private String testCompactJson;
		private String testNormalizedJson;

		private DIDDocument emptyCustomizedDidDocument;
		private DIDDocument customizedDidDocument;

		private VerifiableCredential profileVc;
		private String profileVcCompactJson;
		private String profileVcNormalizedJson;

		private VerifiableCredential emailVc;
		private String emailVcCompactJson;
		private String emailVcNormalizedJson;

		private VerifiableCredential passportVc;
		private String passportVcCompactJson;
		private String passportVcNormalizedJson;

		private VerifiableCredential twitterVc;
		private String twitterVcCompactJson;
		private String twitterVcNormalizedJson;

		private VerifiableCredential jsonVc;
		private String jsonVcCompactJson;
		private String jsonVcNormalizedJson;

		private VerifiablePresentation testVp;
		private String testVpNormalizedJson;

		private DIDDocument loadDIDDocument(String fileName)
				throws DIDException, IOException {
			Reader input = new InputStreamReader(getClass()
					.getClassLoader().getResourceAsStream("testdata/" + fileName));
			DIDDocument doc = DIDDocument.parse(input);
			input.close();

			if (store != null) {
				store.storeDid(doc);
			}

			return doc;
		}

		private void importPrivateKey(DIDURL id, String fileName)
				throws IOException, DIDException {
			String skBase58 = loadText(fileName);
			byte[] sk = HDKey.deserializeBase58(skBase58).serialize();

			store.storePrivateKey(id, sk, TestConfig.storePass);
		}


		public DIDDocument loadTestIssuer() throws DIDException, IOException {
			if (testIssuer == null) {
				testIssuer = loadDIDDocument("issuer.json");

				importPrivateKey(testIssuer.getDefaultPublicKeyId(), "issuer.primary.sk");

				testIssuer.publish(TestConfig.storePass);
			}

			return testIssuer;
		}

		public DIDDocument loadTestDocument() throws DIDException, IOException {
			loadTestIssuer();

			if (testDocument == null) {
				testDocument = loadDIDDocument("document.json");

				importPrivateKey(testDocument.getDefaultPublicKeyId(), "document.primary.sk");
				importPrivateKey(testDocument.getPublicKey("key2").getId(), "document.key2.sk");
				importPrivateKey(testDocument.getPublicKey("key3").getId(), "document.key3.sk");

				testDocument.publish(TestConfig.storePass);
			}

			return testDocument;
		}

		public DIDDocument loadEmptyCustomizedDidDocument() throws DIDException, IOException {
			loadTestIssuer();
			loadTestDocument();

			if (emptyCustomizedDidDocument == null) {
				emptyCustomizedDidDocument = loadDIDDocument("customized-did-empty.json");

				emptyCustomizedDidDocument.publish(TestConfig.storePass);
			}

			return emptyCustomizedDidDocument;
		}

		public DIDDocument loadCustomizedDidDocument() throws DIDException, IOException {
			loadTestIssuer();
			loadTestDocument();

			if (customizedDidDocument == null) {
				customizedDidDocument = loadDIDDocument("customized-did.json");

				customizedDidDocument.publish(TestConfig.storePass);
			}

			return customizedDidDocument;
		}

		private VerifiableCredential loadCredential(String fileName)
				throws DIDException, IOException {
			Reader input = new InputStreamReader(getClass()
					.getClassLoader().getResourceAsStream("testdata/" + fileName));
			VerifiableCredential vc = VerifiableCredential.parse(input);
			input.close();

			if (store != null)
				store.storeCredential(vc);

			return vc;
		}

		public VerifiableCredential loadProfileCredential()
				throws DIDException, IOException {
			if (profileVc == null)
				profileVc = loadCredential("vc-profile.json");

			return profileVc;
		}

		public VerifiableCredential loadEmailCredential()
				throws DIDException, IOException {
			if (emailVc == null)
				emailVc = loadCredential("vc-email.json");

			return emailVc;
		}

		public VerifiableCredential loadPassportCredential()
				throws DIDException, IOException {
			if (passportVc == null)
				passportVc = loadCredential("vc-passport.json");

			return passportVc;
		}

		public VerifiableCredential loadTwitterCredential()
				throws DIDException, IOException {
			if (twitterVc == null)
				twitterVc = loadCredential("vc-twitter.json");

			return twitterVc;
		}

		public VerifiableCredential loadJsonCredential()
				throws DIDException, IOException {
			if (jsonVc == null)
				jsonVc = loadCredential("vc-json.json");

			return jsonVc;
		}

		public VerifiablePresentation loadPresentation()
				throws DIDException, IOException {
			if (testVp == null) {
				Reader input = new InputStreamReader(getClass()
						.getClassLoader().getResourceAsStream("testdata/vp.json"));
				testVp = VerifiablePresentation.parse(input);
				input.close();
			}

			return testVp;
		}

		private String loadText(String fileName) throws IOException {
			BufferedReader input = new BufferedReader(new InputStreamReader(
					getClass().getClassLoader().getResourceAsStream("testdata/" + fileName)));
			String text = input.readLine();
			input.close();

			return text;
		}

		public String loadIssuerCompactJson() throws IOException {
			if (issuerCompactJson == null)
				issuerCompactJson = loadText("issuer.compact.json");

			return issuerCompactJson;
		}

		public String loadIssuerNormalizedJson() throws IOException {
			if (issuerNormalizedJson == null)
				issuerNormalizedJson = loadText("issuer.normalized.json");

			return issuerNormalizedJson;
		}

		public String loadTestCompactJson() throws IOException {
			if (testCompactJson == null)
				testCompactJson = loadText("document.compact.json");

			return testCompactJson;
		}

		public String loadTestNormalizedJson() throws IOException {
			if (testNormalizedJson == null)
				testNormalizedJson = loadText("document.normalized.json");

			return testNormalizedJson;
		}

		public String loadProfileVcCompactJson() throws IOException {
			if (profileVcCompactJson == null)
				profileVcCompactJson = loadText("vc-profile.compact.json");

			return profileVcCompactJson;
		}

		public String loadProfileVcNormalizedJson() throws IOException {
			if (profileVcNormalizedJson == null)
				profileVcNormalizedJson = loadText("vc-profile.normalized.json");

			return profileVcNormalizedJson;
		}

		public String loadEmailVcCompactJson() throws IOException {
			if (emailVcCompactJson == null)
				emailVcCompactJson = loadText("vc-email.compact.json");

			return emailVcCompactJson;
		}

		public String loadEmailVcNormalizedJson() throws IOException {
			if (emailVcNormalizedJson == null)
				emailVcNormalizedJson = loadText("vc-email.normalized.json");

			return emailVcNormalizedJson;
		}

		public String loadPassportVcCompactJson() throws IOException {
			if (passportVcCompactJson == null)
				passportVcCompactJson = loadText("vc-passport.compact.json");

			return passportVcCompactJson;
		}

		public String loadPassportVcNormalizedJson() throws IOException {
			if (passportVcNormalizedJson == null)
				passportVcNormalizedJson = loadText("vc-passport.normalized.json");

			return passportVcNormalizedJson;
		}

		public String loadTwitterVcCompactJson() throws IOException {
			if (twitterVcCompactJson == null)
				twitterVcCompactJson = loadText("vc-twitter.compact.json");

			return twitterVcCompactJson;
		}

		public String loadTwitterVcNormalizedJson() throws IOException {
			if (twitterVcNormalizedJson == null)
				twitterVcNormalizedJson = loadText("vc-twitter.normalized.json");

			return twitterVcNormalizedJson;
		}

		public String loadJsonVcCompactJson() throws IOException {
			if (jsonVcCompactJson == null)
				jsonVcCompactJson = loadText("vc-json.compact.json");

			return jsonVcCompactJson;
		}

		public String loadJsonVcNormalizedJson() throws IOException {
			if (jsonVcNormalizedJson == null)
				jsonVcNormalizedJson = loadText("vc-json.normalized.json");

			return jsonVcNormalizedJson;
		}

		public String loadPresentationNormalizedJson() throws IOException {
			if (testVpNormalizedJson == null)
				testVpNormalizedJson = loadText("vp.normalized.json");

			return testVpNormalizedJson;
		}
	}

	public class InstantData {
		private DIDDocument testIssuer;
		private DIDDocument testDocument;
		private VerifiableCredential vcProfile;
		private VerifiableCredential vcEmail;
		private VerifiableCredential vcPassport;
		private VerifiableCredential vcTwitter;
		private VerifiableCredential vcJson;
		private VerifiablePresentation vpTest;

		public DIDDocument loadTestIssuer() throws DIDException, IOException {
			if (testIssuer == null) {
				initIdentity();

				DIDDocument doc = identity.newDid(TestConfig.storePass);
				doc.getMetadata().setAlias("Issuer");

				Issuer selfIssuer = new Issuer(doc);
				VerifiableCredential.Builder cb = selfIssuer.issueFor(doc.getSubject());

				Map<String, Object> props= new HashMap<String, Object>();
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

				vc.getMetadata().setAlias("Profile");
				store.storeCredential(vc);

				doc.publish(TestConfig.storePass);

				testIssuer = doc;
			}

			return testIssuer;

		}

		public DIDDocument loadTestDocument() throws DIDException, IOException {
			if (testDocument == null) {
				DIDDocument issuer = loadTestIssuer();

				DIDDocument doc = identity.newDid(TestConfig.storePass);
				doc.getMetadata().setAlias("Test");

				DIDDocument.Builder db = doc.edit();

				HDKey temp = TestData.generateKeypair();
				DIDURL id = new DIDURL(doc.getSubject(), "#key2");
				db.addAuthenticationKey(id, temp.getPublicKeyBase58());
				store.storePrivateKey(id, temp.serialize(), TestConfig.storePass);

				temp = TestData.generateKeypair();
				id = new DIDURL(doc.getSubject(), "#key3");
				db.addAuthenticationKey(id, temp.getPublicKeyBase58());
				store.storePrivateKey(id, temp.serialize(), TestConfig.storePass);

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

				Map<String, Object> props= new HashMap<String, Object>();
				props.put("name", "John");
				props.put("gender", "Male");
				props.put("nation", "Singapore");
				props.put("language", "English");
				props.put("email", "john@example.com");
				props.put("twitter", "@john");

				vcProfile = cb.id("profile")
						.type("BasicProfileCredential", "SelfProclaimedCredential")
						.properties(props)
						.seal(TestConfig.storePass);

				Issuer kycIssuer = new Issuer(issuer);
				cb = kycIssuer.issueFor(doc.getSubject());

				props= new HashMap<String, Object>();
				props.put("email", "john@example.com");

				vcEmail = cb.id("email")
						.type("BasicProfileCredential",
								"InternetAccountCredential", "EmailCredential")
						.properties(props)
						.seal(TestConfig.storePass);

				db.addCredential(vcProfile);
				db.addCredential(vcEmail);
				doc = db.seal(TestConfig.storePass);

				vcProfile.getMetadata().setAlias("Profile");
				store.storeCredential(vcProfile);
				vcEmail.getMetadata().setAlias("Email");
				store.storeCredential(vcEmail);

				store.storeDid(doc);
				doc.publish(TestConfig.storePass);

				id = new DIDURL(doc.getSubject(), "passport");
				cb = selfIssuer.issueFor(doc.getSubject());

				props= new HashMap<String, Object>();
				props.put("nation", "Singapore");
				props.put("passport", "S653258Z07");

				vcPassport = cb.id(id)
						.type("BasicProfileCredential", "SelfProclaimedCredential")
						.properties(props)
						.seal(TestConfig.storePass);
				vcPassport.getMetadata().setAlias("Passport");
				store.storeCredential(vcPassport);

				id = new DIDURL(doc.getSubject(), "twitter");
				cb = kycIssuer.issueFor(doc.getSubject());

				props= new HashMap<String, Object>();
				props.put("twitter", "@john");

				vcTwitter = cb.id(id)
						.type("InternetAccountCredential", "TwitterCredential")
						.properties(props)
						.seal(TestConfig.storePass);
				vcTwitter.getMetadata().setAlias("Twitter");
				store.storeCredential(vcTwitter);

				testDocument = doc;
			}

			return testDocument;
		}


		public DIDDocument loadEmptyCustomizedDidDocument() throws DIDException, IOException {
			return null;
		}

		public DIDDocument loadCustomizedDidDocument() throws DIDException, IOException {
			return null;
		}

		public VerifiableCredential loadProfileCredential()
				throws DIDException, IOException {
			if (vcProfile == null)
				loadTestDocument();

			return vcProfile;
		}

		public VerifiableCredential loadEmailCredential()
				throws DIDException, IOException {
			if (vcEmail == null)
				loadTestDocument();

			return vcEmail;
		}

		public VerifiableCredential loadPassportCredential()
				throws DIDException, IOException {
			if (vcPassport == null)
				loadTestDocument();

			return vcPassport;
		}

		public VerifiableCredential loadTwitterCredential()
				throws DIDException, IOException {
			if (vcTwitter == null)
				loadTestDocument();

			return vcTwitter;
		}

		public VerifiableCredential loadJsonCredential()
				throws DIDException, IOException {
			if (vcJson == null) {
				DIDDocument doc = loadTestDocument();
				DIDDocument issuer = loadTestIssuer();

				Issuer kycIssuer = new Issuer(issuer);

				DIDURL id = new DIDURL(doc.getSubject(), "json");
				VerifiableCredential.Builder cb = kycIssuer.issueFor(doc.getSubject());

				String jsonProps = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\",\"booleanValue\":true,\"numberValue\":1234,\"doubleValue\":9.5,\"nationality\":\"Canadian\",\"birthPlace\":{\"type\":\"Place\",\"address\":{\"type\":\"PostalAddress\",\"addressLocality\":\"Vancouver\",\"addressRegion\":\"BC\",\"addressCountry\":\"Canada\"}},\"affiliation\":[{\"type\":\"Organization\",\"name\":\"Futurpreneur\",\"sameAs\":[\"https://twitter.com/futurpreneur\",\"https://www.facebook.com/futurpreneur/\",\"https://www.linkedin.com/company-beta/100369/\",\"https://www.youtube.com/user/CYBF\"]}],\"alumniOf\":[{\"type\":\"CollegeOrUniversity\",\"name\":\"Vancouver Film School\",\"sameAs\":\"https://en.wikipedia.org/wiki/Vancouver_Film_School\",\"year\":2000},{\"type\":\"CollegeOrUniversity\",\"name\":\"CodeCore Bootcamp\"}],\"gender\":\"Male\",\"Description\":\"Technologist\",\"disambiguatingDescription\":\"Co-founder of CodeCore Bootcamp\",\"jobTitle\":\"Technical Director\",\"worksFor\":[{\"type\":\"Organization\",\"name\":\"Skunkworks Creative Group Inc.\",\"sameAs\":[\"https://twitter.com/skunkworks_ca\",\"https://www.facebook.com/skunkworks.ca\",\"https://www.linkedin.com/company/skunkworks-creative-group-inc-\",\"https://plus.google.com/+SkunkworksCa\"]}],\"url\":\"https://jay.holtslander.ca\",\"image\":\"https://s.gravatar.com/avatar/961997eb7fd5c22b3e12fb3c8ca14e11?s=512&r=g\",\"address\":{\"type\":\"PostalAddress\",\"addressLocality\":\"Vancouver\",\"addressRegion\":\"BC\",\"addressCountry\":\"Canada\"},\"sameAs\":[\"https://twitter.com/j_holtslander\",\"https://pinterest.com/j_holtslander\",\"https://instagram.com/j_holtslander\",\"https://www.facebook.com/jay.holtslander\",\"https://ca.linkedin.com/in/holtslander/en\",\"https://plus.google.com/+JayHoltslander\",\"https://www.youtube.com/user/jasonh1234\",\"https://github.com/JayHoltslander\",\"https://profiles.wordpress.org/jasonh1234\",\"https://angel.co/j_holtslander\",\"https://www.foursquare.com/user/184843\",\"https://jholtslander.yelp.ca\",\"https://codepen.io/j_holtslander/\",\"https://stackoverflow.com/users/751570/jay\",\"https://dribbble.com/j_holtslander\",\"http://jasonh1234.deviantart.com/\",\"https://www.behance.net/j_holtslander\",\"https://www.flickr.com/people/jasonh1234/\",\"https://medium.com/@j_holtslander\"]}";

				vcJson = cb.id(id)
						.type("InternetAccountCredential", "TwitterCredential")
						.properties(jsonProps)
						.seal(TestConfig.storePass);
				vcJson.getMetadata().setAlias("json");
			}

			return vcJson;
		}

		public VerifiablePresentation loadPresentation()
				throws DIDException, IOException {
			if (vpTest == null) {
				DIDDocument doc = loadTestDocument();

				VerifiablePresentation.Builder pb = VerifiablePresentation.createFor(
						doc.getSubject(), store);

				vpTest = pb.credentials(loadProfileCredential(), loadEmailCredential())
						.credentials(loadPassportCredential())
						.credentials(loadTwitterCredential())
						.realm("https://example.com/")
						.nonce("873172f58701a9ee686f0630204fee59")
						.seal(TestConfig.storePass);

			}

			return vpTest;
		}
	}
}
