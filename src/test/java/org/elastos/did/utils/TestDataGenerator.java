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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

import org.elastos.did.DIDBackend;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.DIDURL;
import org.elastos.did.Issuer;
import org.elastos.did.Mnemonic;
import org.elastos.did.RootIdentity;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.VerifiablePresentation;
import org.elastos.did.backend.SimulatedIDChain;
import org.elastos.did.crypto.HDKey;
import org.elastos.did.exception.DIDException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class TestDataGenerator {
	private File testDataDir;
	private SimulatedIDChain simChain;
	private DIDDocument issuer;
	private DIDDocument[] users = new DIDDocument[3];
	private DIDStore store;
	private RootIdentity identity;
	private HDKey rootPrivateKey;

	private void init(String dataRoot) throws IOException, DIDException {
		simChain = new SimulatedIDChain();
		simChain.start();

		DIDBackend.initialize(simChain.getAdapter());

		Utils.deleteFile(new File(dataRoot + File.separator + "teststore"));
		store = DIDStore.open(dataRoot + File.separator + "teststore");

    	//String mnemonic =  Mnemonic.getInstance().generate();
    	String mnemonic = "amateur file dignity extend cabin jaguar early electric ask video happy access";
    	rootPrivateKey = new HDKey(mnemonic, TestConfig.passphrase);

    	identity = RootIdentity.create(Mnemonic.ENGLISH, mnemonic,
    			TestConfig.passphrase, store, TestConfig.storePass);

    	testDataDir = new File(dataRoot + File.separator + "testdata");
    	testDataDir.mkdirs();
	}

	private void cleanup() {
		if (simChain != null)
			simChain.stop();

		simChain = null;
	}

	private void createTestIssuer() throws DIDException, IOException {
		// index = 0;
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		doc.getMetadata().setAlias("Issuer");

		System.out.print("Generate issuer DID: " + doc.getSubject() + "...");

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
		issuer = db.seal(TestConfig.storePass);
		store.storeDid(issuer);

		DIDURL id = issuer.getDefaultPublicKeyId();
		HDKey key = rootPrivateKey.derive(HDKey.DERIVE_PATH_PREFIX + 0);
		writeTo("issuer.id." + id.getFragment() + ".sk", key.serializeBase58());

		String json = issuer.toString(true);
		writeTo("issuer.id.normalized.json", json);

		json = formatJson(json);
		writeTo("issuer.id.json", json);

		json = issuer.toString(false);
		writeTo("issuer.id.compact.json", json);

		System.out.println(issuer.isValid() ? "OK" : "Error");
	}

	private void createTestUser1() throws DIDException, IOException {
		// index = 1;
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		doc.getMetadata().setAlias("User1");

		// Test document with two embedded credentials
		System.out.print("Generate user1 DID: " + doc.getSubject() + "...");

		DIDDocument.Builder db = doc.edit();

		HDKey temp = TestData.generateKeypair();
		db.addAuthenticationKey("key2", temp.getPublicKeyBase58());
		store.storePrivateKey(new DIDURL(doc.getSubject(), "key2"),
				temp.serialize(), TestConfig.storePass);
		writeTo("user1.id.key2.sk", temp.serializeBase58());

		temp = TestData.generateKeypair();
		db.addAuthenticationKey("key3", temp.getPublicKeyBase58());
		store.storePrivateKey(new DIDURL(doc.getSubject(), "key3"),
				temp.serialize(), TestConfig.storePass);
		writeTo("user1.id.key3.sk", temp.serializeBase58());

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

		Issuer kycIssuer = new Issuer(issuer);
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

		users[0] = doc;

		DIDURL id = doc.getDefaultPublicKeyId();
		HDKey key = rootPrivateKey.derive(HDKey.DERIVE_PATH_PREFIX + 1);
		writeTo("user1.id." + id.getFragment() + ".sk", key.serializeBase58());

		String json = doc.toString(true);
		writeTo("user1.id.normalized.json", json);

		json = formatJson(json);
		writeTo("user1.id.json", json);

		json = doc.toString(false);
		writeTo("user1.id.compact.json", json);

		System.out.println(doc.isValid() ? "OK" : "Error");

		// Passport credential
		id = new DIDURL(doc.getSubject(), "passport");
		System.out.print("Generate credential: " + id + "...");

		cb = selfIssuer.issueFor(doc.getSubject());

		props.clear();
		props.put("nation", "Singapore");
		props.put("passport", "S653258Z07");

		VerifiableCredential vcPassport = cb.id(id)
				.type("BasicProfileCredential", "SelfProclaimedCredential")
				.properties(props)
				.seal(TestConfig.storePass);
		vcPassport.getMetadata().setAlias("Passport");
		store.storeCredential(vcPassport);

		json = vcPassport.toString(true);
		writeTo("user1.vc.passport.normalized.json", json);

		json = formatJson(json);
		writeTo("user1.vc.passport.json", json);

		json = vcPassport.toString(false);
		writeTo("user1.vc.passport.compact.json", json);

		//System.out.println(vcPassport.isValid() ? "OK" : "Error");
		System.out.println("OK");

		// Twitter credential
		id = new DIDURL(doc.getSubject(), "twitter");
		System.out.print("Generate credential: " + id + "...");

		cb = kycIssuer.issueFor(doc.getSubject());

		props.clear();
		props.put("twitter", "@john");

		VerifiableCredential vcTwitter = cb.id(id)
				.type("InternetAccountCredential", "TwitterCredential")
				.properties(props)
				.seal(TestConfig.storePass);
		vcTwitter.getMetadata().setAlias("Twitter");
		store.storeCredential(vcTwitter);

		json = vcTwitter.toString(true);
		writeTo("user1.vc.twitter.normalized.json", json);

		json = formatJson(json);
		writeTo("user1.vc.twitter.json", json);

		json = vcTwitter.toString(false);
		writeTo("user1.vc.twitter.compact.json", json);

		//System.out.println(vcTwitter.isValid() ? "OK" : "Error");
		System.out.println("OK");

		// Json format credential
		id = new DIDURL(doc.getSubject(), "json");
		System.out.print("Generate credential: " + id + "...");

		cb = kycIssuer.issueFor(doc.getSubject());

		String jsonProps = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\",\"booleanValue\":true,\"numberValue\":1234,\"doubleValue\":9.5,\"nationality\":\"Canadian\",\"birthPlace\":{\"type\":\"Place\",\"address\":{\"type\":\"PostalAddress\",\"addressLocality\":\"Vancouver\",\"addressRegion\":\"BC\",\"addressCountry\":\"Canada\"}},\"affiliation\":[{\"type\":\"Organization\",\"name\":\"Futurpreneur\",\"sameAs\":[\"https://twitter.com/futurpreneur\",\"https://www.facebook.com/futurpreneur/\",\"https://www.linkedin.com/company-beta/100369/\",\"https://www.youtube.com/user/CYBF\"]}],\"alumniOf\":[{\"type\":\"CollegeOrUniversity\",\"name\":\"Vancouver Film School\",\"sameAs\":\"https://en.wikipedia.org/wiki/Vancouver_Film_School\",\"year\":2000},{\"type\":\"CollegeOrUniversity\",\"name\":\"CodeCore Bootcamp\"}],\"gender\":\"Male\",\"Description\":\"Technologist\",\"disambiguatingDescription\":\"Co-founder of CodeCore Bootcamp\",\"jobTitle\":\"Technical Director\",\"worksFor\":[{\"type\":\"Organization\",\"name\":\"Skunkworks Creative Group Inc.\",\"sameAs\":[\"https://twitter.com/skunkworks_ca\",\"https://www.facebook.com/skunkworks.ca\",\"https://www.linkedin.com/company/skunkworks-creative-group-inc-\",\"https://plus.google.com/+SkunkworksCa\"]}],\"url\":\"https://jay.holtslander.ca\",\"image\":\"https://s.gravatar.com/avatar/961997eb7fd5c22b3e12fb3c8ca14e11?s=512&r=g\",\"address\":{\"type\":\"PostalAddress\",\"addressLocality\":\"Vancouver\",\"addressRegion\":\"BC\",\"addressCountry\":\"Canada\"},\"sameAs\":[\"https://twitter.com/j_holtslander\",\"https://pinterest.com/j_holtslander\",\"https://instagram.com/j_holtslander\",\"https://www.facebook.com/jay.holtslander\",\"https://ca.linkedin.com/in/holtslander/en\",\"https://plus.google.com/+JayHoltslander\",\"https://www.youtube.com/user/jasonh1234\",\"https://github.com/JayHoltslander\",\"https://profiles.wordpress.org/jasonh1234\",\"https://angel.co/j_holtslander\",\"https://www.foursquare.com/user/184843\",\"https://jholtslander.yelp.ca\",\"https://codepen.io/j_holtslander/\",\"https://stackoverflow.com/users/751570/jay\",\"https://dribbble.com/j_holtslander\",\"http://jasonh1234.deviantart.com/\",\"https://www.behance.net/j_holtslander\",\"https://www.flickr.com/people/jasonh1234/\",\"https://medium.com/@j_holtslander\"]}";

		VerifiableCredential vcJson = cb.id(id)
				.type("TestCredential", "JsonCredential")
				.properties(jsonProps)
				.seal(TestConfig.storePass);
		vcJson.getMetadata().setAlias("json");
		store.storeCredential(vcTwitter);

		json = vcJson.toString(true);
		writeTo("user1.vc.json.normalized.json", json);

		json = formatJson(json);
		writeTo("user1.vc.json.json", json);

		json = vcJson.toString(false);
		writeTo("user1.vc.json.compact.json", json);

		//System.out.println(vcJson.isValid() ? "OK" : "Error");
		System.out.println("OK");

		// Presentation with above credentials
		System.out.print("Generate presentation...");

		VerifiablePresentation.Builder pb = VerifiablePresentation.createFor(
				doc.getSubject(), store);

		VerifiablePresentation vp = pb.credentials(vcProfile, vcEmail)
				.credentials(vcPassport)
				.credentials(vcTwitter)
				.realm("https://example.com/")
				.nonce("873172f58701a9ee686f0630204fee59")
				.seal(TestConfig.storePass);

		json = vp.toString(true);
		writeTo("user1.vp.nonempty.normalized.json", json);

		json = formatJson( vp.toString());
		writeTo("user1.vp.nonempty.json", json);

		pb = VerifiablePresentation.createFor(
				doc.getSubject(), store);

		vp = pb.realm("https://example.com/")
				.nonce("873172f58701a9ee686f0630204fee59")
				.seal(TestConfig.storePass);

		json = vp.toString(true);
		writeTo("user1.vp.empty.normalized.json", json);

		json = formatJson(vp.toString());
		writeTo("user1.vp.empty.json", json);

		//System.out.println(vp.isValid() ? "OK" : "Error");
		System.out.println("OK");
	}

	private void createTestUser2() throws DIDException, IOException {
		// index = 2;
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		doc.getMetadata().setAlias("User2");

		// Test document with two embedded credentials
		System.out.print("Generate user2 DID: " + doc.getSubject() + "...");

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

		users[1] = doc;

		DIDURL id = doc.getDefaultPublicKeyId();
		HDKey key = rootPrivateKey.derive(HDKey.DERIVE_PATH_PREFIX + 2);
		writeTo("user2.id." + id.getFragment() + ".sk", key.serializeBase58());

		String json = doc.toString(true);
		writeTo("user2.id.normalized.json", json);

		json = formatJson(json);
		writeTo("user2.id.json", json);

		json = doc.toString(false);
		writeTo("user2.id.compact.json", json);

		System.out.println(doc.isValid() ? "OK" : "Error");
	}

	private void createTestUser3() throws DIDException, IOException {
		// index = 3;
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		doc.getMetadata().setAlias("User3");

		// Test document with two embedded credentials
		System.out.print("Generate user3 DID: " + doc.getSubject() + "...");

		users[2] = doc;

		DIDURL id = doc.getDefaultPublicKeyId();
		HDKey key = rootPrivateKey.derive(HDKey.DERIVE_PATH_PREFIX + 3);
		writeTo("user3.id." + id.getFragment() + ".sk", key.serializeBase58());

		String json = doc.toString(true);
		writeTo("user3.id.normalized.json", json);

		json = formatJson(json);
		writeTo("user3.id.json", json);

		json = doc.toString(false);
		writeTo("user3.id.compact.json", json);

		System.out.println(doc.isValid() ? "OK" : "Error");
	}

	public void createTestFiles() throws IOException, DIDException {
		init(TestConfig.tempDir + File.separator + "DIDTestFiles.v2");
		createTestIssuer();
		createTestUser1();
		createTestUser2();
		createTestUser3();
		cleanup();
	}

	private String formatJson(String json) throws IOException {
		ObjectMapper mapper = new ObjectMapper();
		JsonNode node = mapper.readTree(json);
		json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(node);
		return json;
	}

	private void writeTo(String fileName, String content) throws IOException {
		Writer out = new FileWriter(testDataDir.getPath()
				+ File.separator + fileName);
		out.write(content);
		out.close();
	}

	public static void main(String[] argc) throws Exception {
		TestDataGenerator tdc = new TestDataGenerator();

		tdc.createTestFiles();
	}
}
