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

import org.elastos.did.DID;
import org.elastos.did.DIDBackend;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.DIDURL;
import org.elastos.did.Issuer;
import org.elastos.did.RootIdentity;
import org.elastos.did.TransferTicket;
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
	private DIDDocument exampleCorp;
	private DIDDocument[] users = new DIDDocument[4];
	private DIDStore store;
	private RootIdentity identity;
	private HDKey rootPrivateKey;

	private void init(String dataRoot) throws IOException, DIDException {
		simChain = new SimulatedIDChain();
		simChain.start();

		DIDBackend.initialize(simChain.getAdapter());

		Utils.deleteFile(new File(dataRoot + File.separator + "teststore"));
		store = DIDStore.open(dataRoot + File.separator + "teststore");

    	// String mnemonic =  Mnemonic.getInstance().generate();
    	String mnemonic = "amateur file dignity extend cabin jaguar early electric ask video happy access";
    	rootPrivateKey = new HDKey(mnemonic, TestConfig.passphrase);

    	identity = RootIdentity.create(mnemonic, TestConfig.passphrase,
    			store, TestConfig.storePass);

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
		System.out.print("Generate issuer DID...");

		DIDDocument doc = identity.newDid(TestConfig.storePass);
		doc.getMetadata().setAlias("Issuer");

		System.out.print(doc.getSubject() + "...");

		Issuer selfIssuer = new Issuer(doc);
		VerifiableCredential.Builder cb = selfIssuer.issueFor(doc.getSubject());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", "Test Issuer");
		props.put("nation", "Singapore");
		props.put("language", "English");
		props.put("email", "issuer@example.com");

		VerifiableCredential vc = cb.id("#profile")
				.type("BasicProfileCredential", "SelfProclaimedCredential")
				.properties(props)
				.seal(TestConfig.storePass);

		DIDDocument.Builder db = doc.edit();
		db.addCredential(vc);
		issuer = db.seal(TestConfig.storePass);
		store.storeDid(issuer);
		issuer.publish(TestConfig.storePass);

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
		System.out.print("Generate user1 DID...");

		DIDDocument doc = identity.newDid(TestConfig.storePass);
		doc.getMetadata().setAlias("User1");

		System.out.print(doc.getSubject() + "...");

		DIDDocument.Builder db = doc.edit();

		HDKey temp = TestData.generateKeypair();
		db.addAuthenticationKey("#key2", temp.getPublicKeyBase58());
		store.storePrivateKey(new DIDURL(doc.getSubject(), "#key2"),
				temp.serialize(), TestConfig.storePass);
		writeTo("user1.id.key2.sk", temp.serializeBase58());

		temp = TestData.generateKeypair();
		db.addAuthenticationKey("#key3", temp.getPublicKeyBase58());
		store.storePrivateKey(new DIDURL(doc.getSubject(), "#key3"),
				temp.serialize(), TestConfig.storePass);
		writeTo("user1.id.key3.sk", temp.serializeBase58());

		temp = TestData.generateKeypair();
		db.addAuthorizationKey("#recovery",
				"did:elastos:" + temp.getAddress(),
				temp.getPublicKeyBase58());

		db.addService("#openid", "OpenIdConnectVersion1.0Service",
				"https://openid.example.com/");
		db.addService("#vcr", "CredentialRepositoryService",
				"https://did.example.com/credentials");
		db.addService("#carrier", "CarrierAddress",
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

		VerifiableCredential vcProfile = cb.id("#profile")
				.type("BasicProfileCredential", "SelfProclaimedCredential")
				.properties(props)
				.seal(TestConfig.storePass);

		Issuer kycIssuer = new Issuer(issuer);
		cb = kycIssuer.issueFor(doc.getSubject());

		props.clear();
		props.put("email", "john@example.com");

		VerifiableCredential vcEmail = cb.id("#email")
				.type("BasicProfileCredential",
						"InternetAccountCredential", "EmailCredential")
				.properties(props)
				.seal(TestConfig.storePass);

		db.addCredential(vcProfile);
		db.addCredential(vcEmail);
		doc = db.seal(TestConfig.storePass);
		store.storeDid(doc);
		doc.publish(TestConfig.storePass);

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
		id = new DIDURL(doc.getSubject(), "#passport");
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
		id = new DIDURL(doc.getSubject(), "#twitter");
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
		id = new DIDURL(doc.getSubject(), "#json");
		System.out.print("Generate credential: " + id + "...");

		cb = kycIssuer.issueFor(doc.getSubject());

		String jsonProps = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\",\"booleanValue\":true,\"numberValue\":1234,\"doubleValue\":9.5,\"nationality\":\"Canadian\",\"birthPlace\":{\"type\":\"Place\",\"address\":{\"type\":\"PostalAddress\",\"addressLocality\":\"Vancouver\",\"addressRegion\":\"BC\",\"addressCountry\":\"Canada\"}},\"affiliation\":[{\"type\":\"Organization\",\"name\":\"Futurpreneur\",\"sameAs\":[\"https://twitter.com/futurpreneur\",\"https://www.facebook.com/futurpreneur/\",\"https://www.linkedin.com/company-beta/100369/\",\"https://www.youtube.com/user/CYBF\"]}],\"alumniOf\":[{\"type\":\"CollegeOrUniversity\",\"name\":\"Vancouver Film School\",\"sameAs\":\"https://en.wikipedia.org/wiki/Vancouver_Film_School\",\"year\":2000},{\"type\":\"CollegeOrUniversity\",\"name\":\"CodeCore Bootcamp\"}],\"gender\":\"Male\",\"Description\":\"Technologist\",\"disambiguatingDescription\":\"Co-founder of CodeCore Bootcamp\",\"jobTitle\":\"Technical Director\",\"worksFor\":[{\"type\":\"Organization\",\"name\":\"Skunkworks Creative Group Inc.\",\"sameAs\":[\"https://twitter.com/skunkworks_ca\",\"https://www.facebook.com/skunkworks.ca\",\"https://www.linkedin.com/company/skunkworks-creative-group-inc-\",\"https://plus.google.com/+SkunkworksCa\"]}],\"url\":\"https://jay.holtslander.ca\",\"image\":\"https://s.gravatar.com/avatar/961997eb7fd5c22b3e12fb3c8ca14e11?s=512&r=g\",\"address\":{\"type\":\"PostalAddress\",\"addressLocality\":\"Vancouver\",\"addressRegion\":\"BC\",\"addressCountry\":\"Canada\"},\"sameAs\":[\"https://twitter.com/j_holtslander\",\"https://pinterest.com/j_holtslander\",\"https://instagram.com/j_holtslander\",\"https://www.facebook.com/jay.holtslander\",\"https://ca.linkedin.com/in/holtslander/en\",\"https://plus.google.com/+JayHoltslander\",\"https://www.youtube.com/user/jasonh1234\",\"https://github.com/JayHoltslander\",\"https://profiles.wordpress.org/jasonh1234\",\"https://angel.co/j_holtslander\",\"https://www.foursquare.com/user/184843\",\"https://jholtslander.yelp.ca\",\"https://codepen.io/j_holtslander/\",\"https://stackoverflow.com/users/751570/jay\",\"https://dribbble.com/j_holtslander\",\"http://jasonh1234.deviantart.com/\",\"https://www.behance.net/j_holtslander\",\"https://www.flickr.com/people/jasonh1234/\",\"https://medium.com/@j_holtslander\"]}";

		VerifiableCredential vcJson = cb.id(id)
				.type("TestCredential", "JsonCredential")
				.properties(jsonProps)
				.seal(TestConfig.storePass);
		vcJson.getMetadata().setAlias("json");
		store.storeCredential(vcJson);

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
		System.out.print("Generate user2 DID...");

		DIDDocument doc = identity.newDid(TestConfig.storePass);
		doc.getMetadata().setAlias("User2");

		System.out.print(doc.getSubject() + "...");

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
		System.out.print("Generate user3 DID...");

		DIDDocument doc = identity.newDid(TestConfig.storePass);
		doc.getMetadata().setAlias("User3");
		doc.publish(TestConfig.storePass);

		System.out.print(doc.getSubject() + "...");

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

	private void createTestUser4() throws DIDException, IOException {
		// index = 4;
		System.out.print("Generate user4 DID...");

		DIDDocument doc = identity.newDid(TestConfig.storePass);
		doc.getMetadata().setAlias("User4");
		doc.publish(TestConfig.storePass);

		System.out.print(doc.getSubject() + "...");

		users[3] = doc;

		DIDURL id = doc.getDefaultPublicKeyId();
		HDKey key = rootPrivateKey.derive(HDKey.DERIVE_PATH_PREFIX + 4);
		writeTo("user4.id." + id.getFragment() + ".sk", key.serializeBase58());

		String json = doc.toString(true);
		writeTo("user4.id.normalized.json", json);

		json = formatJson(json);
		writeTo("user4.id.json", json);

		json = doc.toString(false);
		writeTo("user4.id.compact.json", json);

		System.out.println(doc.isValid() ? "OK" : "Error");
	}

	private void createExampleCorp() throws DIDException, IOException {
		System.out.print("Generate ExampleCorp DID...");

		DID did = new DID("did:elastos:example");
		DIDDocument doc = issuer.newCustomizedDid(did, TestConfig.storePass);

		System.out.print(did + "...");

		Issuer selfIssuer = new Issuer(doc);
		VerifiableCredential.Builder cb = selfIssuer.issueFor(doc.getSubject());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", "Example LLC");
		props.put("website", "https://example.com/");
		props.put("email", "contact@example.com");

		VerifiableCredential vc = cb.id("#profile")
				.type("BasicProfileCredential", "SelfProclaimedCredential")
				.properties(props)
				.seal(TestConfig.storePass);

		DIDDocument.Builder db = doc.edit();
		db.addCredential(vc);

		doc = db.seal(TestConfig.storePass);
		store.storeDid(doc);
		doc.publish(TestConfig.storePass);

		exampleCorp = doc;

		String json = exampleCorp.toString(true);
		writeTo("examplecorp.id.normalized.json", json);

		json = formatJson(json);
		writeTo("examplecorp.id.json", json);

		json = exampleCorp.toString(false);
		writeTo("examplecorp.id.compact.json", json);

		System.out.println(doc.isValid() ? "OK" : "Error");
	}

	private void createFooBar() throws DIDException, IOException {
		System.out.print("Generate FooBar DID...");

		DID[] controllers = {users[0].getSubject(), users[1].getSubject(), users[2].getSubject()};
		DID did = new DID("did:elastos:foobar");
		DIDDocument doc = users[0].newCustomizedDid(did, controllers, 2, TestConfig.storePass);

		System.out.print(did + "...");

		DIDURL signKey = users[0].getDefaultPublicKeyId();

		// Add public keys embedded credentials
		DIDDocument.Builder db = doc.edit(users[0]);

		HDKey temp = TestData.generateKeypair();
		db.addAuthenticationKey("#key2", temp.getPublicKeyBase58());
		store.storePrivateKey(new DIDURL(doc.getSubject(), "#key2"),
				temp.serialize(), TestConfig.storePass);
		writeTo("foobar.id.key2.sk", temp.serializeBase58());

		temp = TestData.generateKeypair();
		db.addAuthenticationKey("#key3", temp.getPublicKeyBase58());
		store.storePrivateKey(new DIDURL(doc.getSubject(), "#key3"),
				temp.serialize(), TestConfig.storePass);
		writeTo("foobar.id.key3.sk", temp.serializeBase58());

		db.addService("#vault", "Hive.Vault.Service",
				"https://foobar.com/vault");
		db.addService("#vcr", "CredentialRepositoryService",
				"https://foobar.com/credentials");

		Issuer selfIssuer = new Issuer(doc, signKey);
		VerifiableCredential.Builder cb = selfIssuer.issueFor(doc.getSubject());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", "Foo Bar Inc");
		props.put("language", "Chinese");
		props.put("email", "contact@foobar.com");

		VerifiableCredential vcProfile = cb.id("#profile")
				.type("BasicProfileCredential", "SelfProclaimedCredential")
				.properties(props)
				.seal(TestConfig.storePass);

		Issuer kycIssuer = new Issuer(exampleCorp);
		cb = kycIssuer.issueFor(doc.getSubject());

		props.clear();
		props.put("email", "foobar@example.com");

		VerifiableCredential vcEmail = cb.id("#email")
				.type("BasicProfileCredential",
						"InternetAccountCredential", "EmailCredential")
				.properties(props)
				.seal(TestConfig.storePass);

		db.addCredential(vcProfile);
		db.addCredential(vcEmail);
		doc = db.seal(TestConfig.storePass);
		doc = users[2].sign(doc, TestConfig.storePass);
		store.storeDid(doc);
		doc.publish(signKey, TestConfig.storePass);

		String json = doc.toString(true);
		writeTo("foobar.id.normalized.json", json);

		json = formatJson(json);
		writeTo("foobar.id.json", json);

		json = doc.toString(false);
		writeTo("foobar.id.compact.json", json);

		System.out.println(doc.isValid() ? "OK" : "Error");

		DIDURL id = new DIDURL(doc.getSubject(), "#services");
		System.out.print("Generate credential: " + id + "...");

		cb = selfIssuer.issueFor(doc.getSubject());

		props.clear();
		props.put("consultation", "https://foobar.com/consultation");
		props.put("Outsourceing", "https://foobar.com/outsourcing");

		VerifiableCredential vcServices = cb.id(id)
				.type("BasicProfileCredential", "SelfProclaimedCredential")
				.properties(props)
				.seal(TestConfig.storePass);
		store.storeCredential(vcServices);

		json = vcServices.toString(true);
		writeTo("foobar.vc.services.normalized.json", json);

		json = formatJson(json);
		writeTo("foobar.vc.services.json", json);

		json = vcServices.toString(false);
		writeTo("foobar.vc.services.compact.json", json);

		//System.out.println(vcPassport.isValid() ? "OK" : "Error");
		System.out.println("OK");

		id = new DIDURL(doc.getSubject(), "#license");
		System.out.print("Generate credential: " + id + "...");

		cb = kycIssuer.issueFor(doc.getSubject());

		props.clear();
		props.put("license-id", "20201021C889");
		props.put("scope", "Consulting");

		VerifiableCredential vcLicense = cb.id(id)
				.type("LicenseCredential")
				.properties(props)
				.seal(TestConfig.storePass);
		store.storeCredential(vcLicense);

		json = vcLicense.toString(true);
		writeTo("foobar.vc.license.normalized.json", json);

		json = formatJson(json);
		writeTo("foobar.vc.license.json", json);

		json = vcLicense.toString(false);
		writeTo("foobar.vc.license.compact.json", json);

		//System.out.println(vcPassport.isValid() ? "OK" : "Error");
		System.out.println("OK");

		System.out.print("Generate presentation...");

		VerifiablePresentation.Builder pb = VerifiablePresentation.createFor(
				doc.getSubject(), signKey, store);

		VerifiablePresentation vp = pb
				.credentials(vcProfile, vcEmail)
				.credentials(vcServices)
				.credentials(vcLicense)
				.realm("https://example.com/")
				.nonce("873172f58701a9ee686f0630204fee59")
				.seal(TestConfig.storePass);

		json = vp.toString(true);
		writeTo("foobar.vp.nonempty.normalized.json", json);

		json = formatJson( vp.toString());
		writeTo("foobar.vp.nonempty.json", json);

		pb = VerifiablePresentation.createFor(
				doc.getSubject(), new DIDURL("did:elastos:foobar#key2"), store);

		vp = pb.realm("https://example.com/")
				.nonce("873172f58701a9ee686f0630204fee59")
				.seal(TestConfig.storePass);

		json = vp.toString(true);
		writeTo("foobar.vp.empty.normalized.json", json);

		json = formatJson( vp.toString());
		writeTo("foobar.vp.empty.json", json);

		System.out.println("OK");

		System.out.print("Creatr transfer ticket: " + did + "...");
		TransferTicket tt = users[0].createTransferTicket(doc.getSubject(), users[3].getSubject(), TestConfig.storePass);
		tt = users[2].sign(tt, TestConfig.storePass);

		json = tt.toString();
		writeTo("foobar.tt.json", json);

		System.out.println("OK");
	}

	private void createFoo() throws DIDException, IOException {
		System.out.print("Generate Foo DID...");

		DID did = new DID("did:elastos:foo");
		DID[] controllers = {users[1].getSubject()};
		DIDDocument doc = users[0].newCustomizedDid(did, controllers, 2, TestConfig.storePass);
		System.out.print(did + "...");

		doc = users[1].sign(doc, TestConfig.storePass);
		store.storeDid(doc);

		doc.setEffectiveController(users[1].getSubject());
		doc.publish(TestConfig.storePass);
		doc.setEffectiveController(null);

		String json = doc.toString(true);
		writeTo("foo.id.normalized.json", json);

		json = formatJson(json);
		writeTo("foo.id.json", json);

		json = doc.toString(false);
		writeTo("foo.id.compact.json", json);

		System.out.println(doc.isValid() ? "OK" : "Error");

		DIDURL id = new DIDURL(doc.getSubject(), "#email");
		System.out.print("Generate credential: " + id + "...");

		Issuer kycIssuer = new Issuer(issuer);
		VerifiableCredential.Builder cb = kycIssuer.issueFor(doc.getSubject());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("email", "foo@example.com");

		VerifiableCredential vc = cb.id(id)
				.type("InternetAccountCredential")
				.properties(props)
				.seal(TestConfig.storePass);
		store.storeCredential(vc);

		json = vc.toString(true);
		writeTo("foo.vc.email.normalized.json", json);

		json = formatJson(json);
		writeTo("foo.vc.email.json", json);

		json = vc.toString(false);
		writeTo("foo.vc.email.compact.json", json);

		System.out.println("OK");
	}

	private void createBar() throws DIDException, IOException {
		System.out.print("Generate Bar DID...");

		DID[] controllers = {users[1].getSubject(), users[2].getSubject()};
		DID did = new DID("did:elastos:bar");
		DIDDocument doc = users[0].newCustomizedDid(did, controllers, 3, TestConfig.storePass);

		System.out.print(did + "...");

		doc = users[1].sign(doc, TestConfig.storePass);
		doc = users[2].sign(doc, TestConfig.storePass);
		store.storeDid(doc);
		doc.publish(users[2].getDefaultPublicKeyId(), TestConfig.storePass);

		String json = doc.toString(true);
		writeTo("bar.id.normalized.json", json);

		json = formatJson(json);
		writeTo("bar.id.json", json);

		json = doc.toString(false);
		writeTo("bar.id.compact.json", json);

		System.out.println(doc.isValid() ? "OK" : "Error");
	}

	private void createBaz() throws DIDException, IOException {
		System.out.print("Generate Baz DID...");

		DID[] controllers = {users[1].getSubject(), users[2].getSubject()};
		DID did = new DID("did:elastos:baz");
		DIDDocument doc = users[0].newCustomizedDid(did, controllers, 1, TestConfig.storePass);

		System.out.print(did + "...");

		store.storeDid(doc);
		doc.publish(users[0].getDefaultPublicKeyId(), TestConfig.storePass);

		String json = doc.toString(true);
		writeTo("baz.id.normalized.json", json);

		json = formatJson(json);
		writeTo("baz.id.json", json);

		json = doc.toString(false);
		writeTo("baz.id.compact.json", json);

		System.out.println(doc.isValid() ? "OK" : "Error");

		System.out.print("Creatr transfer ticket: " + did + "...");
		TransferTicket tt = users[1].createTransferTicket(doc.getSubject(), users[3].getSubject(), TestConfig.storePass);

		json = tt.toString();
		writeTo("baz.tt.json", json);

		System.out.println("OK");
	}

	public void createTestFiles() throws IOException, DIDException {
		init(TestConfig.tempDir + File.separator + "DIDTestFiles.v2");
		createTestIssuer();
		createTestUser1();
		createTestUser2();
		createTestUser3();
		createTestUser4();
		createExampleCorp();
		createFooBar();
		createFoo();
		createBar();
		createBaz();
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
