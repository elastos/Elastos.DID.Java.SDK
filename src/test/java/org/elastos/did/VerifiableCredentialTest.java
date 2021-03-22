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

package org.elastos.did;

import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;
import java.util.Random;

import org.elastos.did.backend.CredentialBiography;
import org.elastos.did.backend.IDChainRequest;
import org.elastos.did.exception.CredentialAlreadyExistException;
import org.elastos.did.exception.CredentialRevokedException;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDTransactionException;
import org.elastos.did.utils.DIDTestExtension;
import org.elastos.did.utils.TestConfig;
import org.elastos.did.utils.TestData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ExtendWith(DIDTestExtension.class)
public class VerifiableCredentialTest {
	private TestData testData;

	private static final Logger log = LoggerFactory.getLogger(VerifiableCredentialTest.class);

    @BeforeEach
    public void beforeEach() throws DIDException {
    	testData = new TestData();
    }

    @AfterEach
    public void afterEach() {
    	testData.cleanup();
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testKycCredential(int version) throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(version);

    	DIDDocument issuer = cd.getDocument("issuer");
		DIDDocument user = cd.getDocument("user1");

		VerifiableCredential vc = cd.getCredential("user1", "twitter");

		assertEquals(new DIDURL(user.getSubject(), "#twitter"), vc.getId());

		assertTrue(vc.getType().contains("InternetAccountCredential"));
		assertTrue(vc.getType().contains("TwitterCredential"));

		assertEquals(issuer.getSubject(), vc.getIssuer());
		assertEquals(user.getSubject(), vc.getSubject().getId());

		assertEquals("@john", vc.getSubject().getProperty("twitter"));

		assertNotNull(vc.getIssuanceDate());
		assertNotNull(vc.getExpirationDate());

		assertFalse(vc.isSelfProclaimed());
		assertFalse(vc.isExpired());
		assertTrue(vc.isGenuine());
		assertTrue(vc.isValid());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testSelfProclaimedCredential(int version) throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(version);

    	DIDDocument user = cd.getDocument("user1");
		VerifiableCredential vc = cd.getCredential("user1", "passport");

		assertEquals(new DIDURL(user.getSubject(), "#passport"), vc.getId());

		assertTrue(vc.getType().contains("BasicProfileCredential"));
		assertTrue(vc.getType().contains("SelfProclaimedCredential"));

		assertEquals(user.getSubject(), vc.getIssuer());
		assertEquals(user.getSubject(), vc.getSubject().getId());

		assertEquals("Singapore", vc.getSubject().getProperty("nation"));
		assertEquals("S653258Z07", vc.getSubject().getProperty("passport"));

		assertNotNull(vc.getIssuanceDate());
		assertNotNull(vc.getExpirationDate());

		assertTrue(vc.isSelfProclaimed());
		assertFalse(vc.isExpired());
		assertTrue(vc.isGenuine());
		assertTrue(vc.isValid());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testJsonCredential(int version) throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(version);

    	DIDDocument issuer = cd.getDocument("issuer");
    	DIDDocument user = cd.getDocument("user1");
		VerifiableCredential vc = cd.getCredential("user1", "json");

		assertEquals(new DIDURL(user.getSubject(), "#json"), vc.getId());

		assertTrue(vc.getType().contains("JsonCredential"));
		assertTrue(vc.getType().contains("TestCredential"));

		assertEquals(issuer.getSubject(), vc.getIssuer());
		assertEquals(user.getSubject(), vc.getSubject().getId());

		assertEquals("Technologist", vc.getSubject().getProperty("Description"));
		assertEquals(true, vc.getSubject().getProperty("booleanValue"));
		assertEquals(1234, vc.getSubject().getProperty("numberValue"));

		assertNotNull(vc.getIssuanceDate());
		assertNotNull(vc.getExpirationDate());

		assertFalse(vc.isSelfProclaimed());
		assertFalse(vc.isExpired());
		assertTrue(vc.isGenuine());
		assertTrue(vc.isValid());
	}

    @Test
    public void testKycCredentialToCid() throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(2);
    	cd.loadAll();

    	DIDDocument issuer = cd.getDocument("issuer");
    	DIDDocument foo = cd.getDocument("foo");

    	VerifiableCredential vc = cd.getCredential("foo", "email");

		assertEquals(new DIDURL(foo.getSubject(), "#email"), vc.getId());

		assertTrue(vc.getType().contains("InternetAccountCredential"));
		assertFalse(vc.getType().contains("ProfileCredential"));

		assertEquals(issuer.getSubject(), vc.getIssuer());
		assertEquals(foo.getSubject(), vc.getSubject().getId());

		assertEquals("foo@example.com", vc.getSubject().getProperty("email"));

		assertNotNull(vc.getIssuanceDate());
		assertNotNull(vc.getExpirationDate());

		assertFalse(vc.isSelfProclaimed());
		assertFalse(vc.isExpired());
		assertTrue(vc.isGenuine());
		assertTrue(vc.isValid());
    }

    @Test
    public void testKycCredentialFromCid() throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(2);
    	cd.loadAll();

    	DIDDocument exampleCorp = cd.getDocument("examplecorp");
    	DIDDocument foobar = cd.getDocument("foobar");

    	VerifiableCredential vc = cd.getCredential("foobar", "license");

		assertEquals(new DIDURL(foobar.getSubject(), "#license"), vc.getId());

		assertTrue(vc.getType().contains("LicenseCredential"));
		assertFalse(vc.getType().contains("ProfileCredential"));

		assertEquals(exampleCorp.getSubject(), vc.getIssuer());
		assertEquals(foobar.getSubject(), vc.getSubject().getId());

		assertEquals("20201021C889", vc.getSubject().getProperty("license-id"));
		assertEquals("Consulting", vc.getSubject().getProperty("scope"));

		assertNotNull(vc.getIssuanceDate());
		assertNotNull(vc.getExpirationDate());

		assertFalse(vc.isSelfProclaimed());
		assertFalse(vc.isExpired());
		assertTrue(vc.isGenuine());
		assertTrue(vc.isValid());
    }

    @Test
    public void testSelfProclaimedCredentialFromCid() throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(2);
    	cd.loadAll();

    	DIDDocument foobar = cd.getDocument("foobar");

    	VerifiableCredential vc = cd.getCredential("foobar", "services");

		assertEquals(new DIDURL(foobar.getSubject(), "#services"), vc.getId());

		assertTrue(vc.getType().contains("SelfProclaimedCredential"));
		assertTrue(vc.getType().contains("BasicProfileCredential"));

		assertEquals(foobar.getSubject(), vc.getIssuer());
		assertEquals(foobar.getSubject(), vc.getSubject().getId());

		assertEquals("https://foobar.com/outsourcing", vc.getSubject().getProperty("Outsourceing"));
		assertEquals("https://foobar.com/consultation", vc.getSubject().getProperty("consultation"));

		assertNotNull(vc.getIssuanceDate());
		assertNotNull(vc.getExpirationDate());

		assertTrue(vc.isSelfProclaimed());
		assertFalse(vc.isExpired());
		assertTrue(vc.isGenuine());
		assertTrue(vc.isValid());
    }

    @ParameterizedTest
    @CsvSource({
    	"1,user1,twitter",
    	"1,user1,passport",
    	"1,user1,json",
    	"2,user1,twitter",
    	"2,user1,passport",
    	"2,user1,json",
    	"2,foobar,license",
    	"2,foobar,services",
    	"2,foo,email"})
	public void testParseAndSerializeJsonCredential(int version, String did, String vc)
			throws DIDException, IOException {
	   	TestData.CompatibleData cd = testData.getCompatibleData(version);
	   	cd.loadAll();

		String normalizedJson = cd.getCredentialJson(did, vc, "normalized");
		VerifiableCredential normalized = VerifiableCredential.parse(normalizedJson);

		String compactJson = cd.getCredentialJson(did, vc, "compact");
		VerifiableCredential compact = VerifiableCredential.parse(compactJson);

		VerifiableCredential credential = cd.getCredential(did, vc);

		assertFalse(credential.isExpired());
		assertTrue(credential.isGenuine());
		assertTrue(credential.isValid());

		assertEquals(normalizedJson, normalized.toString(true));
		assertEquals(normalizedJson, compact.toString(true));
		assertEquals(normalizedJson, credential.toString(true));

		// Don't check the compact mode for the old versions
		if (cd.isLatestVersion()) {
			assertEquals(compactJson, normalized.toString(false));
			assertEquals(compactJson, compact.toString(false));
			assertEquals(compactJson, credential.toString(false));
		}
	}

    @ParameterizedTest
    @CsvSource({
    	"1,user1,twitter",
    	"1,user1,passport",
    	"1,user1,json",
    	"2,user1,twitter",
    	"2,user1,passport",
    	"2,user1,json",
    	"2,foobar,license",
    	"2,foobar,services",
    	"2,foo,email"})
    public void testDeclareCrendential(int version, String did, String vc)
			throws DIDException, IOException {
	   	TestData.CompatibleData cd = testData.getCompatibleData(version);
	   	cd.loadAll();

		VerifiableCredential credential = cd.getCredential(did, vc);
		// Sign key for customized DID
		DIDDocument doc = credential.getSubject().getId().resolve();
		DIDURL signKey = null;
		if (doc.getControllerCount() > 1) {
			Random rnd = new Random();
			int index = (rnd.nextInt() & Integer.MAX_VALUE) % doc.getControllerCount();
			signKey = doc.getControllers().get(index).resolve().getDefaultPublicKeyId();
		}

		credential.declare(signKey, TestConfig.storePass);

		DIDURL id = credential.getId();
		VerifiableCredential resolved = VerifiableCredential.resolve(id);
		assertNotNull(resolved);

		assertEquals(credential.toString(), resolved.toString());

		CredentialMetadata metadata = resolved.getMetadata();
		assertNotNull(metadata);
		assertNotNull(metadata.getPublishTime());
		assertNotNull(metadata.getTransactionId());
		assertFalse(resolved.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id, credential.getIssuer());
		assertNotNull(bio);
		assertEquals(1, bio.getAllTransactions().size());
		assertEquals(IDChainRequest.Operation.DECLARE, bio.getTransaction(0).getRequest().getOperation());
    }

    @Test
    public void testDeclareCrendentials() throws DIDException {
	   	TestData.InstantData sd = testData.getInstantData();

	   	String[][] vcds = {
	   			{ "user1", "twitter" },
	   			{ "user1", "passport" },
	   			{ "user1", "json" },
	   			{ "user1", "jobposition" },
	   			{ "foobar", "license" },
	   			{ "foobar", "services" },
	   			{ "foo" , "email" }
	   	};

	   	for (String[] vcd : vcds) {
			VerifiableCredential credential = sd.getCredential(vcd[0], vcd[1]);
			// Sign key for customized DID
			DIDDocument doc = credential.getSubject().getId().resolve();
			DIDURL signKey = null;
			if (doc.getControllerCount() > 1) {
				Random rnd = new Random();
				int index = (rnd.nextInt() & Integer.MAX_VALUE) % doc.getControllerCount();
				signKey = doc.getControllers().get(index).resolve().getDefaultPublicKeyId();
			}

			credential.declare(signKey, TestConfig.storePass);

			DIDURL id = credential.getId();
			VerifiableCredential resolved = VerifiableCredential.resolve(id);
			assertNotNull(resolved);

			assertEquals(credential.toString(), resolved.toString());

			CredentialMetadata metadata = resolved.getMetadata();
			assertNotNull(metadata);
			assertNotNull(metadata.getPublishTime());
			assertNotNull(metadata.getTransactionId());
			assertFalse(resolved.isRevoked());

			CredentialBiography bio = VerifiableCredential.resolveBiography(id, credential.getIssuer());
			assertNotNull(bio);
			assertEquals(1, bio.getAllTransactions().size());
			assertEquals(IDChainRequest.Operation.DECLARE, bio.getTransaction(0).getRequest().getOperation());
	   	}
    }

    @ParameterizedTest
    @CsvSource({
    	"1,user1,twitter",
    	"1,user1,passport",
    	"1,user1,json",
    	"2,user1,twitter",
    	"2,user1,passport",
    	"2,user1,json",
    	"2,foobar,license",
    	"2,foobar,services",
    	"2,foo,email"})
    public void testRevokeCrendential(int version, String did, String vc)
			throws DIDException, IOException {
	   	TestData.CompatibleData cd = testData.getCompatibleData(version);
	   	cd.loadAll();

		VerifiableCredential credential = cd.getCredential(did, vc);
		assertFalse(credential.wasDeclared());

		// Sign key for customized DID
		DIDDocument doc = credential.getSubject().getId().resolve();
		DIDURL signKey = null;
		if (doc.getControllerCount() > 1) {
			Random rnd = new Random();
			int index = (rnd.nextInt() & Integer.MAX_VALUE) % doc.getControllerCount();
			signKey = doc.getControllers().get(index).resolve().getDefaultPublicKeyId();
		}

		credential.declare(signKey, TestConfig.storePass);

		DIDURL id = credential.getId();
		VerifiableCredential resolved = VerifiableCredential.resolve(id);
		assertNotNull(resolved);

		assertEquals(credential.toString(), resolved.toString());

		CredentialMetadata metadata = resolved.getMetadata();
		assertNotNull(metadata);
		assertNotNull(metadata.getPublishTime());
		assertNotNull(metadata.getTransactionId());
		assertFalse(resolved.isRevoked());

		assertTrue(credential.wasDeclared());

		credential.revoke(signKey, TestConfig.storePass);

		resolved = VerifiableCredential.resolve(id);
		assertNotNull(resolved);

		assertEquals(credential.toString(), resolved.toString());

		metadata = resolved.getMetadata();
		assertNotNull(metadata);
		assertNotNull(metadata.getPublishTime());
		assertNotNull(metadata.getTransactionId());
		assertTrue(resolved.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id, credential.getIssuer());
		assertNotNull(bio);
		assertEquals(2, bio.getAllTransactions().size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
		assertEquals(IDChainRequest.Operation.DECLARE, bio.getTransaction(1).getRequest().getOperation());
    }

    @ParameterizedTest
    @CsvSource({
    	"1,user1,twitter",
    	"1,user1,passport",
    	"1,user1,json",
    	"2,user1,twitter",
    	"2,user1,passport",
    	"2,user1,json",
    	"2,foobar,license",
    	"2,foobar,services",
    	"2,foo,email"})
    public void testIllegalRevoke(int version, String did, String vc)
			throws DIDException, IOException {
	   	TestData.CompatibleData cd = testData.getCompatibleData(version);
	   	cd.loadAll();

		VerifiableCredential credential = cd.getCredential(did, vc);
		assertFalse(credential.wasDeclared());

		// Sign key for customized DID
		DIDDocument doc = credential.getSubject().getId().resolve();
		DIDURL signKey = null;
		if (doc.getControllerCount() > 1) {
			Random rnd = new Random();
			int index = (rnd.nextInt() & Integer.MAX_VALUE) % doc.getControllerCount();
			signKey = doc.getControllers().get(index).resolve().getDefaultPublicKeyId();
		}

		credential.declare(signKey, TestConfig.storePass);

		DIDURL id = credential.getId();
		VerifiableCredential resolved = VerifiableCredential.resolve(id);
		assertNotNull(resolved);

		assertEquals(credential.toString(), resolved.toString());

		CredentialMetadata metadata = resolved.getMetadata();
		assertNotNull(metadata);
		assertNotNull(metadata.getPublishTime());
		assertNotNull(metadata.getTransactionId());
		assertFalse(resolved.isRevoked());

		assertTrue(credential.wasDeclared());

		assertThrows(DIDTransactionException.class, () -> {
		   	TestData.InstantData sd = testData.getInstantData();
		   	DIDDocument d = sd.getUser1Document();
			VerifiableCredential.revoke(credential.getId(), d, TestConfig.storePass);
		});

		resolved = VerifiableCredential.resolve(id);
		assertNotNull(resolved);

		assertEquals(credential.toString(), resolved.toString());

		metadata = resolved.getMetadata();
		assertNotNull(metadata);
		assertNotNull(metadata.getPublishTime());
		assertNotNull(metadata.getTransactionId());
		assertFalse(resolved.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id, credential.getIssuer());
		assertNotNull(bio);
		assertEquals(1, bio.getAllTransactions().size());
		assertEquals(IDChainRequest.Operation.DECLARE, bio.getTransaction(0).getRequest().getOperation());
    }

    @ParameterizedTest
    @CsvSource({
    	"2,foobar,license",
    	"2,foobar,services",
    	"2,foo,email"})
    public void testRevokeCrendentialWithDifferentKey(int version, String did, String vc)
			throws DIDException, IOException {
	   	TestData.CompatibleData cd = testData.getCompatibleData(version);
	   	cd.loadAll();

		VerifiableCredential credential = cd.getCredential(did, vc);
		assertFalse(credential.wasDeclared());

		// Sign key for customized DID
		DIDDocument doc = credential.getSubject().getId().resolve();
		DIDURL signKey = null;
		int index = 0;
		if (doc.getControllerCount() > 1) {
			Random rnd = new Random();
			index = (rnd.nextInt() & Integer.MAX_VALUE) % doc.getControllerCount();
			signKey = doc.getControllers().get(index).resolve().getDefaultPublicKeyId();
		}

		credential.declare(signKey, TestConfig.storePass);

		DIDURL id = credential.getId();
		VerifiableCredential resolved = VerifiableCredential.resolve(id);
		assertNotNull(resolved);

		assertEquals(credential.toString(), resolved.toString());

		CredentialMetadata metadata = resolved.getMetadata();
		assertNotNull(metadata);
		assertNotNull(metadata.getPublishTime());
		assertNotNull(metadata.getTransactionId());
		assertFalse(resolved.isRevoked());

		assertTrue(credential.wasDeclared());

		if (doc.getControllerCount() > 1) {
			index = ++index % doc.getControllerCount();
			signKey = doc.getControllers().get(index).resolve().getDefaultPublicKeyId();
		}

		credential.revoke(signKey, TestConfig.storePass);

		resolved = VerifiableCredential.resolve(id);
		assertNotNull(resolved);

		assertEquals(credential.toString(), resolved.toString());

		metadata = resolved.getMetadata();
		assertNotNull(metadata);
		assertNotNull(metadata.getPublishTime());
		assertNotNull(metadata.getTransactionId());
		assertTrue(resolved.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id, credential.getIssuer());
		assertNotNull(bio);
		assertEquals(2, bio.getAllTransactions().size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
		assertEquals(IDChainRequest.Operation.DECLARE, bio.getTransaction(1).getRequest().getOperation());
    }

    @ParameterizedTest
    @CsvSource({
    	"1,user1,twitter",
    	"1,user1,passport",
    	"1,user1,json",
    	"2,user1,twitter",
    	"2,user1,passport",
    	"2,user1,json",
    	"2,foobar,license",
    	"2,foobar,services",
    	"2,foo,email"})
    public void testDeclareAfterDeclare(int version, String did, String vc)
			throws DIDException, IOException {
	   	TestData.CompatibleData cd = testData.getCompatibleData(version);
	   	cd.loadAll();

		VerifiableCredential credential = cd.getCredential(did, vc);
		assertFalse(credential.wasDeclared());
		assertFalse(credential.isRevoked());

		// Sign key for customized DID
		DIDDocument doc = credential.getSubject().getId().resolve();
		DIDURL signKey = null;
		if (doc.getControllerCount() > 1) {
			Random rnd = new Random();
			int index = (rnd.nextInt() & Integer.MAX_VALUE) % doc.getControllerCount();
			signKey = doc.getControllers().get(index).resolve().getDefaultPublicKeyId();
		}

		credential.declare(signKey, TestConfig.storePass);
		VerifiableCredential resolved = VerifiableCredential.resolve(credential.getId());
		assertNotNull(resolved);
		assertTrue(credential.wasDeclared());
		assertFalse(credential.isRevoked());

		final DIDURL key = signKey;
		assertThrows(CredentialAlreadyExistException.class, () -> {
			credential.declare(key, TestConfig.storePass);
	    });

		CredentialBiography bio = VerifiableCredential.resolveBiography(credential.getId(), credential.getIssuer());
		assertNotNull(bio);
		assertEquals(1, bio.getAllTransactions().size());
		assertEquals(IDChainRequest.Operation.DECLARE, bio.getTransaction(0).getRequest().getOperation());
    }

    @ParameterizedTest
    @CsvSource({
    	"1,user1,twitter",
    	"1,user1,passport",
    	"1,user1,json",
    	"2,user1,twitter",
    	"2,user1,passport",
    	"2,user1,json",
    	"2,foobar,license",
    	"2,foobar,services",
    	"2,foo,email"})
    public void testDeclareAfterRevoke(int version, String did, String vc)
			throws DIDException, IOException {
	   	TestData.CompatibleData cd = testData.getCompatibleData(version);
	   	cd.loadAll();

		VerifiableCredential credential = cd.getCredential(did, vc);
		assertFalse(credential.wasDeclared());
		assertFalse(credential.isRevoked());

		// Sign key for customized DID
		DIDDocument doc = credential.getSubject().getId().resolve();
		DIDURL signKey = null;
		if (doc.getControllerCount() > 1) {
			Random rnd = new Random();
			int index = (rnd.nextInt() & Integer.MAX_VALUE) % doc.getControllerCount();
			signKey = doc.getControllers().get(index).resolve().getDefaultPublicKeyId();
		}

		credential.revoke(signKey, TestConfig.storePass);

		assertFalse(credential.wasDeclared());
		assertTrue(credential.isRevoked());

		VerifiableCredential resolved = VerifiableCredential.resolve(credential.getId());
		assertNull(resolved);

		final DIDURL key = signKey;
		assertThrows(CredentialRevokedException.class, () -> {
			credential.declare(key, TestConfig.storePass);
	    });

		CredentialBiography bio = VerifiableCredential.resolveBiography(credential.getId(), credential.getIssuer());
		assertNotNull(bio);
		assertEquals(1, bio.getAllTransactions().size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
    }

    @ParameterizedTest
    @CsvSource({
    	"2,foobar,license",
    	"2,foobar,services",
    	"2,foo,email"})
    public void testDeclareAfterRevokeWithDifferentKey(int version, String did, String vc)
			throws DIDException, IOException {
	   	TestData.CompatibleData cd = testData.getCompatibleData(version);
	   	cd.loadAll();

		VerifiableCredential credential = cd.getCredential(did, vc);
		assertFalse(credential.wasDeclared());
		assertFalse(credential.isRevoked());

		// Sign key for customized DID
		DIDDocument doc = credential.getSubject().getId().resolve();
		DIDURL signKey = null;
		int index = 0;
		if (doc.getControllerCount() > 1) {
			Random rnd = new Random();
			index = (rnd.nextInt() & Integer.MAX_VALUE) % doc.getControllerCount();
			signKey = doc.getControllers().get(index).resolve().getDefaultPublicKeyId();
		}

		credential.revoke(signKey, TestConfig.storePass);

		assertFalse(credential.wasDeclared());
		assertTrue(credential.isRevoked());

		VerifiableCredential resolved = VerifiableCredential.resolve(credential.getId());
		assertNull(resolved);

		if (doc.getControllerCount() > 1) {
			index = ++index % doc.getControllerCount();
			signKey = doc.getControllers().get(index).resolve().getDefaultPublicKeyId();
		}

		final DIDURL key = signKey;
		assertThrows(CredentialRevokedException.class, () -> {
			credential.declare(key, TestConfig.storePass);
	    });

		CredentialBiography bio = VerifiableCredential.resolveBiography(credential.getId(), credential.getIssuer());
		assertNotNull(bio);
		assertEquals(1, bio.getAllTransactions().size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
    }

    @ParameterizedTest
    @CsvSource({
    	"1,user1,twitter",
    	"1,user1,passport",
    	"1,user1,json",
    	"2,user1,twitter",
    	"2,user1,passport",
    	"2,user1,json",
    	"2,foobar,license",
    	"2,foobar,services",
    	"2,foo,email"})
    public void testDeclareAfterRevokeByIssuer(int version, String did, String vc)
			throws DIDException, IOException {
	   	TestData.CompatibleData cd = testData.getCompatibleData(version);
	   	cd.loadAll();

		VerifiableCredential credential = cd.getCredential(did, vc);
		assertFalse(credential.wasDeclared());
		assertFalse(credential.isRevoked());

		// Sign key for issuer
		DIDDocument issuer = credential.getIssuer().resolve();
		DIDURL signKey = null;
		if (issuer.getControllerCount() > 1) {
			Random rnd = new Random();
			int index = (rnd.nextInt() & Integer.MAX_VALUE) % issuer.getControllerCount();
			signKey = issuer.getControllers().get(index).resolve().getDefaultPublicKeyId();
		} else
			signKey = issuer.getDefaultPublicKeyId();

		credential.revoke(signKey, TestConfig.storePass);

		assertFalse(credential.wasDeclared());
		assertTrue(credential.isRevoked());

		VerifiableCredential resolved = VerifiableCredential.resolve(credential.getId());
		assertNull(resolved);

		DIDDocument doc = credential.getSubject().getId().resolve();
		if (doc.getControllerCount() > 1) {
			Random rnd = new Random();
			int index = (rnd.nextInt() & Integer.MAX_VALUE) % doc.getControllerCount();
			signKey = doc.getControllers().get(index).resolve().getDefaultPublicKeyId();
		}

		final DIDURL key = signKey;
		assertThrows(CredentialRevokedException.class, () -> {
			credential.declare(key, TestConfig.storePass);
	    });

		CredentialBiography bio = VerifiableCredential.resolveBiography(credential.getId(), credential.getIssuer());
		assertNotNull(bio);
		assertEquals(1, bio.getAllTransactions().size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
    }

    @ParameterizedTest
    @CsvSource({
    	"1,user1,twitter",
    	"1,user1,passport",
    	"1,user1,json",
    	"2,user1,twitter",
    	"2,user1,passport",
    	"2,user1,json",
    	"2,foobar,license",
    	"2,foobar,services",
    	"2,foo,email"})
    public void testDeclareAfterInvalidRevoke(int version, String did, String vc)
			throws DIDException, IOException {
	   	TestData.CompatibleData cd = testData.getCompatibleData(version);
	   	TestData.InstantData sd = testData.getInstantData();
	   	cd.loadAll();

		VerifiableCredential credential = cd.getCredential(did, vc);
		DIDURL id = credential.getId();

		assertFalse(credential.wasDeclared());
		assertFalse(credential.isRevoked());

		DIDDocument doc = sd.getUser1Document();
		VerifiableCredential.revoke(id, doc, TestConfig.storePass);

		assertFalse(credential.wasDeclared());
		assertFalse(credential.isRevoked());
		assertNull(VerifiableCredential.resolve(id));
		assertNull(VerifiableCredential.resolve(id, doc.getSubject()));

		doc = credential.getSubject().getId().resolve();
		DIDURL signKey = null;
		if (doc.getControllerCount() > 1) {
			Random rnd = new Random();
			int index = (rnd.nextInt() & Integer.MAX_VALUE) % doc.getControllerCount();
			signKey = doc.getControllers().get(index).resolve().getDefaultPublicKeyId();
		}

		credential.declare(signKey, TestConfig.storePass);

		VerifiableCredential resolved = VerifiableCredential.resolve(id);
		assertNotNull(resolved);

		assertEquals(credential.toString(), resolved.toString());

		CredentialMetadata metadata = resolved.getMetadata();
		assertNotNull(metadata);
		assertNotNull(metadata.getPublishTime());
		assertNotNull(metadata.getTransactionId());
		assertFalse(resolved.isRevoked());

		assertTrue(credential.wasDeclared());

		credential.revoke(signKey, TestConfig.storePass);

		resolved = VerifiableCredential.resolve(id);
		assertNotNull(resolved);

		assertEquals(credential.toString(), resolved.toString());

		metadata = resolved.getMetadata();
		assertNotNull(metadata);
		assertNotNull(metadata.getPublishTime());
		assertNotNull(metadata.getTransactionId());
		assertTrue(resolved.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id, credential.getIssuer());
		assertNotNull(bio);
		assertEquals(2, bio.getAllTransactions().size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
		assertEquals(IDChainRequest.Operation.DECLARE, bio.getTransaction(1).getRequest().getOperation());
    }

    @Test
    public void testListCrendentials() throws DIDException {
	   	TestData.InstantData sd = testData.getInstantData();

	   	String[][] vcds = {
	   			{ "user1", "twitter" },
	   			{ "user1", "passport" },
	   			{ "user1", "json" },
	   			{ "user1", "jobposition" },
	   			{ "foobar", "license" },
	   			{ "foobar", "services" },
	   			{ "foo" , "email" }
	   	};

	   	for (String[] vcd : vcds) {
			VerifiableCredential credential = sd.getCredential(vcd[0], vcd[1]);

			// Sign key for customized DID
			DIDDocument doc = credential.getSubject().getId().resolve();
			DIDURL signKey = null;
			if (doc.getControllerCount() > 1) {
				Random rnd = new Random();
				int index = (rnd.nextInt() & Integer.MAX_VALUE) % doc.getControllerCount();
				signKey = doc.getControllers().get(index).resolve().getDefaultPublicKeyId();
			}

			credential.declare(signKey, TestConfig.storePass);

			DIDURL id = credential.getId();
			VerifiableCredential resolved = VerifiableCredential.resolve(id);
			assertNotNull(resolved);

			assertEquals(credential.toString(), resolved.toString());

			CredentialMetadata metadata = resolved.getMetadata();
			assertNotNull(metadata);
			assertNotNull(metadata.getPublishTime());
			assertNotNull(metadata.getTransactionId());
			assertFalse(resolved.isRevoked());

			CredentialBiography bio = VerifiableCredential.resolveBiography(id, credential.getIssuer());
			assertNotNull(bio);
			assertEquals(1, bio.getAllTransactions().size());
			assertEquals(IDChainRequest.Operation.DECLARE, bio.getTransaction(0).getRequest().getOperation());
	   	}

	   	DIDDocument doc = sd.getUser1Document();
	   	DID did = doc.getSubject();
	   	List<DIDURL> ids = VerifiableCredential.list(did);
	   	assertNotNull(ids);
	   	assertEquals(4, ids.size());
	   	for (DIDURL id : ids) {
	   		VerifiableCredential vc = VerifiableCredential.resolve(id);
	   		assertNotNull(vc);
	   		assertEquals(id, vc.getId());
	   		assertTrue(vc.wasDeclared());
	   		assertFalse(vc.isRevoked());
	   	}

	   	doc = sd.getFooBarDocument();
	   	did = doc.getSubject();
	   	ids = VerifiableCredential.list(did);
	   	assertNotNull(ids);
	   	assertEquals(2, ids.size());
	   	for (DIDURL id : ids) {
	   		VerifiableCredential vc = VerifiableCredential.resolve(id);
	   		assertNotNull(vc);
	   		assertEquals(id, vc.getId());
	   		assertTrue(vc.wasDeclared());
	   		assertFalse(vc.isRevoked());
	   	}

	   	doc = sd.getFooDocument();
	   	did = doc.getSubject();
	   	ids = VerifiableCredential.list(did);
	   	assertNotNull(ids);
	   	assertEquals(1, ids.size());
	   	for (DIDURL id : ids) {
	   		VerifiableCredential vc = VerifiableCredential.resolve(id);
	   		assertNotNull(vc);
	   		assertEquals(id, vc.getId());
	   		assertTrue(vc.wasDeclared());
	   		assertFalse(vc.isRevoked());
	   	}

	   	doc = sd.getBarDocument();
	   	did = doc.getSubject();
	   	ids = VerifiableCredential.list(did);
	   	assertNull(ids);

	   	for (String[] vcd : vcds) {
			VerifiableCredential credential = sd.getCredential(vcd[0], vcd[1]);

			// Sign key for customized DID
			doc = credential.getSubject().getId().resolve();
			DIDURL signKey = null;
			if (doc.getControllerCount() > 1) {
				Random rnd = new Random();
				int index = (rnd.nextInt() & Integer.MAX_VALUE) % doc.getControllerCount();
				signKey = doc.getControllers().get(index).resolve().getDefaultPublicKeyId();
			}

			credential.revoke(signKey, TestConfig.storePass);

			DIDURL id = credential.getId();
			VerifiableCredential resolved = VerifiableCredential.resolve(id);
			assertNotNull(resolved);
			assertTrue(resolved.isRevoked());
	   	}

	   	doc = sd.getUser1Document();
	   	did = doc.getSubject();
	   	ids = VerifiableCredential.list(did);
	   	assertNotNull(ids);
	   	assertEquals(4, ids.size());
	   	for (DIDURL id : ids) {
	   		VerifiableCredential vc = VerifiableCredential.resolve(id);
	   		assertNotNull(vc);
	   		assertEquals(id, vc.getId());
	   		assertTrue(vc.wasDeclared());
	   		assertTrue(vc.isRevoked());
	   	}

	   	doc = sd.getFooBarDocument();
	   	did = doc.getSubject();
	   	ids = VerifiableCredential.list(did);
	   	assertNotNull(ids);
	   	assertEquals(2, ids.size());
	   	for (DIDURL id : ids) {
	   		VerifiableCredential vc = VerifiableCredential.resolve(id);
	   		assertNotNull(vc);
	   		assertEquals(id, vc.getId());
	   		assertTrue(vc.wasDeclared());
	   		assertTrue(vc.isRevoked());
	   	}

	   	doc = sd.getFooDocument();
	   	did = doc.getSubject();
	   	ids = VerifiableCredential.list(did);
	   	assertNotNull(ids);
	   	assertEquals(1, ids.size());
	   	for (DIDURL id : ids) {
	   		VerifiableCredential vc = VerifiableCredential.resolve(id);
	   		assertNotNull(vc);
	   		assertEquals(id, vc.getId());
	   		assertTrue(vc.wasDeclared());
	   		assertTrue(vc.isRevoked());
	   	}

	   	doc = sd.getBarDocument();
	   	did = doc.getSubject();
	   	ids = VerifiableCredential.list(did);
	   	assertNull(ids);
    }

    @Test
    public void testListPagination() throws DIDException {
    	TestData.InstantData sd = testData.getInstantData();

    	DIDDocument doc = sd.getUser1Document();
    	DID did = doc.getSubject();

    	Issuer selfIssuer = new Issuer(doc);

    	for (int i = 0; i < 1028; i++) {
    		log.trace("Creating test credential {}...", i);

    		VerifiableCredential vc = selfIssuer.issueFor(did)
    				.id("#test" + i)
    				.type("SelfProclaimedCredential")
    				.propertie("index", Integer.valueOf(i))
    				.seal(TestConfig.storePass);

    		vc.getMetadata().attachStore(doc.getStore());
    		vc.declare(TestConfig.storePass);

    		assertTrue(vc.wasDeclared());
    	}

    	int index = 1027;
    	List<DIDURL> ids = VerifiableCredential.list(did);
    	assertNotNull(ids);
    	assertEquals(128, ids.size());
	   	for (DIDURL id : ids) {
	   		log.trace("Resolving credential {}...", id.getFragment());

	   		DIDURL ref = new DIDURL(did, "#test" + index--);
	   		assertEquals(ref, id);

	   		VerifiableCredential vc = VerifiableCredential.resolve(id);

	   		assertNotNull(vc);
	   		assertEquals(ref, vc.getId());
	   		assertTrue(vc.wasDeclared());
	   	}

    	index = 1027;
    	ids = VerifiableCredential.list(did, 560);
    	assertNotNull(ids);
    	assertEquals(512, ids.size());
	   	for (DIDURL id : ids) {
	   		log.trace("Resolving credential {}...", id.getFragment());

	   		DIDURL ref = new DIDURL(did, "#test" + index--);
	   		assertEquals(ref, id);

	   		VerifiableCredential vc = VerifiableCredential.resolve(id);

	   		assertNotNull(vc);
	   		assertEquals(ref, vc.getId());
	   		assertTrue(vc.wasDeclared());
	   	}

    	ids = VerifiableCredential.list(did, 1028, 100);
    	assertNull(ids);

    	int skip = 0;
    	int limit = 256;
    	index = 1028;
    	while (true) {
    		int resultSize = index >= limit ? limit : index;
	    	ids = VerifiableCredential.list(did, skip, limit);
	    	if (ids == null)
	    		break;

	    	assertEquals(resultSize, ids.size());
		   	for (DIDURL id : ids) {
		   		log.trace("Resolving credential {}...", id.getFragment());

		   		DIDURL ref = new DIDURL(did, "#test" + --index);
		   		assertEquals(ref, id);

		   		VerifiableCredential vc = VerifiableCredential.resolve(id);

		   		assertNotNull(vc);
		   		assertEquals(ref, vc.getId());
		   		assertTrue(vc.wasDeclared());
		   	}

		   	skip += ids.size();
    	}
    	assertEquals(0, index);

    	skip = 200;
    	limit = 100;
    	index = 828;
    	while (true) {
    		int resultSize = index >= limit ? limit : index;
	    	ids = VerifiableCredential.list(did, skip, limit);
	    	if (ids == null)
	    		break;

	    	assertEquals(resultSize, ids.size());
		   	for (DIDURL id : ids) {
		   		log.trace("Resolving credential {}...", id.getFragment());

		   		DIDURL ref = new DIDURL(did, "#test" + --index);
		   		assertEquals(ref, id);

		   		VerifiableCredential vc = VerifiableCredential.resolve(id);

		   		assertNotNull(vc);
		   		assertEquals(ref, vc.getId());
		   		assertTrue(vc.wasDeclared());
		   	}

		   	skip += ids.size();
    	}
    	assertEquals(0, index);
    }
}
