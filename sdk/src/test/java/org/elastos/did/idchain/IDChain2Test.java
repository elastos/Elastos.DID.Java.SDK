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

package org.elastos.did.idchain;

import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.elastos.did.DID;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.DIDURL;
import org.elastos.did.Issuer;
import org.elastos.did.Mnemonic;
import org.elastos.did.RootIdentity;
import org.elastos.did.TransferTicket;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.backend.CredentialBiography;
import org.elastos.did.backend.CredentialList;
import org.elastos.did.backend.DIDBiography;
import org.elastos.did.backend.IDChainRequest;
import org.elastos.did.crypto.HDKey;
import org.elastos.did.exception.CredentialRevokedException;
import org.elastos.did.exception.DIDControllersChangedException;
import org.elastos.did.exception.DIDException;
import org.elastos.did.utils.DIDTestExtension;
import org.elastos.did.utils.TestData;
import org.elastos.did.utils.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@TestMethodOrder(OrderAnnotation.class)
@ExtendWith(DIDTestExtension.class)
public class IDChain2Test {
	private static List<Entity> persons;

	private static Entity Alice;
	private static Entity Bob;
	private static Entity Carol;
	private static Entity Dave;
	private static Entity Erin;
	private static Entity Frank;
	private static Entity Grace;

	private static DID foo1, foo2;
	private static DID bar1, bar2, bar3;
	//private static DID baz1, baz2, baz3;

	private static DIDURL foo1Vc, foo2Vc; // self-proclaimed VC
	private static DIDURL bar1Vc, bar2Vc, bar3Vc; // KYC VC

	private static final Logger log = LoggerFactory.getLogger(IDChain2Test.class);

	static class Entity {
		// Mnemonic passphrase and the store password should set by the end user.
		private final static String passphrase = "";  // Default is an empty string, or any user defined word
		private final static String storepass = "mypassword" + System.currentTimeMillis();

		// The entity name
		private String name;

		private DIDStore store;
		private DID did;
		private DID customizedDid;

		private List<DIDURL> selfProclaimedVcs;
		private List<DIDURL> kycVcs;

		private List<DIDURL> cidSelfProclaimedVcs;
		private List<DIDURL> cidKycVcs;

		protected Entity(String name) throws DIDException {
			this.name = name;

			selfProclaimedVcs = new ArrayList<DIDURL>();
			kycVcs = new ArrayList<DIDURL>();
			cidSelfProclaimedVcs = new ArrayList<DIDURL>();
			cidKycVcs = new ArrayList<DIDURL>();

			initRootIdentity();
			initDid();
		}

		private void initRootIdentity() throws DIDException {
			File storePath = new File(System.getProperty("java.io.tmpdir")
					+ File.separator + name + ".store");

			Utils.deleteFile(storePath);
			store = DIDStore.open(storePath);

			// Check the store whether contains the root private identity.
			if (store.containsRootIdentities())
				return; // Already exists

			// Create a mnemonic use default language(English).
			Mnemonic mg = Mnemonic.getInstance();
			String mnemonic = mg.generate();

			// Initialize the root identity.
			RootIdentity.create(mnemonic, passphrase, store, storepass);
		}

		private void initDid() throws DIDException {
			// Check the DID store already contains owner's DID(with private key).
			List<DID> dids = store.listDids((did) -> {
				try {
					return (did.getMetadata().getAlias().equals("me") &&
							store.containsPrivateKeys(did));
				} catch (DIDException e) {
					return false;
				}
			});

			if (dids.size() > 0) {
				// Already has DID
				this.did = dids.get(0);
				return;
			}

			RootIdentity id = store.loadRootIdentity();
			DIDDocument doc = id.newDid(storepass);
			doc.getMetadata().setAlias("me");
			doc.publish(storepass);

			this.did = doc.getSubject();
			log.debug("{} created DID: {}\n", getName(), did.toString());
		}

		public DID getDid() {
			return did;
		}

		public DIDDocument getDocument() throws DIDException {
			return store.loadDid(did);
		}

		protected void setCustomizedDid(DID did) {
			this.customizedDid = did;
		}

		public DID getCustomizedDid() {
			return customizedDid;
		}

		public DIDDocument getCustomizedDocument() throws DIDException {
			return store.loadDid(customizedDid);
		}

		public String getName() {
			return name;
		}

		protected DIDStore getStore() {
			return store;
		}

		protected String getStorePassword() {
			return storepass;
		}

		public void addSelfProclaimedCredential(DIDURL id) {
			if (id.getDid().equals(getDid()))
				selfProclaimedVcs.add(id);
			else if (id.getDid().equals(getCustomizedDid()))
				cidSelfProclaimedVcs.add(id);
			else
				throw new IllegalArgumentException("Invalid credential");
		}

		public List<DIDURL> getSelfProclaimedCredential(DID did) {
			if (did.equals(getDid()))
				return selfProclaimedVcs;
			else if (did.equals(getCustomizedDid()))
				return cidSelfProclaimedVcs;
			else
				return null;
		}

		public void addKycCredential(DIDURL id) {
			if (id.getDid().equals(getDid()))
				kycVcs.add(id);
			else if (id.getDid().equals(getCustomizedDid()))
				cidKycVcs.add(id);
			else
				throw new IllegalArgumentException("Invalid credential");
		}

		public List<DIDURL> getKycCredential(DID did) {
			if (did.equals(getDid()))
				return kycVcs;
			else if (did.equals(getCustomizedDid()))
				return cidKycVcs;
			else
				return null;
		}
	}

	@BeforeEach
	public void beforeEach() throws DIDException {
		TestData.waitForWalletAvaliable();
	}

	@Test
	@Order(0)
	public void beforeAll() throws DIDException {
		log.debug("Prepareing the DIDs for testing...");
		persons = new ArrayList<Entity>();

		Alice = new Entity("Alice");
		persons.add(Alice);

		Bob = new Entity("Bob");
		persons.add(Bob);

		Carol = new Entity("Carol");
		persons.add(Carol);

		Dave = new Entity("Dave");
		persons.add(Dave);

		Erin = new Entity("Erin");
		persons.add(Erin);

		Frank = new Entity("Frank");
		persons.add(Frank);

		Grace = new Entity("Grace");
		persons.add(Grace);
	}

	@Test
	@Order(1)
	public void testCreateCustomizedDid() throws DIDException {
		for (Entity person : persons) {
			assertNotNull(person.getDid().resolve());

			DIDDocument doc = person.getDocument();

			DID customizedDid = new DID("did:elastos:" + person.getName() + "Z" + System.currentTimeMillis());
			DIDDocument customizedDoc = doc.newCustomizedDid(customizedDid, person.getStorePassword());
			assertNotNull(customizedDoc);

			customizedDoc.publish(person.getStorePassword());

			DIDDocument resolvedDoc = customizedDid.resolve();
			assertNotNull(resolvedDoc);
			assertEquals(customizedDid, resolvedDoc.getSubject());
			assertEquals(1, resolvedDoc.getControllerCount());
			assertEquals(person.getDid(), resolvedDoc.getController());
			assertEquals(customizedDoc.getProof().getSignature(),
					resolvedDoc.getProof().getSignature());

			assertTrue(resolvedDoc.isValid());

			DIDBiography bio = customizedDid.resolveBiography();
			assertNotNull(bio);
			assertEquals(1, bio.size());
			assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

			person.setCustomizedDid(customizedDid);
		}
	}

	@Test
	@Order(2)
	public void testCreateMultisigCustomizedDid_1of2() throws DIDException {
		DID customizedDid = new DID("did:elastos:foo1" + "Z" + System.currentTimeMillis());

		// Alice create initially
		DIDDocument customizedDoc = Alice.getDocument().newCustomizedDid(customizedDid,
				new DID[] { Bob.getDid() }, 1, Alice.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Bob publish
		Bob.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Bob.getDid());
		customizedDoc.publish(Bob.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);

		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(2, resolvedDoc.getControllerCount());
		assertEquals("1:2", resolvedDoc.getMultiSignature().toString());
		List<DID> ctrls = new ArrayList<DID>();
		ctrls.add(Alice.getDid());
		ctrls.add(Bob.getDid());
		Collections.sort(ctrls);
		assertArrayEquals(resolvedDoc.getControllers().toArray(), ctrls.toArray());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		assertTrue(resolvedDoc.isValid());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		foo1 = customizedDid;
	}

	@Test
	@Order(3)
	public void testCreateMultisigCustomizedDid_2of2() throws DIDException {
		DID customizedDid = new DID("did:elastos:foo2" + "Z" + System.currentTimeMillis());

		// Alice create initially
		DIDDocument customizedDoc = Alice.getDocument().newCustomizedDid(customizedDid,
				new DID[] { Bob.getDid() }, 2, Alice.getStorePassword());
		assertFalse(customizedDoc.isValid());

		// Bob sign
		customizedDoc = Bob.getDocument().sign(customizedDoc, Bob.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Bob publish
		Bob.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Bob.getDid());
		customizedDoc.publish(Bob.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);

		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(2, resolvedDoc.getControllerCount());
		assertEquals("2:2", resolvedDoc.getMultiSignature().toString());
		List<DID> ctrls = new ArrayList<DID>();
		ctrls.add(Alice.getDid());
		ctrls.add(Bob.getDid());
		Collections.sort(ctrls);
		assertArrayEquals(resolvedDoc.getControllers().toArray(), ctrls.toArray());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		assertTrue(resolvedDoc.isValid());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		foo2 = customizedDid;
	}

	@Test
	@Order(4)
	public void testCreateMultisigCustomizedDid_1of3() throws DIDException {
		DID customizedDid = new DID("did:elastos:bar1" + "Z" + System.currentTimeMillis());

		// Alice create initially
		DIDDocument customizedDoc = Alice.getDocument().newCustomizedDid(customizedDid,
				new DID[] { Bob.getDid(), Carol.getDid() }, 1, Alice.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Alice publish
		customizedDoc.setEffectiveController(Alice.getDid());
		customizedDoc.publish(Alice.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);

		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(3, resolvedDoc.getControllerCount());
		assertEquals("1:3", resolvedDoc.getMultiSignature().toString());
		List<DID> ctrls = new ArrayList<DID>();
		ctrls.add(Alice.getDid());
		ctrls.add(Bob.getDid());
		ctrls.add(Carol.getDid());
		Collections.sort(ctrls);
		assertArrayEquals(resolvedDoc.getControllers().toArray(), ctrls.toArray());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		assertTrue(resolvedDoc.isValid());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		bar1 = customizedDid;
	}

	@Test
	@Order(5)
	public void testCreateMultisigCustomizedDid_2of3() throws DIDException {
		DID customizedDid = new DID("did:elastos:bar2" + "Z" + System.currentTimeMillis());

		// Alice create initially
		DIDDocument customizedDoc = Alice.getDocument().newCustomizedDid(customizedDid,
				new DID[] { Bob.getDid(), Carol.getDid() }, 2, Alice.getStorePassword());
		assertFalse(customizedDoc.isValid());

		// Bob sign
		customizedDoc = Bob.getDocument().sign(customizedDoc, Bob.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Carol publish
		Carol.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Carol.getDid());
		customizedDoc.publish(Carol.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);

		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(3, resolvedDoc.getControllerCount());
		assertEquals("2:3", resolvedDoc.getMultiSignature().toString());
		List<DID> ctrls = new ArrayList<DID>();
		ctrls.add(Alice.getDid());
		ctrls.add(Bob.getDid());
		ctrls.add(Carol.getDid());
		Collections.sort(ctrls);
		assertArrayEquals(resolvedDoc.getControllers().toArray(), ctrls.toArray());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		assertTrue(resolvedDoc.isValid());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		bar2 = customizedDid;
	}

	@Test
	@Order(6)
	public void testCreateMultisigCustomizedDid_3of3() throws DIDException {
		DID customizedDid = new DID("did:elastos:bar3" + "Z" + System.currentTimeMillis());

		// Alice create initially
		DIDDocument customizedDoc = Alice.getDocument().newCustomizedDid(customizedDid,
				new DID[] { Bob.getDid(), Carol.getDid() }, 3, Alice.getStorePassword());
		assertFalse(customizedDoc.isValid());

		// Bob sign
		customizedDoc = Bob.getDocument().sign(customizedDoc, Bob.getStorePassword());
		assertFalse(customizedDoc.isValid());

		// Bob sign
		customizedDoc = Carol.getDocument().sign(customizedDoc, Carol.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Carol publish
		Carol.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Carol.getDid());
		customizedDoc.publish(Carol.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);

		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(3, resolvedDoc.getControllerCount());
		assertEquals("3:3", resolvedDoc.getMultiSignature().toString());
		List<DID> ctrls = new ArrayList<DID>();
		ctrls.add(Alice.getDid());
		ctrls.add(Bob.getDid());
		ctrls.add(Carol.getDid());
		Collections.sort(ctrls);
		assertArrayEquals(resolvedDoc.getControllers().toArray(), ctrls.toArray());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		assertTrue(resolvedDoc.isValid());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		bar3 = customizedDid;
	}

	@Test
	@Order(7)
	public void testUpdateMultisigCustomizedDid_1of2() throws DIDException {
		DID customizedDid = foo1;
		HDKey newKey = TestData.generateKeypair();

		DIDDocument customizedDoc = customizedDid.resolve();

		// Bob edit the doc
		Bob.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Bob.getDid());
		DIDDocument.Builder db = customizedDoc.edit();

		// add a new authentication key
		DIDURL keyId = new DIDURL(customizedDid, "#signKey");
		db.addAuthenticationKey(keyId, newKey.getPublicKeyBase58());
		Bob.getStore().storePrivateKey(keyId, newKey.serialize(), Bob.getStorePassword());

		// add a self-proclaimed credential
		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", "Foo1");
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", "foo1@example.com");

		db.addCredential("#profile",
				new String[] { "https://ns.elastos.org/credentials/profile/v1#ProfileCredential",
						"https://ns.elastos.org/credentials/v1#SelfProclaimedCredential" },
				props, Bob.getStorePassword());

		customizedDoc = db.seal(Bob.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Bob publish
		Bob.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Bob.getDid());
		customizedDoc.publish(Bob.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);

		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(2, resolvedDoc.getControllerCount());
		assertEquals("1:2", resolvedDoc.getMultiSignature().toString());
		List<DID> ctrls = new ArrayList<DID>();
		ctrls.add(Alice.getDid());
		ctrls.add(Bob.getDid());
		Collections.sort(ctrls);
		assertArrayEquals(resolvedDoc.getControllers().toArray(), ctrls.toArray());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		assertTrue(resolvedDoc.isValid());
	}

	@Test
	@Order(8)
	public void testUpdateMultisigCustomizedDid_2of2() throws DIDException {
		DID customizedDid = foo2;
		HDKey newKey = TestData.generateKeypair();

		DIDDocument customizedDoc = customizedDid.resolve();

		// Bob edit the doc
		Bob.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Bob.getDid());
		DIDDocument.Builder db = customizedDoc.edit();

		// add a new authentication key
		DIDURL keyId = new DIDURL(customizedDid, "#signKey");
		db.addAuthenticationKey(keyId, newKey.getPublicKeyBase58());
		Bob.getStore().storePrivateKey(keyId, newKey.serialize(), Bob.getStorePassword());

		// add a self-proclaimed credential
		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", "Foo2");
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", "foo2@example.com");

		db.addCredential("#profile",
				new String[] { "https://ns.elastos.org/credentials/profile/v1#ProfileCredential",
						"https://ns.elastos.org/credentials/v1#SelfProclaimedCredential" },
				props, Bob.getStorePassword());

		customizedDoc = db.seal(Bob.getStorePassword());
		assertFalse(customizedDoc.isValid());

		// Alice sign
		customizedDoc = Alice.getDocument().sign(customizedDoc, Alice.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Alice publish
		Alice.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Alice.getDid());
		customizedDoc.publish(Alice.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);

		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(2, resolvedDoc.getControllerCount());
		assertEquals("2:2", resolvedDoc.getMultiSignature().toString());
		List<DID> ctrls = new ArrayList<DID>();
		ctrls.add(Alice.getDid());
		ctrls.add(Bob.getDid());
		Collections.sort(ctrls);
		assertArrayEquals(resolvedDoc.getControllers().toArray(), ctrls.toArray());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		assertTrue(resolvedDoc.isValid());
	}

	@Test
	@Order(9)
	public void testUpdateMultisigCustomizedDid_1of3() throws DIDException {
		DID customizedDid = bar1;
		HDKey newKey = TestData.generateKeypair();

		DIDDocument customizedDoc = customizedDid.resolve();

		// Carol edit the doc
		Carol.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Carol.getDid());
		DIDDocument.Builder db = customizedDoc.edit();

		// add a new authentication key
		DIDURL keyId = new DIDURL(customizedDid, "#signKey");
		db.addAuthenticationKey(keyId, newKey.getPublicKeyBase58());
		Carol.getStore().storePrivateKey(keyId, newKey.serialize(), Carol.getStorePassword());

		// add a self-proclaimed credential
		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", "Bar1");
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", "bar1@example.com");

		db.addCredential("#profile",
				new String[] { "https://ns.elastos.org/credentials/profile/v1#ProfileCredential",
						"https://ns.elastos.org/credentials/v1#SelfProclaimedCredential" },
				props, Carol.getStorePassword());

		customizedDoc = db.seal(Carol.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Bob publish
		Bob.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Bob.getDid());
		customizedDoc.publish(Bob.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);

		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(3, resolvedDoc.getControllerCount());
		assertEquals("1:3", resolvedDoc.getMultiSignature().toString());
		List<DID> ctrls = new ArrayList<DID>();
		ctrls.add(Alice.getDid());
		ctrls.add(Bob.getDid());
		ctrls.add(Carol.getDid());
		Collections.sort(ctrls);
		assertArrayEquals(resolvedDoc.getControllers().toArray(), ctrls.toArray());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		assertTrue(resolvedDoc.isValid());
	}

	@Test
	@Order(10)
	public void testUpdateMultisigCustomizedDid_2of3() throws DIDException {
		DID customizedDid = bar2;
		HDKey newKey = TestData.generateKeypair();

		DIDDocument customizedDoc = customizedDid.resolve();

		// Carol edit the doc
		Carol.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Carol.getDid());
		DIDDocument.Builder db = customizedDoc.edit();

		// add a new authentication key
		DIDURL keyId = new DIDURL(customizedDid, "#signKey");
		db.addAuthenticationKey(keyId, newKey.getPublicKeyBase58());
		Carol.getStore().storePrivateKey(keyId, newKey.serialize(), Carol.getStorePassword());

		// add a self-proclaimed credential
		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", "Bar1");
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", "bar1@example.com");

		db.addCredential("#profile",
				new String[] { "https://ns.elastos.org/credentials/profile/v1#ProfileCredential",
						"https://ns.elastos.org/credentials/v1#SelfProclaimedCredential" },
				props, Carol.getStorePassword());

		customizedDoc = db.seal(Carol.getStorePassword());
		assertFalse(customizedDoc.isValid());

		// Alice sign
		customizedDoc = Alice.getDocument().sign(customizedDoc, Alice.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Bob publish
		Bob.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Bob.getDid());
		customizedDoc.publish(Bob.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);

		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(3, resolvedDoc.getControllerCount());
		assertEquals("2:3", resolvedDoc.getMultiSignature().toString());
		List<DID> ctrls = new ArrayList<DID>();
		ctrls.add(Alice.getDid());
		ctrls.add(Bob.getDid());
		ctrls.add(Carol.getDid());
		Collections.sort(ctrls);
		assertArrayEquals(resolvedDoc.getControllers().toArray(), ctrls.toArray());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		assertTrue(resolvedDoc.isValid());
	}

	@Test
	@Order(11)
	public void testUpdateMultisigCustomizedDid_3of3() throws DIDException {
		DID customizedDid = bar3;
		HDKey newKey = TestData.generateKeypair();

		DIDDocument customizedDoc = customizedDid.resolve();

		// Carol edit the doc
		Carol.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Carol.getDid());
		DIDDocument.Builder db = customizedDoc.edit();

		// add a new authentication key
		DIDURL keyId = new DIDURL(customizedDid, "#signKey");
		db.addAuthenticationKey(keyId, newKey.getPublicKeyBase58());
		Carol.getStore().storePrivateKey(keyId, newKey.serialize(), Carol.getStorePassword());

		// add a self-proclaimed credential
		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", "Bar1");
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", "bar1@example.com");

		db.addCredential("#profile",
				new String[] { "https://ns.elastos.org/credentials/profile/v1#ProfileCredential",
						"https://ns.elastos.org/credentials/v1#SelfProclaimedCredential" },
				props, Carol.getStorePassword());

		customizedDoc = db.seal(Carol.getStorePassword());
		assertFalse(customizedDoc.isValid());

		// Alice sign
		customizedDoc = Alice.getDocument().sign(customizedDoc, Alice.getStorePassword());
		assertFalse(customizedDoc.isValid());

		// Bob sign
		customizedDoc = Bob.getDocument().sign(customizedDoc, Bob.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Bob publish
		Bob.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Bob.getDid());
		customizedDoc.publish(Bob.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);

		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(3, resolvedDoc.getControllerCount());
		assertEquals("3:3", resolvedDoc.getMultiSignature().toString());
		List<DID> ctrls = new ArrayList<DID>();
		ctrls.add(Alice.getDid());
		ctrls.add(Bob.getDid());
		ctrls.add(Carol.getDid());
		Collections.sort(ctrls);
		assertArrayEquals(resolvedDoc.getControllers().toArray(), ctrls.toArray());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		assertTrue(resolvedDoc.isValid());
	}

	@Test
	@Order(12)
	public void testChangeControllersWithUpdate_1of2() throws DIDException {
		DID customizedDid = foo1;

		DIDDocument customizedDoc = customizedDid.resolve();

		// Bob edit the doc
		Bob.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Bob.getDid());
		DIDDocument.Builder db = customizedDoc.edit();

		// Change the controllers
		db.removeController(Alice.getDid());
		db.addController(Carol.getDid());
		db.setMultiSignature(1);

		customizedDoc = db.seal(Bob.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Bob publish
		Bob.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Bob.getDid());

		// Should failed because the controllers changed
		// Here the exception raised from the SDK
		final DIDDocument doc = customizedDoc;
		assertThrows(DIDControllersChangedException.class, () -> {
			doc.publish(Bob.getStorePassword());
		});

		// TODO: how to verify the behavior of the ID chain
	}

	@Test
	@Order(13)
	public void testChangeControllersWithUpdate_2of2() throws DIDException {
		DID customizedDid = foo2;

		DIDDocument customizedDoc = customizedDid.resolve();

		// Bob edit the doc
		Bob.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Bob.getDid());
		DIDDocument.Builder db = customizedDoc.edit();

		// Change the controllers
		db.removeController(Alice.getDid());
		db.addController(Carol.getDid());
		db.setMultiSignature(2);

		customizedDoc = db.seal(Bob.getStorePassword());
		assertFalse(customizedDoc.isValid());

		// Carol sign
		customizedDoc = Carol.getDocument().sign(customizedDoc, Carol.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Carol publish
		Carol.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Carol.getDid());

		// Should failed because the controllers changed
		// Here the exception raised from the SDK
		final DIDDocument doc = customizedDoc;
		assertThrows(DIDControllersChangedException.class, () -> {
			doc.publish(Carol.getStorePassword());
		});

		// TODO: how to verify the behavior of the ID chain
	}

	@Test
	@Order(14)
	public void testChangeControllersWithUpdate_1of3() throws DIDException {
		DID customizedDid = bar1;

		DIDDocument customizedDoc = customizedDid.resolve();

		// Alice edit the doc
		Alice.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Alice.getDid());
		DIDDocument.Builder db = customizedDoc.edit();

		// Change the controllers
		db.removeController(Bob.getDid());
		db.addController(Dave.getDid());
		db.setMultiSignature(1);

		customizedDoc = db.seal(Alice.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Carol publish
		Carol.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Carol.getDid());

		// Should failed because the controllers changed
		// Here the exception raised from the SDK
		final DIDDocument doc = customizedDoc;
		assertThrows(DIDControllersChangedException.class, () -> {
			doc.publish(Carol.getStorePassword());
		});

		// TODO: how to verify the behavior of the ID chain
	}

	@Test
	@Order(15)
	public void testChangeControllersWithUpdate_2of3() throws DIDException {
		DID customizedDid = bar2;

		DIDDocument customizedDoc = customizedDid.resolve();

		// Alice edit the doc
		Alice.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Alice.getDid());
		DIDDocument.Builder db = customizedDoc.edit();

		// Change the controllers
		db.removeController(Bob.getDid());
		db.addController(Dave.getDid());
		db.setMultiSignature(2);

		customizedDoc = db.seal(Alice.getStorePassword());
		assertFalse(customizedDoc.isValid());

		// Carol sign
		customizedDoc = Carol.getDocument().sign(customizedDoc, Carol.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Carol publish
		Carol.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Carol.getDid());

		// Should failed because the controllers changed
		// Here the exception raised from the SDK
		final DIDDocument doc = customizedDoc;
		assertThrows(DIDControllersChangedException.class, () -> {
			doc.publish(Carol.getStorePassword());
		});

		// TODO: how to verify the behavior of the ID chain
	}

	@Test
	@Order(16)
	public void testChangeControllersWithUpdate_3of3() throws DIDException {
		DID customizedDid = bar3;

		DIDDocument customizedDoc = customizedDid.resolve();

		// Alice edit the doc
		Alice.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Alice.getDid());
		DIDDocument.Builder db = customizedDoc.edit();

		// Change the controllers
		db.removeController(Bob.getDid());
		db.addController(Dave.getDid());
		db.setMultiSignature(3);

		customizedDoc = db.seal(Alice.getStorePassword());
		assertFalse(customizedDoc.isValid());

		// Carol sign
		customizedDoc = Carol.getDocument().sign(customizedDoc, Carol.getStorePassword());
		assertFalse(customizedDoc.isValid());

		// Dave sign
		customizedDoc = Dave.getDocument().sign(customizedDoc, Dave.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Dave publish
		Dave.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Dave.getDid());

		// Should failed because the controllers changed
		// Here the exception raised from the SDK
		final DIDDocument doc = customizedDoc;
		assertThrows(DIDControllersChangedException.class, () -> {
			doc.publish(Carol.getStorePassword());
		});

		// TODO: how to verify the behavior of the ID chain
	}

	@Test
	@Order(17)
	public void testTransferCustomizedDid_1to1() throws DIDException {
		// Alice create a customized did: baz1
		DIDDocument doc = Alice.getDocument();

		DID customizedDid = new DID("did:elastos:baz1" + "Z" + System.currentTimeMillis());
		DIDDocument customizedDoc = doc.newCustomizedDid(customizedDid, Alice.getStorePassword());
		assertNotNull(customizedDoc);

		customizedDoc.publish(Alice.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);
		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(1, resolvedDoc.getControllerCount());
		assertEquals(Alice.getDid(), resolvedDoc.getController());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		assertTrue(resolvedDoc.isValid());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		// Alice prepare to transfer to Bob
		customizedDoc.setEffectiveController(Alice.getDid());
		TransferTicket ticket = customizedDoc.createTransferTicket(Bob.getDid(), Alice.getStorePassword());

		// Bob create the new document
		doc = Bob.getDocument();

		customizedDoc = doc.newCustomizedDid(customizedDid, true, Bob.getStorePassword());
		assertNotNull(customizedDoc);

		// Bob publish the DID and take the ownership
		customizedDoc.publish(ticket, Bob.getStorePassword());

		resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);
		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(1, resolvedDoc.getControllerCount());
		assertEquals(Bob.getDid(), resolvedDoc.getController());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		assertTrue(resolvedDoc.isValid());

		bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		// baz1 = customizedDid;
	}

	@Test
	@Order(18)
	public void testTransferCustomizedDid_1to2() throws DIDException {
		// Alice create a customized did: baz2
		DIDDocument doc = Alice.getDocument();

		DID customizedDid = new DID("did:elastos:baz2" + "Z" + System.currentTimeMillis());
		DIDDocument customizedDoc = doc.newCustomizedDid(customizedDid, Alice.getStorePassword());
		assertNotNull(customizedDoc);

		customizedDoc.publish(Alice.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);
		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(1, resolvedDoc.getControllerCount());
		assertEquals(Alice.getDid(), resolvedDoc.getController());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		assertTrue(resolvedDoc.isValid());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		// Alice prepare to transfer to Bob, Carol...
		customizedDoc.setEffectiveController(Alice.getDid());
		TransferTicket ticket = customizedDoc.createTransferTicket(Bob.getDid(), Alice.getStorePassword());

		// Bob create the new document
		doc = Bob.getDocument();

		customizedDoc = doc.newCustomizedDid(customizedDid,
				new DID[] { Bob.getDid(), Carol.getDid() }, 1,
				true, Bob.getStorePassword());
		assertNotNull(customizedDoc);

		// Bob publish the DID and take the ownership
		customizedDoc.publish(ticket, Bob.getStorePassword());

		resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);
		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(2, resolvedDoc.getControllerCount());
		assertEquals("1:2", resolvedDoc.getMultiSignature().toString());
		List<DID> ctrls = new ArrayList<DID>();
		ctrls.add(Bob.getDid());
		ctrls.add(Carol.getDid());
		Collections.sort(ctrls);
		assertArrayEquals(resolvedDoc.getControllers().toArray(), ctrls.toArray());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		assertTrue(resolvedDoc.isValid());

		bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		// baz2 = customizedDid;
	}

	@Test
	@Order(19)
	public void testTransferCustomizedDid_1to3_WithoutRequiredSig() throws DIDException {
		// Alice create a customized did: baz3
		DIDDocument doc = Alice.getDocument();

		DID customizedDid = new DID("did:elastos:baz3" + "Z" + System.currentTimeMillis());
		DIDDocument customizedDoc = doc.newCustomizedDid(customizedDid, Alice.getStorePassword());
		assertNotNull(customizedDoc);

		customizedDoc.publish(Alice.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);
		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(1, resolvedDoc.getControllerCount());
		assertEquals(Alice.getDid(), resolvedDoc.getController());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		assertTrue(resolvedDoc.isValid());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		// Alice prepare to transfer to Bob, Carol...
		customizedDoc.setEffectiveController(Alice.getDid());
		TransferTicket ticket = customizedDoc.createTransferTicket(Bob.getDid(), Alice.getStorePassword());

		// Carol create the new document
		doc = Carol.getDocument();

		customizedDoc = doc.newCustomizedDid(customizedDid,
				new DID[] { Bob.getDid(), Carol.getDid(), Dave.getDid() }, 2,
				true, Carol.getStorePassword());
		assertNotNull(customizedDoc);
		assertFalse(customizedDoc.isValid());

		// Dave sign
		customizedDoc = Dave.getDocument().sign(customizedDoc, Dave.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Dave publish the DID and take the ownership
		Dave.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Dave.getDid());

		// Should failed because of missing Bob's signature
		// Here the exception raised from the SDK
		final DIDDocument d = customizedDoc;
		Exception e = assertThrows(IllegalArgumentException.class, () -> {
			d.publish(ticket, Dave.getStorePassword());
		});
		assertEquals("Document not signed by: " + Bob.getDid(), e.getMessage());

		// TODO: how to verify the behavior of the ID chain

		// baz3 = customizedDid;
	}

	@Test
	@Order(20)
	public void testTransferCustomizedDid_2to1() throws DIDException {
		DID customizedDid = foo1;
		DIDDocument customizedDoc = customizedDid.resolve();
		assertNotNull(customizedDoc);

		// Bob prepare to transfer to Carol
		Bob.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Bob.getDid());
		TransferTicket ticket = customizedDoc.createTransferTicket(Carol.getDid(), Bob.getStorePassword());

		// Carol create the new document
		DIDDocument doc = Carol.getDocument();

		customizedDoc = doc.newCustomizedDid(customizedDid, true, Carol.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Carol publish the DID and take the ownership
		customizedDoc.publish(ticket, Carol.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);
		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(1, resolvedDoc.getControllerCount());
		assertEquals(Carol.getDid(), resolvedDoc.getController());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		assertTrue(resolvedDoc.isValid());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(3, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());
	}

	@Test
	@Order(21)
	public void testTransferCustomizedDid_2to2() throws DIDException {
		DID customizedDid = foo2;
		DIDDocument customizedDoc = customizedDid.resolve();
		assertNotNull(customizedDoc);

		// Alice prepare to transfer to Carol
		Alice.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Alice.getDid());
		TransferTicket ticket = customizedDoc.createTransferTicket(Carol.getDid(), Alice.getStorePassword());
		assertFalse(ticket.isValid());

		// Bob sign the ticket
		ticket = Bob.getDocument().sign(ticket, Bob.getStorePassword());
		assertTrue(ticket.isValid());

		// Carol create the new document
		DIDDocument doc = Carol.getDocument();

		customizedDoc = doc.newCustomizedDid(customizedDid,
				new DID[] { Carol.getDid(), Dave.getDid() },
				2, true, Carol.getStorePassword());
		assertFalse(customizedDoc.isValid());

		// Dave sign the doc
		customizedDoc = Dave.getDocument().sign(customizedDoc, Dave.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Dave publish the DID
		Dave.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Dave.getDid());
		customizedDoc.publish(ticket, Dave.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);
		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(2, resolvedDoc.getControllerCount());
		assertEquals("2:2", resolvedDoc.getMultiSignature().toString());
		List<DID> ctrls = new ArrayList<DID>();
		ctrls.add(Carol.getDid());
		ctrls.add(Dave.getDid());
		Collections.sort(ctrls);
		assertArrayEquals(resolvedDoc.getControllers().toArray(), ctrls.toArray());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		assertTrue(resolvedDoc.isValid());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(3, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());
	}

	@Test
	@Order(22)
	public void testTransferCustomizedDid_3to1() throws DIDException {
		DID customizedDid = bar1;
		DIDDocument customizedDoc = customizedDid.resolve();
		assertNotNull(customizedDoc);

		// Carol prepare to transfer to Dave
		Carol.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Carol.getDid());
		TransferTicket ticket = customizedDoc.createTransferTicket(Dave.getDid(), Carol.getStorePassword());

		// Dave create the new document
		DIDDocument doc = Dave.getDocument();

		customizedDoc = doc.newCustomizedDid(customizedDid, true, Dave.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Dave publish the DID and take the ownership
		customizedDoc.publish(ticket, Dave.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);
		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(1, resolvedDoc.getControllerCount());
		assertEquals(Dave.getDid(), resolvedDoc.getController());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		assertTrue(resolvedDoc.isValid());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(3, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());
	}

	@Test
	@Order(23)
	public void testTransferCustomizedDid_3to2() throws DIDException {
		DID customizedDid = bar2;
		DIDDocument customizedDoc = customizedDid.resolve();
		assertNotNull(customizedDoc);

		// Alice prepare to transfer to Dave
		Alice.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Alice.getDid());
		TransferTicket ticket = customizedDoc.createTransferTicket(Dave.getDid(), Alice.getStorePassword());
		assertFalse(ticket.isValid());

		// Carol sign the ticket
		ticket = Carol.getDocument().sign(ticket, Carol.getStorePassword());
		assertTrue(ticket.isValid());

		// Dave create the new document
		DIDDocument doc = Dave.getDocument();

		customizedDoc = doc.newCustomizedDid(customizedDid,
				new DID[] { Dave.getDid(), Erin.getDid() },
				2, true, Dave.getStorePassword());
		assertFalse(customizedDoc.isValid());

		// Erin sign the doc
		customizedDoc = Erin.getDocument().sign(customizedDoc, Erin.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Erin publish the DID
		Erin.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Erin.getDid());
		customizedDoc.publish(ticket, Erin.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);
		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(2, resolvedDoc.getControllerCount());
		assertEquals("2:2", resolvedDoc.getMultiSignature().toString());
		List<DID> ctrls = new ArrayList<DID>();
		ctrls.add(Erin.getDid());
		ctrls.add(Dave.getDid());
		Collections.sort(ctrls);
		assertArrayEquals(resolvedDoc.getControllers().toArray(), ctrls.toArray());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		assertTrue(resolvedDoc.isValid());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(3, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());
	}

	@Test
	@Order(24)
	public void testTransferCustomizedDid_3to3() throws DIDException {
		DID customizedDid = bar3;
		DIDDocument customizedDoc = customizedDid.resolve();
		assertNotNull(customizedDoc);

		// Alice prepare to transfer to Dave
		Alice.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Alice.getDid());
		TransferTicket ticket = customizedDoc.createTransferTicket(Dave.getDid(), Alice.getStorePassword());
		assertFalse(ticket.isValid());

		// Bob sign the ticket
		ticket = Bob.getDocument().sign(ticket, Bob.getStorePassword());
		assertFalse(ticket.isValid());

		// Carol sign the ticket
		ticket = Carol.getDocument().sign(ticket, Carol.getStorePassword());
		assertTrue(ticket.isValid());

		// Erin create the new document
		DIDDocument doc = Erin.getDocument();

		customizedDoc = doc.newCustomizedDid(customizedDid,
				new DID[] { Dave.getDid(), Erin.getDid(), Frank.getDid() },
				2, true, Erin.getStorePassword());
		assertFalse(customizedDoc.isValid());

		// Dave sign the doc
		customizedDoc = Dave.getDocument().sign(customizedDoc, Dave.getStorePassword());
		assertTrue(customizedDoc.isValid());

		// Frank publish the DID
		Frank.getStore().storeDid(customizedDoc);
		customizedDoc.setEffectiveController(Frank.getDid());
		customizedDoc.publish(ticket, Frank.getStorePassword());

		DIDDocument resolvedDoc = customizedDid.resolve();
		assertNotNull(resolvedDoc);
		assertEquals(customizedDid, resolvedDoc.getSubject());
		assertEquals(3, resolvedDoc.getControllerCount());
		assertEquals("2:3", resolvedDoc.getMultiSignature().toString());
		List<DID> ctrls = new ArrayList<DID>();
		ctrls.add(Dave.getDid());
		ctrls.add(Erin.getDid());
		ctrls.add(Frank.getDid());
		Collections.sort(ctrls);
		assertArrayEquals(resolvedDoc.getControllers().toArray(), ctrls.toArray());
		assertEquals(customizedDoc.getProof().getSignature(),
				resolvedDoc.getProof().getSignature());

		assertTrue(resolvedDoc.isValid());

		DIDBiography bio = customizedDid.resolveBiography();
		assertNotNull(bio);
		assertEquals(3, bio.size());
		assertEquals(customizedDoc.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());
	}

	@Test
	@Order(100)
	public void testDeclareSelfProclaimedCredential() throws DIDException {
		for (Entity person : persons) {
			DIDDocument doc = person.getDocument();

			// add a self-proclaimed credential
			Map<String, Object> props = new HashMap<String, Object>();
			props.put("name", person.getName());
			props.put("gender", "Male");
			props.put("nationality", "Singapore");
			props.put("email", person.getName() + "@example.com");

			DIDURL id = new DIDURL(doc.getSubject(), "#profile-" + System.currentTimeMillis());

			VerifiableCredential vc = VerifiableCredential.resolve(id);
			assertNull(vc);

			VerifiableCredential.Builder cb = new Issuer(doc).issueFor(doc.getSubject());
			vc = cb.id(id)
				.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
				.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
				.properties(props)
				.seal(person.getStorePassword());

			person.getStore().storeCredential(vc);
			vc.declare(person.getStorePassword());

			VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
			assertNotNull(resolvedVc);
			assertEquals(id, resolvedVc.getId());
			assertTrue(resolvedVc.getType().contains("ProfileCredential"));
			assertTrue(resolvedVc.getType().contains("SelfProclaimedCredential"));
			assertEquals(doc.getSubject(), resolvedVc.getSubject().getId());
			assertEquals(vc.getProof().getSignature(),
					resolvedVc.getProof().getSignature());

			assertTrue(resolvedVc.isValid());

			CredentialBiography bio = VerifiableCredential.resolveBiography(id);
			assertNotNull(bio);
			assertEquals(1, bio.size());
			assertEquals(vc.getProof().getSignature(), bio.getTransaction(0).getRequest().getCredential().getProof().getSignature());

			person.addSelfProclaimedCredential(vc.getId());
		}
	}

	@Test
	@Order(101)
	public void testDeclareSelfProclaimedCredentialForCid() throws DIDException {
		for (Entity person : persons) {
			DIDDocument doc = person.getCustomizedDocument();

			// add a self-proclaimed credential
			Map<String, Object> props = new HashMap<String, Object>();
			props.put("name", person.getName());
			props.put("gender", "Male");
			props.put("nationality", "Singapore");
			props.put("email", person.getName() + "@example.com");

			DIDURL id = new DIDURL(doc.getSubject(), "#profile-" + System.currentTimeMillis());

			VerifiableCredential vc = VerifiableCredential.resolve(id);
			assertNull(vc);

			VerifiableCredential.Builder cb = new Issuer(doc).issueFor(doc.getSubject());
			vc = cb.id(id)
				.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
				.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
				.properties(props)
				.seal(person.getStorePassword());

			person.getStore().storeCredential(vc);
			vc.declare(person.getStorePassword());

			VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
			assertNotNull(resolvedVc);
			assertEquals(id, resolvedVc.getId());
			assertTrue(resolvedVc.getType().contains("ProfileCredential"));
			assertTrue(resolvedVc.getType().contains("SelfProclaimedCredential"));
			assertEquals(doc.getSubject(), resolvedVc.getSubject().getId());
			assertEquals(vc.getProof().getSignature(),
					resolvedVc.getProof().getSignature());

			assertTrue(resolvedVc.isValid());

			CredentialBiography bio = VerifiableCredential.resolveBiography(id);
			assertNotNull(bio);
			assertEquals(1, bio.size());
			assertEquals(vc.getProof().getSignature(), bio.getTransaction(0).getRequest().getCredential().getProof().getSignature());

			person.addSelfProclaimedCredential(vc.getId());
		}
	}

	@Test
	@Order(102)
	public void testDeclareSelfProclaimedCredentialForFoo1() throws DIDException {
		DIDDocument doc = foo1.resolve();
		Carol.getStore().storeDid(doc);
		doc.setEffectiveController(Carol.getDid());

		// add a self-proclaimed credential
		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", "Foo1");
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", "foo1@example.com");

		// VC for the normal DID
		DIDURL id = new DIDURL(doc.getSubject(), "#profile-" + System.currentTimeMillis());
		VerifiableCredential.Builder cb = new Issuer(doc).issueFor(doc.getSubject());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
			.properties(props)
			.seal(Carol.getStorePassword());

		Carol.getStore().storeCredential(vc);
		vc.declare(Carol.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNotNull(resolvedVc);
		assertEquals(id, resolvedVc.getId());
		assertTrue(resolvedVc.getType().contains("ProfileCredential"));
		assertTrue(resolvedVc.getType().contains("SelfProclaimedCredential"));
		assertEquals(doc.getSubject(), resolvedVc.getSubject().getId());
		assertEquals(vc.getProof().getSignature(),
				resolvedVc.getProof().getSignature());

		assertTrue(resolvedVc.isValid());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(vc.getProof().getSignature(), bio.getTransaction(0).getRequest().getCredential().getProof().getSignature());

		foo1Vc = vc.getId();
	}

	@Test
	@Order(103)
	public void testDeclareSelfProclaimedCredentialForFoo2() throws DIDException {
		DIDDocument doc = foo2.resolve();
		Dave.getStore().storeDid(doc);
		doc.setEffectiveController(Dave.getDid());

		// add a self-proclaimed credential
		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", "Foo2");
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", "foo2@example.com");

		// VC for the normal DID
		DIDURL id = new DIDURL(doc.getSubject(), "#profile-" + System.currentTimeMillis());
		VerifiableCredential.Builder cb = new Issuer(doc).issueFor(doc.getSubject());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
			.properties(props)
			.seal(Dave.getStorePassword());

		Dave.getStore().storeCredential(vc);
		vc.declare(Dave.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNotNull(resolvedVc);
		assertEquals(id, resolvedVc.getId());
		assertTrue(resolvedVc.getType().contains("ProfileCredential"));
		assertTrue(resolvedVc.getType().contains("SelfProclaimedCredential"));
		assertEquals(doc.getSubject(), resolvedVc.getSubject().getId());
		assertEquals(vc.getProof().getSignature(),
				resolvedVc.getProof().getSignature());

		assertTrue(resolvedVc.isValid());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(vc.getProof().getSignature(), bio.getTransaction(0).getRequest().getCredential().getProof().getSignature());

		foo2Vc = vc.getId();
	}

	@Test
	@Order(104)
	public void testDeclareKycCredential_p2p() throws DIDException {
		Issuer issuer = new Issuer(Grace.getDocument());

		for (Entity person : persons) {
			// add a KYC credential
			Map<String, Object> props = new HashMap<String, Object>();
			props.put("name", person.getName());
			props.put("gender", "Male");
			props.put("nationality", "Singapore");
			props.put("email", person.getName() + "@example.com");

			DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());
			VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
			VerifiableCredential vc = cb.id(id)
				.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
				.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
				.properties(props)
				.seal(Grace.getStorePassword());

			person.getStore().storeCredential(vc);
			vc.declare(person.getStorePassword());

			VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
			assertNotNull(resolvedVc);
			assertEquals(id, resolvedVc.getId());
			assertTrue(resolvedVc.getType().contains("ProfileCredential"));
			assertTrue(resolvedVc.getType().contains("SelfProclaimedCredential"));
			assertEquals(person.getDid(), resolvedVc.getSubject().getId());
			assertEquals(Grace.getDid(), resolvedVc.getIssuer());
			assertEquals(vc.getProof().getSignature(),
					resolvedVc.getProof().getSignature());

			assertTrue(resolvedVc.isValid());

			CredentialBiography bio = VerifiableCredential.resolveBiography(id);
			assertNotNull(bio);
			assertEquals(1, bio.size());
			assertEquals(vc.getProof().getSignature(), bio.getTransaction(0).getRequest().getCredential().getProof().getSignature());

			person.addKycCredential(vc.getId());
		}
	}

	@Test
	@Order(105)
	public void testDeclareKycCredential_p2c() throws DIDException {
		Issuer issuer = new Issuer(Grace.getDocument());

		for (Entity person : persons) {
			// add a KYC credential
			Map<String, Object> props = new HashMap<String, Object>();
			props.put("name", person.getName());
			props.put("gender", "Male");
			props.put("nationality", "Singapore");
			props.put("email", person.getName() + "@example.com");

			DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());
			VerifiableCredential.Builder cb = issuer.issueFor(person.getCustomizedDid());
			VerifiableCredential vc = cb.id(id)
				.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
				.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
				.properties(props)
				.seal(Grace.getStorePassword());

			person.getStore().storeCredential(vc);
			vc.declare(person.getStorePassword());

			VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
			assertNotNull(resolvedVc);
			assertEquals(id, resolvedVc.getId());
			assertTrue(resolvedVc.getType().contains("ProfileCredential"));
			assertTrue(resolvedVc.getType().contains("SelfProclaimedCredential"));
			assertEquals(person.getCustomizedDid(), resolvedVc.getSubject().getId());
			assertEquals(Grace.getDid(), resolvedVc.getIssuer());
			assertEquals(vc.getProof().getSignature(),
					resolvedVc.getProof().getSignature());

			assertTrue(resolvedVc.isValid());

			CredentialBiography bio = VerifiableCredential.resolveBiography(id);
			assertNotNull(bio);
			assertEquals(1, bio.size());
			assertEquals(vc.getProof().getSignature(), bio.getTransaction(0).getRequest().getCredential().getProof().getSignature());

			person.addKycCredential(vc.getId());
		}
	}

	@Test
	@Order(106)
	public void testDeclareKycCredential_c2p() throws DIDException {
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		for (Entity person : persons) {
			// add a KYC credential
			Map<String, Object> props = new HashMap<String, Object>();
			props.put("name", person.getName());
			props.put("gender", "Male");
			props.put("nationality", "Singapore");
			props.put("email", person.getName() + "@example.com");

			DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());
			VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
			VerifiableCredential vc = cb.id(id)
				.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
				.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
				.properties(props)
				.seal(Grace.getStorePassword());

			person.getStore().storeCredential(vc);
			vc.declare(person.getStorePassword());

			VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
			assertNotNull(resolvedVc);
			assertEquals(id, resolvedVc.getId());
			assertTrue(resolvedVc.getType().contains("ProfileCredential"));
			assertTrue(resolvedVc.getType().contains("SelfProclaimedCredential"));
			assertEquals(person.getDid(), resolvedVc.getSubject().getId());
			assertEquals(Grace.getCustomizedDid(), resolvedVc.getIssuer());
			assertEquals(vc.getProof().getSignature(),
					resolvedVc.getProof().getSignature());

			assertTrue(resolvedVc.isValid());

			CredentialBiography bio = VerifiableCredential.resolveBiography(id);
			assertNotNull(bio);
			assertEquals(1, bio.size());
			assertEquals(vc.getProof().getSignature(), bio.getTransaction(0).getRequest().getCredential().getProof().getSignature());

			person.addKycCredential(vc.getId());
		}
	}

	@Test
	@Order(107)
	public void testDeclareKycCredential_c2c() throws DIDException {
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		for (Entity person : persons) {
			// add a KYC credential
			Map<String, Object> props = new HashMap<String, Object>();
			props.put("name", person.getName());
			props.put("gender", "Male");
			props.put("nationality", "Singapore");
			props.put("email", person.getName() + "@example.com");

			DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());
			VerifiableCredential.Builder cb = issuer.issueFor(person.getCustomizedDid());
			VerifiableCredential vc = cb.id(id)
				.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
				.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
				.properties(props)
				.seal(Grace.getStorePassword());

			person.getStore().storeCredential(vc);
			vc.declare(person.getStorePassword());

			VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
			assertNotNull(resolvedVc);
			assertEquals(id, resolvedVc.getId());
			assertTrue(resolvedVc.getType().contains("ProfileCredential"));
			assertTrue(resolvedVc.getType().contains("SelfProclaimedCredential"));
			assertEquals(person.getCustomizedDid(), resolvedVc.getSubject().getId());
			assertEquals(Grace.getCustomizedDid(), resolvedVc.getIssuer());
			assertEquals(vc.getProof().getSignature(),
					resolvedVc.getProof().getSignature());

			assertTrue(resolvedVc.isValid());

			CredentialBiography bio = VerifiableCredential.resolveBiography(id);
			assertNotNull(bio);
			assertEquals(1, bio.size());
			assertEquals(vc.getProof().getSignature(), bio.getTransaction(0).getRequest().getCredential().getProof().getSignature());

			person.addKycCredential(vc.getId());
		}
	}

	@Test
	@Order(108)
	public void testDeclareKycCredentialForBar1_p() throws DIDException {
		Issuer issuer = new Issuer(Grace.getDocument());

		// add a KYC credential
		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", "Bar1");
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", "bar2@example.com");

		// VC for the normal DID
		DIDURL id = new DIDURL(bar1, "#profile-" + System.currentTimeMillis());
		VerifiableCredential.Builder cb = issuer.issueFor(bar1);
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		Dave.getStore().storeCredential(vc);
		vc.declare(Dave.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNotNull(resolvedVc);
		assertEquals(id, resolvedVc.getId());
		assertTrue(resolvedVc.getType().contains("ProfileCredential"));
		assertTrue(resolvedVc.getType().contains("SelfProclaimedCredential"));
		assertEquals(bar1, resolvedVc.getSubject().getId());
		assertEquals(Grace.getDid(), resolvedVc.getIssuer());
		assertEquals(vc.getProof().getSignature(),
				resolvedVc.getProof().getSignature());

		assertTrue(resolvedVc.isValid());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(vc.getProof().getSignature(), bio.getTransaction(0).getRequest().getCredential().getProof().getSignature());

		bar1Vc = vc.getId();
	}

	@Test
	@Order(109)
	public void testDeclareKycCredentialForBar2_c() throws DIDException {
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		// add a KYC credential
		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", "Bar2");
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", "bar2@example.com");

		// VC for the normal DID
		DIDURL id = new DIDURL(bar2, "#profile-" + System.currentTimeMillis());
		VerifiableCredential.Builder cb = issuer.issueFor(bar2);
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		Erin.getStore().storeCredential(vc);
		vc.declare(Erin.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNotNull(resolvedVc);
		assertEquals(id, resolvedVc.getId());
		assertTrue(resolvedVc.getType().contains("ProfileCredential"));
		assertTrue(resolvedVc.getType().contains("SelfProclaimedCredential"));
		assertEquals(bar2, resolvedVc.getSubject().getId());
		assertEquals(Grace.getCustomizedDid(), resolvedVc.getIssuer());
		assertEquals(vc.getProof().getSignature(),
				resolvedVc.getProof().getSignature());

		assertTrue(resolvedVc.isValid());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(vc.getProof().getSignature(), bio.getTransaction(0).getRequest().getCredential().getProof().getSignature());

		bar2Vc = vc.getId();
	}

	@Test
	@Order(110)
	public void testDeclareKycCredentialForBar3_c() throws DIDException {
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		// add a KYC credential
		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", "Bar3");
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", "bar3@example.com");

		// VC for the normal DID
		DIDURL id = new DIDURL(bar3, "#profile-" + System.currentTimeMillis());
		VerifiableCredential.Builder cb = issuer.issueFor(bar3);
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		Frank.getStore().storeCredential(vc);
		vc.declare(Frank.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNotNull(resolvedVc);
		assertEquals(id, resolvedVc.getId());
		assertTrue(resolvedVc.getType().contains("ProfileCredential"));
		assertTrue(resolvedVc.getType().contains("SelfProclaimedCredential"));
		assertEquals(bar3, resolvedVc.getSubject().getId());
		assertEquals(Grace.getCustomizedDid(), resolvedVc.getIssuer());
		assertEquals(vc.getProof().getSignature(),
				resolvedVc.getProof().getSignature());

		assertTrue(resolvedVc.isValid());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(vc.getProof().getSignature(), bio.getTransaction(0).getRequest().getCredential().getProof().getSignature());

		bar3Vc = vc.getId();
	}

	@Test
	@Order(111)
	public void testDeclareMultilangCredential() throws DIDException, IOException {
		Entity nobody = new Entity("nobody");

		Issuer selfIssuer = new Issuer(nobody.getDocument());
		VerifiableCredential.Builder cb = selfIssuer.issueFor(nobody.getDid());

		Map<String, Object> props= new HashMap<String, Object>();

		File i18nDir = new File(getClass().getResource("/i18n").getPath());
		File[] i18nRes = i18nDir.listFiles();
		for (File res : i18nRes) {
			BufferedReader reader = new BufferedReader(new FileReader(res));
			String text = reader.lines().collect(Collectors.joining(System.lineSeparator()));
			reader.close();

			props.put(res.getName(), text);
		}

		DIDURL id = new DIDURL(nobody.getDid(), "#i18n");
		VerifiableCredential vc = cb.id(id)
				.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
				.type("TestCredential", "https://trinity-tech.io/credentials/i18n/v1")
				.properties(props)
				.seal(nobody.getStorePassword());
		assertNotNull(vc);

		nobody.getStore().storeCredential(vc);
		vc.declare(nobody.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNotNull(resolvedVc);
		assertEquals(id, resolvedVc.getId());
		assertTrue(resolvedVc.getType().contains("SelfProclaimedCredential"));
		assertEquals(nobody.getDid(), resolvedVc.getSubject().getId());
		assertEquals(nobody.getDid(), resolvedVc.getIssuer());
		assertEquals(vc.getProof().getSignature(),
				resolvedVc.getProof().getSignature());

		assertTrue(resolvedVc.isValid());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(vc.getProof().getSignature(), bio.getTransaction(0).getRequest().getCredential().getProof().getSignature());
	}

	@Test
	@Order(200)
	public void testListVcForAlice_p() throws DIDException {
		List<DIDURL> vcs = VerifiableCredential.list(Alice.getDid());

		assertEquals(3, vcs.size());

		for (DIDURL id : vcs) {
			VerifiableCredential vc = VerifiableCredential.resolve(id);
			assertNotNull(vc);
			assertEquals(id, vc.getId());
			assertEquals(Alice.getDid(), vc.getSubject().getId());
		}
	}

	@Test
	@Order(201)
	public void testListVcForAlice_c() throws DIDException {
		List<DIDURL> vcs = VerifiableCredential.list(Alice.getCustomizedDid());

		assertEquals(3, vcs.size());

		for (DIDURL id : vcs) {
			VerifiableCredential vc = VerifiableCredential.resolve(id);
			assertNotNull(vc);
			assertEquals(id, vc.getId());
			assertEquals(Alice.getCustomizedDid(), vc.getSubject().getId());
		}
	}

	@Test
	@Order(202)
	public void testListVcForFoo1() throws DIDException {
		List<DIDURL> vcs = VerifiableCredential.list(foo1);

		assertEquals(1, vcs.size());

		for (DIDURL id : vcs) {
			VerifiableCredential vc = VerifiableCredential.resolve(id);
			assertNotNull(vc);
			assertEquals(id, vc.getId());
			assertEquals(foo1, vc.getSubject().getId());
		}
	}

	@Test
	@Order(203)
	public void testListVcForBar3() throws DIDException {
		List<DIDURL> vcs = VerifiableCredential.list(bar3);

		assertEquals(1, vcs.size());

		for (DIDURL id : vcs) {
			VerifiableCredential vc = VerifiableCredential.resolve(id);
			assertNotNull(vc);
			assertEquals(id, vc.getId());
			assertEquals(bar3, vc.getSubject().getId());
		}
	}

	@Test
	@Order(204)
	public void testListPagination() throws DIDException {
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		Entity nobody = new Entity("nobody");

		// Create a bunch of vcs
		for (int i = 0; i < 271; i++) {
			log.debug("Creating test credential {}...", i);

			VerifiableCredential vc = issuer.issueFor(nobody.getDid())
					.id("#test" + i)
					.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
					.property("index", Integer.valueOf(i))
					.seal(Grace.getStorePassword());

			nobody.getStore().storeCredential(vc);
			vc.declare(nobody.getStorePassword());

			assertTrue(vc.wasDeclared());
		}

		// Default page size
		int index = 271;
		List<DIDURL> ids = VerifiableCredential.list(nobody.getDid());
		assertNotNull(ids);
		assertEquals(CredentialList.DEFAULT_SIZE, ids.size());
		for (DIDURL id : ids) {
			log.trace("Resolving credential {}...", id.getFragment());

			DIDURL ref = new DIDURL(nobody.getDid(), "#test" + --index);
			assertEquals(ref, id);

			VerifiableCredential vc = VerifiableCredential.resolve(id);

			assertNotNull(vc);
			assertEquals(ref, vc.getId());
			assertTrue(vc.wasDeclared());
		}

		// Max page size
		index = 271;
		ids = VerifiableCredential.list(nobody.getDid(), 500);
		assertNotNull(ids);
		assertEquals(CredentialList.MAX_SIZE, ids.size());
		for (DIDURL id : ids) {
			log.trace("Resolving credential {}...", id.getFragment());

			DIDURL ref = new DIDURL(nobody.getDid(), "#test" + --index);
			assertEquals(ref, id);

			VerifiableCredential vc = VerifiableCredential.resolve(id);

			assertNotNull(vc);
			assertEquals(ref, vc.getId());
			assertTrue(vc.wasDeclared());
		}

		// out of boundary
		ids = VerifiableCredential.list(nobody.getDid(), 300, 100);
		assertNull(ids);

		// list all with default page size
		int skip = 0;
		int limit = CredentialList.DEFAULT_SIZE;
		index = 271;
		while (true) {
			int resultSize = index >= limit ? limit : index;
			ids = VerifiableCredential.list(nobody.getDid(), skip, limit);
			if (ids == null)
				break;

			assertEquals(resultSize, ids.size());
			for (DIDURL id : ids) {
				log.trace("Resolving credential {}...", id.getFragment());

				DIDURL ref = new DIDURL(nobody.getDid(), "#test" + --index);
				assertEquals(ref, id);

				VerifiableCredential vc = VerifiableCredential.resolve(id);

				assertNotNull(vc);
				assertEquals(ref, vc.getId());
				assertTrue(vc.wasDeclared());
			}

			skip += ids.size();
		}
		assertEquals(0, index);

		// list with specific page size and start position
		skip = 100;
		limit = 100;
		index = 171;
		while (true) {
			int resultSize = index >= limit ? limit : index;
			ids = VerifiableCredential.list(nobody.getDid(), skip, limit);
			if (ids == null)
				break;

			assertEquals(resultSize, ids.size());
			for (DIDURL id : ids) {
				log.trace("Resolving credential {}...", id.getFragment());

				DIDURL ref = new DIDURL(nobody.getDid(), "#test" + --index);
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

	@Test
	@Order(300)
	public void testRevokeSelfProclaimedVcFromNobody_p() throws DIDException {
		// Frank' self-proclaimed credential
		DIDURL id = Frank.getSelfProclaimedCredential(Frank.getDid()).get(0);

		// Alice try to revoke
		assertThrows(Exception.class, () -> {
			VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());
		});

		List<DIDURL> vcs = VerifiableCredential.list(Frank.getDid());
		assertEquals(3, vcs.size());
		assertTrue(vcs.contains(id));

		VerifiableCredential vc = VerifiableCredential.resolve(id);
		assertFalse(vc.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(vc.getProof().getSignature(), bio.getTransaction(0).getRequest().getCredential().getProof().getSignature());
	}

	@Test
	@Order(301)
	public void testRevokeSelfProclaimedVcFromNobody_c() throws DIDException {
		// Frank' self-proclaimed credential
		DIDURL id = Frank.getSelfProclaimedCredential(Frank.getCustomizedDid()).get(0);

		// Alice try to revoke
		assertThrows(Exception.class, () -> {
			VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());
		});

		List<DIDURL> vcs = VerifiableCredential.list(Frank.getCustomizedDid());
		assertEquals(3, vcs.size());
		assertTrue(vcs.contains(id));

		VerifiableCredential vc = VerifiableCredential.resolve(id);
		assertFalse(vc.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(vc.getProof().getSignature(), bio.getTransaction(0).getRequest().getCredential().getProof().getSignature());
	}

	@Test
	@Order(302)
	public void testRevokeSelfProclaimedVc_p1() throws DIDException {
		// Frank' self-proclaimed credential
		DIDURL id = Frank.getSelfProclaimedCredential(Frank.getDid()).get(0);

		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		List<DIDURL> vcs = VerifiableCredential.list(Frank.getDid());
		assertEquals(3, vcs.size());
		assertTrue(vcs.contains(id));

		VerifiableCredential vc = VerifiableCredential.resolve(id);
		assertTrue(vc.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(303)
	public void testRevokeSelfProclaimedVc_c1() throws DIDException {
		// Frank' self-proclaimed credential
		DIDURL id = Frank.getSelfProclaimedCredential(Frank.getCustomizedDid()).get(0);

		DIDDocument doc = Frank.getCustomizedDocument();
		doc.setEffectiveController(Frank.getDid());

		VerifiableCredential.revoke(id, doc, Frank.getStorePassword());

		List<DIDURL> vcs = VerifiableCredential.list(Frank.getCustomizedDid());
		assertEquals(3, vcs.size());
		assertTrue(vcs.contains(id));

		VerifiableCredential vc = VerifiableCredential.resolve(id);
		assertTrue(vc.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(304)
	public void testRevokeSelfProclaimedVc_p2() throws DIDException {
		// Erin' self-proclaimed credential
		DIDURL id = Erin.getSelfProclaimedCredential(Erin.getDid()).get(0);

		VerifiableCredential vc = VerifiableCredential.resolve(id);
		assertFalse(vc.isRevoked());

		vc.revoke(Erin.getDocument(), Erin.getStorePassword());

		List<DIDURL> vcs = VerifiableCredential.list(Erin.getDid());
		assertEquals(3, vcs.size());
		assertTrue(vcs.contains(id));

		vc = VerifiableCredential.resolve(id);
		assertTrue(vc.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(305)
	public void testRevokeSelfProclaimedVc_c2() throws DIDException {
		// Erin' self-proclaimed credential
		DIDURL id = Erin.getSelfProclaimedCredential(Erin.getCustomizedDid()).get(0);

		VerifiableCredential vc = VerifiableCredential.resolve(id);
		assertFalse(vc.isRevoked());

		DIDDocument doc = Erin.getCustomizedDocument();
		doc.setEffectiveController(Erin.getDid());

		vc.revoke(doc, Erin.getStorePassword());

		List<DIDURL> vcs = VerifiableCredential.list(Erin.getCustomizedDid());
		assertEquals(3, vcs.size());
		assertTrue(vcs.contains(id));

		vc = VerifiableCredential.resolve(id);
		assertTrue(vc.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(306)
	public void testRevokeKycVc_p1() throws DIDException {
		// Frank' KYC credential
		DIDURL id = Frank.getKycCredential(Frank.getDid()).get(0);

		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		List<DIDURL> vcs = VerifiableCredential.list(Frank.getDid());
		assertEquals(3, vcs.size());
		assertTrue(vcs.contains(id));

		VerifiableCredential vc = VerifiableCredential.resolve(id);
		assertTrue(vc.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(307)
	public void testRevokeKycVc_c1() throws DIDException {
		// Frank' KYC credential
		DIDURL id = Frank.getKycCredential(Frank.getCustomizedDid()).get(0);

		DIDDocument doc = Frank.getCustomizedDocument();
		doc.setEffectiveController(Frank.getDid());

		VerifiableCredential.revoke(id, doc, Frank.getStorePassword());

		List<DIDURL> vcs = VerifiableCredential.list(Frank.getCustomizedDid());
		assertEquals(3, vcs.size());
		assertTrue(vcs.contains(id));

		VerifiableCredential vc = VerifiableCredential.resolve(id);
		assertTrue(vc.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(308)
	public void testRevokeKycVc_p2() throws DIDException {
		// Erin' KYC credential
		DIDURL id = Erin.getKycCredential(Erin.getDid()).get(0);

		VerifiableCredential vc = VerifiableCredential.resolve(id);
		assertFalse(vc.isRevoked());

		vc.revoke(Erin.getDocument(), Erin.getStorePassword());

		List<DIDURL> vcs = VerifiableCredential.list(Erin.getDid());
		assertEquals(3, vcs.size());
		assertTrue(vcs.contains(id));

		vc = VerifiableCredential.resolve(id);
		assertTrue(vc.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(309)
	public void testRevokeKycVc_c2() throws DIDException {
		// Erin' KYC credential
		DIDURL id = Erin.getKycCredential(Erin.getCustomizedDid()).get(0);

		VerifiableCredential vc = VerifiableCredential.resolve(id);
		assertFalse(vc.isRevoked());

		DIDDocument doc = Erin.getCustomizedDocument();
		doc.setEffectiveController(Erin.getDid());

		vc.revoke(doc, Erin.getStorePassword());

		List<DIDURL> vcs = VerifiableCredential.list(Erin.getCustomizedDid());
		assertEquals(3, vcs.size());
		assertTrue(vcs.contains(id));

		vc = VerifiableCredential.resolve(id);
		assertTrue(vc.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(310)
	public void testRevokeFoo1Vc() throws DIDException {
		VerifiableCredential vc = VerifiableCredential.resolve(foo1Vc);
		assertFalse(vc.isRevoked());

		DIDDocument doc = foo1.resolve();
		Carol.getStore().storeDid(doc);
		doc.setEffectiveController(Carol.getDid());

		vc.revoke(doc, Carol.getStorePassword());

		List<DIDURL> vcs = VerifiableCredential.list(foo1);
		assertEquals(1, vcs.size());
		assertTrue(vcs.contains(foo1Vc));

		vc = VerifiableCredential.resolve(foo1Vc);
		assertTrue(vc.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(vc.getId());
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(311)
	public void testRevokeFoo2Vc() throws DIDException {
		VerifiableCredential vc = VerifiableCredential.resolve(foo2Vc);
		assertFalse(vc.isRevoked());

		DIDDocument doc = foo2.resolve();
		Dave.getStore().storeDid(doc);
		doc.setEffectiveController(Dave.getDid());

		vc.revoke(doc, Dave.getStorePassword());

		List<DIDURL> vcs = VerifiableCredential.list(foo2);
		assertEquals(1, vcs.size());
		assertTrue(vcs.contains(foo2Vc));

		vc = VerifiableCredential.resolve(foo2Vc);
		assertTrue(vc.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(vc.getId());
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(312)
	public void testRevokeBar1VcByNobody() throws DIDException {
		final VerifiableCredential vc = VerifiableCredential.resolve(bar1Vc);
		assertFalse(vc.isRevoked());

		DIDDocument doc = Alice.getDocument();

		assertThrows(Exception.class, () -> {
			vc.revoke(doc, Alice.getStorePassword());
		});

		List<DIDURL> vcs = VerifiableCredential.list(bar1);
		assertEquals(1, vcs.size());
		assertTrue(vcs.contains(bar1Vc));

		VerifiableCredential resolved = VerifiableCredential.resolve(bar1Vc);
		assertFalse(resolved.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(vc.getId());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(vc.getProof().getSignature(), bio.getTransaction(0).getRequest().getCredential().getProof().getSignature());
	}

	@Test
	@Order(313)
	public void testRevokeBar2VcByNobody() throws DIDException {
		final VerifiableCredential vc = VerifiableCredential.resolve(bar2Vc);
		assertFalse(vc.isRevoked());

		DIDDocument doc = Alice.getDocument();

		assertThrows(Exception.class, () -> {
			vc.revoke(doc, Alice.getStorePassword());
		});

		List<DIDURL> vcs = VerifiableCredential.list(bar2);
		assertEquals(1, vcs.size());
		assertTrue(vcs.contains(bar2Vc));

		VerifiableCredential resolved = VerifiableCredential.resolve(bar2Vc);
		assertFalse(resolved.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(vc.getId());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(vc.getProof().getSignature(), bio.getTransaction(0).getRequest().getCredential().getProof().getSignature());
	}

	@Test
	@Order(314)
	public void testRevokeBar1VcByController() throws DIDException {
		VerifiableCredential vc = VerifiableCredential.resolve(bar1Vc);
		assertFalse(vc.isRevoked());

		DIDDocument doc = bar1.resolve();
		Dave.getStore().storeDid(doc);
		doc.setEffectiveController(Dave.getDid());

		vc.revoke(doc, Dave.getStorePassword());

		List<DIDURL> vcs = VerifiableCredential.list(bar1);
		assertEquals(1, vcs.size());
		assertTrue(vcs.contains(bar1Vc));

		vc = VerifiableCredential.resolve(bar1Vc);
		assertTrue(vc.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(vc.getId());
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(315)
	public void testRevokeBar2VcByIssuer() throws DIDException {
		VerifiableCredential vc = VerifiableCredential.resolve(bar2Vc);
		assertFalse(vc.isRevoked());

		DIDDocument doc = Grace.getCustomizedDocument();
		doc.setEffectiveController(Grace.getDid());

		vc.revoke(doc, Grace.getStorePassword());

		List<DIDURL> vcs = VerifiableCredential.list(bar2);
		assertEquals(1, vcs.size());
		assertTrue(vcs.contains(bar2Vc));

		vc = VerifiableCredential.resolve(bar2Vc);
		assertTrue(vc.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(vc.getId());
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(316)
	public void testRevokeBar3VcByIssuer() throws DIDException {
		VerifiableCredential vc = VerifiableCredential.resolve(bar3Vc);
		assertFalse(vc.isRevoked());

		DIDDocument doc = Grace.getCustomizedDocument();
		doc.setEffectiveController(Grace.getDid());

		VerifiableCredential.revoke(bar3Vc, doc, Grace.getStorePassword());

		List<DIDURL> vcs = VerifiableCredential.list(bar3);
		assertEquals(1, vcs.size());
		assertTrue(vcs.contains(bar3Vc));

		vc = VerifiableCredential.resolve(bar3Vc);
		assertTrue(vc.isRevoked());

		CredentialBiography bio = VerifiableCredential.resolveBiography(vc.getId());
		assertNotNull(bio);
		assertEquals(2, bio.size());
		assertEquals(IDChainRequest.Operation.REVOKE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(317)
	public void testRevokeUndeclaredByNobody_selfproclaimed_p() throws DIDException {
		Entity person = Alice;

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = new Issuer(person.getDocument()).issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
			.properties(props)
			.seal(person.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(0, bio.size());
		assertEquals(CredentialBiography.Status.NOT_FOUND, bio.getStatus());
	}

	@Test
	@Order(318)
	public void testRevokeUndeclaredByNobody_selfproclaimed_c() throws DIDException {
		Entity person = Alice;

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = new Issuer(person.getCustomizedDocument()).issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
			.properties(props)
			.seal(person.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(0, bio.size());
		assertEquals(CredentialBiography.Status.NOT_FOUND, bio.getStatus());
	}

	@Test
	@Order(319)
	public void testRevokeUndeclaredByNobody_kyc_p2p() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(0, bio.size());
		assertEquals(CredentialBiography.Status.NOT_FOUND, bio.getStatus());
	}

	@Test
	@Order(320)
	public void testRevokeUndeclaredByNobody_kyc_p2c() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(0, bio.size());
		assertEquals(CredentialBiography.Status.NOT_FOUND, bio.getStatus());
	}

	@Test
	@Order(321)
	public void testRevokeUndeclaredByNobody_kyc_c2p() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(0, bio.size());
		assertEquals(CredentialBiography.Status.NOT_FOUND, bio.getStatus());
	}

	@Test
	@Order(322)
	public void testRevokeUndeclaredByNobody_kyc_c2c() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(0, bio.size());
		assertEquals(CredentialBiography.Status.NOT_FOUND, bio.getStatus());
	}

	@Test
	@Order(323)
	public void testRevokeUndeclaredByController_selfproclaimed_p() throws DIDException {
		Entity person = Alice;

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = new Issuer(person.getDocument()).issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
			.properties(props)
			.seal(person.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(person.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(324)
	public void testRevokeUndeclaredByController_selfproclaimed_p2() throws DIDException {
		Entity person = Alice;

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = new Issuer(person.getDocument()).issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
			.properties(props)
			.seal(person.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(person.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(325)
	public void testRevokeUndeclaredByController_selfproclaimed_c() throws DIDException {
		Entity person = Alice;

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = new Issuer(person.getCustomizedDocument()).issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
			.properties(props)
			.seal(person.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Alice
		DIDDocument doc = Alice.getCustomizedDocument();
		doc.setEffectiveController(Alice.getDid());
		VerifiableCredential.revoke(id, doc, Alice.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(person.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(326)
	public void testRevokeUndeclaredByController_selfproclaimed_c2() throws DIDException {
		Entity person = Alice;

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = new Issuer(person.getCustomizedDocument()).issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
			.properties(props)
			.seal(person.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(person.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(327)
	public void testRevokeUndeclaredByController_selfproclaimed_c3() throws DIDException {
		Entity person = Alice;

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = new Issuer(person.getCustomizedDocument()).issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
			.properties(props)
			.seal(person.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Alice
		DIDDocument doc = Alice.getCustomizedDocument();
		doc.setEffectiveController(Alice.getDid());
		VerifiableCredential.revoke(id, doc, Alice.getStorePassword());

		// Revoke by Alice again
		assertThrows(CredentialRevokedException.class, () -> {
			VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());
		});

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(person.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(328)
	public void testRevokeUndeclaredByController_selfproclaimed_c4() throws DIDException {
		Entity person = Alice;

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = new Issuer(person.getCustomizedDocument()).issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
			.properties(props)
			.seal(person.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Alice
		DIDDocument doc = Alice.getCustomizedDocument();
		doc.setEffectiveController(Alice.getDid());
		VerifiableCredential.revoke(id, doc, Alice.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(person.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(329)
	public void testRevokeUndeclaredByController_kyc_p2p() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(person.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(330)
	public void testRevokeUndeclaredByController_kyc_p2p2() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(person.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(331)
	public void testRevokeUndeclaredByIssuer_kyc_p2p() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Grace
		VerifiableCredential.revoke(id, Grace.getDocument(), Grace.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(0, bio.size());
		assertEquals(CredentialBiography.Status.NOT_FOUND, bio.getStatus());

		bio = VerifiableCredential.resolveBiography(id, Grace.getDid());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Grace.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(332)
	public void testRevokeUndeclaredByIssuer_kyc_p2p2() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Grace
		VerifiableCredential.revoke(id, Grace.getDocument(), Grace.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(0, bio.size());
		assertEquals(CredentialBiography.Status.NOT_FOUND, bio.getStatus());

		bio = VerifiableCredential.resolveBiography(id, Grace.getDid());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Grace.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(333)
	public void testRevokeUndeclaredByIssuerAndController_kyc_p2p() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Grace
		VerifiableCredential.revoke(id, Grace.getDocument(), Grace.getStorePassword());

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Alice.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());

		bio = VerifiableCredential.resolveBiography(id, Grace.getDid());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Grace.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(334)
	public void testRevokeUndeclaredByControllerAndIssuer_kyc_p2p() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());

		// Revoke by Grace
		assertThrows(CredentialRevokedException.class, () -> {
			VerifiableCredential.revoke(id, Grace.getDocument(), Grace.getStorePassword());
		});

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Alice.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());

		bio = VerifiableCredential.resolveBiography(id, Grace.getDid());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Alice.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(335)
	public void testRevokeUndeclaredByController_kyc_p2c() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(person.getCustomizedDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(336)
	public void testRevokeUndeclaredByController_kyc_p2c2() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());


		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(person.getCustomizedDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(337)
	public void testRevokeUndeclaredByIssuer_kyc_p2c() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Grace
		VerifiableCredential.revoke(id, Grace.getDocument(), Grace.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(0, bio.size());
		assertEquals(CredentialBiography.Status.NOT_FOUND, bio.getStatus());

		bio = VerifiableCredential.resolveBiography(id, Grace.getDid());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Grace.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(338)
	public void testRevokeUndeclaredByIssuer_kyc_p2c2() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Grace
		VerifiableCredential.revoke(id, Grace.getDocument(), Grace.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(0, bio.size());
		assertEquals(CredentialBiography.Status.NOT_FOUND, bio.getStatus());

		bio = VerifiableCredential.resolveBiography(id, Grace.getDid());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Grace.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(339)
	public void testRevokeUndeclaredByIssuerAndController_kyc_p2c() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Grace
		VerifiableCredential.revoke(id, Grace.getDocument(), Grace.getStorePassword());

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Alice.getCustomizedDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());

		bio = VerifiableCredential.resolveBiography(id, Grace.getDid());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Grace.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(340)
	public void testRevokeUndeclaredByControllerAndIssuer_kyc_p2c() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());

		// Revoke by Grace
		assertThrows(CredentialRevokedException.class, () -> {
			VerifiableCredential.revoke(id, Grace.getDocument(), Grace.getStorePassword());
		});

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Alice.getCustomizedDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());

		bio = VerifiableCredential.resolveBiography(id, Grace.getDid());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Alice.getCustomizedDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(341)
	public void testRevokeUndeclaredByController_kyc_c2p() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(person.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(342)
	public void testRevokeUndeclaredByController_kyc_c2p2() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());


		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(person.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(343)
	public void testRevokeUndeclaredByIssuer_kyc_c2p() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Grace
		VerifiableCredential.revoke(id, Grace.getDocument(), Grace.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(0, bio.size());
		assertEquals(CredentialBiography.Status.NOT_FOUND, bio.getStatus());

		bio = VerifiableCredential.resolveBiography(id, Grace.getDid());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Grace.getCustomizedDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(344)
	public void testRevokeUndeclaredByIssuer_kyc_c2p2() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Grace
		VerifiableCredential.revoke(id, Grace.getDocument(), Grace.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(0, bio.size());
		assertEquals(CredentialBiography.Status.NOT_FOUND, bio.getStatus());

		bio = VerifiableCredential.resolveBiography(id, Grace.getDid());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Grace.getCustomizedDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(345)
	public void testRevokeUndeclaredByIssuerAndController_kyc_c2p() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Grace
		VerifiableCredential.revoke(id, Grace.getDocument(), Grace.getStorePassword());

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Alice.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());

		bio = VerifiableCredential.resolveBiography(id, Grace.getDid());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Grace.getCustomizedDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(346)
	public void testRevokeUndeclaredByControllerAndIssuer_kyc_c2p() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());

		// Revoke by Grace
		assertThrows(CredentialRevokedException.class, () -> {
			VerifiableCredential.revoke(id, Grace.getDocument(), Grace.getStorePassword());
		});

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Alice.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());

		bio = VerifiableCredential.resolveBiography(id, Grace.getDid());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Alice.getDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(347)
	public void testRevokeUndeclaredByController_kyc_c2c() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(person.getCustomizedDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(348)
	public void testRevokeUndeclaredByController_kyc_c2c2() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());


		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(person.getCustomizedDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(349)
	public void testRevokeUndeclaredByIssuer_kyc_c2c() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Grace
		VerifiableCredential.revoke(id, Grace.getDocument(), Grace.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(0, bio.size());
		assertEquals(CredentialBiography.Status.NOT_FOUND, bio.getStatus());

		bio = VerifiableCredential.resolveBiography(id, Grace.getDid());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Grace.getCustomizedDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(350)
	public void testRevokeUndeclaredByIssuer_kyc_c2c2() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Grace
		VerifiableCredential.revoke(id, Grace.getDocument(), Grace.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(0, bio.size());
		assertEquals(CredentialBiography.Status.NOT_FOUND, bio.getStatus());

		bio = VerifiableCredential.resolveBiography(id, Grace.getDid());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Grace.getCustomizedDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(351)
	public void testRevokeUndeclaredByIssuerAndController_kyc_c2c() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Grace
		VerifiableCredential.revoke(id, Grace.getDocument(), Grace.getStorePassword());

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Alice.getCustomizedDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());

		bio = VerifiableCredential.resolveBiography(id, Grace.getDid());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Grace.getCustomizedDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(352)
	public void testRevokeUndeclaredByControllerAndIssuer_kyc_c2c() throws DIDException {
		Entity person = Alice;
		Issuer issuer = new Issuer(Grace.getCustomizedDocument());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("name", person.getName());
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", person.getName() + "@example.com");

		DIDURL id = new DIDURL(person.getCustomizedDid(), "#profile-" + System.currentTimeMillis());

		VerifiableCredential.Builder cb = issuer.issueFor(person.getCustomizedDid());
		VerifiableCredential vc = cb.id(id)
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(Grace.getStorePassword());

		VerifiableCredential resolvedVc = VerifiableCredential.resolve(id);
		assertNull(resolvedVc);

		// Revoke by Frank
		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

		// Revoke by Alice
		VerifiableCredential.revoke(id, Alice.getDocument(), Alice.getStorePassword());

		// Revoke by Grace
		assertThrows(CredentialRevokedException.class, () -> {
			VerifiableCredential.revoke(id, Grace.getDocument(), Grace.getStorePassword());
		});

		vc = VerifiableCredential.resolve(id);
		assertNull(vc);

		CredentialBiography bio = VerifiableCredential.resolveBiography(id);
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Alice.getCustomizedDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());

		bio = VerifiableCredential.resolveBiography(id, Grace.getDid());
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertTrue(Alice.getCustomizedDocument().isAuthenticationKey(bio.getTransaction(0).getRequest().getProof().getVerificationMethod()));
		assertEquals(CredentialBiography.Status.REVOKED, bio.getStatus());
	}

	@Test
	@Order(400)
	public void testDeactivateFoo1() throws DIDException {
		DIDDocument doc = foo1.resolve();
		assertNotNull(doc);
		assertTrue(doc.isValid());

		Carol.getStore().storeDid(doc);
		doc.setEffectiveController(Carol.getDid());
		doc.deactivate(Carol.getStorePassword());

		doc = foo1.resolve();
		assertTrue(doc.isDeactivated());

		DIDBiography bio = foo1.resolveBiography();
		assertNotNull(bio);
		assertEquals(4, bio.size());
		assertEquals(IDChainRequest.Operation.DEACTIVATE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(401)
	public void testDeactivateFoo2() throws DIDException {
		DIDDocument doc = foo2.resolve();
		assertNotNull(doc);
		assertTrue(doc.isValid());

		Dave.getDocument().deactivate(foo2, Dave.getStorePassword());

		doc = foo1.resolve();
		assertTrue(doc.isDeactivated());

		DIDBiography bio = foo2.resolveBiography();
		assertNotNull(bio);
		assertEquals(4, bio.size());
		assertEquals(IDChainRequest.Operation.DEACTIVATE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(402)
	public void testDeactivateBar1() throws DIDException {
		DIDDocument doc = bar1.resolve();
		assertNotNull(doc);
		assertTrue(doc.isValid());

		Dave.getDocument().deactivate(bar1, Dave.getStorePassword());

		doc = bar1.resolve();
		assertTrue(doc.isDeactivated());

		DIDBiography bio = bar1.resolveBiography();
		assertNotNull(bio);
		assertEquals(4, bio.size());
		assertEquals(IDChainRequest.Operation.DEACTIVATE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(403)
	public void testDeactivateBar2() throws DIDException {
		DIDDocument doc = bar2.resolve();
		assertNotNull(doc);
		assertTrue(doc.isValid());

		Erin.getStore().storeDid(doc);
		doc.setEffectiveController(Erin.getDid());
		doc.deactivate(Erin.getStorePassword());

		doc = bar2.resolve();
		assertTrue(doc.isDeactivated());

		DIDBiography bio = bar2.resolveBiography();
		assertNotNull(bio);
		assertEquals(4, bio.size());
		assertEquals(IDChainRequest.Operation.DEACTIVATE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(404)
	public void testDeactivateBar3() throws DIDException {
		DIDDocument doc = bar3.resolve();
		assertNotNull(doc);
		assertTrue(doc.isValid());

		Frank.getStore().storeDid(doc);
		doc.setEffectiveController(Frank.getDid());
		doc.deactivate(Frank.getStorePassword());

		doc = bar3.resolve();
		assertTrue(doc.isDeactivated());

		DIDBiography bio = bar3.resolveBiography();
		assertNotNull(bio);
		assertEquals(4, bio.size());
		assertEquals(IDChainRequest.Operation.DEACTIVATE, bio.getTransaction(0).getRequest().getOperation());
	}

	@Test
	@Order(405)
	public void testDeactivatePersonsCid() throws DIDException {
		for (Entity person : persons) {
			DIDDocument doc = person.getCustomizedDid().resolve();
			assertNotNull(doc);
			assertTrue(doc.isValid());

			doc = person.getCustomizedDocument();
			doc.deactivate(person.getStorePassword());

			doc = person.getCustomizedDid().resolve();
			assertTrue(doc.isDeactivated());

			DIDBiography bio = foo1.resolveBiography();
			assertNotNull(bio);
			assertEquals(4, bio.size());
			assertEquals(IDChainRequest.Operation.DEACTIVATE, bio.getTransaction(0).getRequest().getOperation());
		}
	}
}
