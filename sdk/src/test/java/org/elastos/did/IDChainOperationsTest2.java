package org.elastos.did;

import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.elastos.did.crypto.HDKey;
import org.elastos.did.exception.DIDControllersChangedException;
import org.elastos.did.exception.DIDException;
import org.elastos.did.utils.DIDTestExtension;
import org.elastos.did.utils.TestData;
import org.elastos.did.utils.Utils;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@TestMethodOrder(OrderAnnotation.class)
@ExtendWith(DIDTestExtension.class)
public class IDChainOperationsTest2 {
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

	private static final Logger log = LoggerFactory.getLogger(IDChainOperationsTest2.class);

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
    }

    @Test
    @Order(40)
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
    		VerifiableCredential.Builder cb = new Issuer(doc).issueFor(doc.getSubject());
    		VerifiableCredential vc = cb.id(id)
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

    		person.addSelfProclaimedCredential(vc.getId());
    	}
    }

    @Test
    @Order(41)
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
    		VerifiableCredential.Builder cb = new Issuer(doc).issueFor(doc.getSubject());
    		VerifiableCredential vc = cb.id(id)
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

    		person.addSelfProclaimedCredential(vc.getId());
    	}
    }

    @Test
    @Order(42)
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
    }

    @Test
    @Order(43)
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
    }

    @Test
    @Order(44)
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

    		person.addKycCredential(vc.getId());
    	}
    }

    @Test
    @Order(45)
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

    		person.addKycCredential(vc.getId());
    	}
    }

    @Test
    @Order(46)
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

    		person.addKycCredential(vc.getId());
    	}
    }

    @Test
    @Order(47)
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

    		person.addKycCredential(vc.getId());
    	}
    }

    @Test
    @Order(48)
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
    }

    @Test
    @Order(49)
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
    }

    @Test
    @Order(50)
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
    }

    @Test
    @Order(51)
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
    @Order(52)
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
    @Order(53)
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
    @Order(54)
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

    //@Test
    //@Order(55)
    public void testListPagination() throws DIDException {
    	Issuer issuer = new Issuer(Grace.getCustomizedDocument());

    	Entity nobody = new Entity("nobody");

    	// Create a bunch of vcs
    	for (int i = 0; i < 520; i++) {
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
    	int index = 519;
    	List<DIDURL> ids = VerifiableCredential.list(nobody.getDid());
    	assertNotNull(ids);
    	assertEquals(128, ids.size());
	   	for (DIDURL id : ids) {
	   		log.trace("Resolving credential {}...", id.getFragment());

	   		DIDURL ref = new DIDURL(nobody.getDid(), "#test" + index--);
	   		assertEquals(ref, id);

	   		VerifiableCredential vc = VerifiableCredential.resolve(id);

	   		assertNotNull(vc);
	   		assertEquals(ref, vc.getId());
	   		assertTrue(vc.wasDeclared());
	   	}

	   	// Max page size
    	index = 519;
    	ids = VerifiableCredential.list(nobody.getDid(), 550);
    	assertNotNull(ids);
    	assertEquals(512, ids.size());
	   	for (DIDURL id : ids) {
	   		log.trace("Resolving credential {}...", id.getFragment());

	   		DIDURL ref = new DIDURL(nobody.getDid(), "#test" + index--);
	   		assertEquals(ref, id);

	   		VerifiableCredential vc = VerifiableCredential.resolve(id);

	   		assertNotNull(vc);
	   		assertEquals(ref, vc.getId());
	   		assertTrue(vc.wasDeclared());
	   	}

	   	// out of boundary
    	ids = VerifiableCredential.list(nobody.getDid(), 520, 100);
    	assertNull(ids);

    	// list all with default page size
    	int skip = 0;
    	int limit = 256;
    	index = 520;
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
    	skip = 200;
    	limit = 100;
    	index = 320;
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
    @Order(70)
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
    }

    @Test
    @Order(71)
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
    }

    @Test
    @Order(72)
    public void testRevokeSelfProclaimedVc_p1() throws DIDException {
    	// Frank' self-proclaimed credential
    	DIDURL id = Frank.getSelfProclaimedCredential(Frank.getDid()).get(0);

		VerifiableCredential.revoke(id, Frank.getDocument(), Frank.getStorePassword());

    	List<DIDURL> vcs = VerifiableCredential.list(Frank.getDid());
    	assertEquals(3, vcs.size());
    	assertTrue(vcs.contains(id));

    	VerifiableCredential vc = VerifiableCredential.resolve(id);
    	assertTrue(vc.isRevoked());
    }

    @Test
    @Order(73)
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
    }

    @Test
    @Order(74)
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
    }

    @Test
    @Order(75)
    public void testRevokeSelfProclaimedVc_c2() throws DIDException {
    	// Frank' self-proclaimed credential
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
    }

    // test deactivate the dids
}
