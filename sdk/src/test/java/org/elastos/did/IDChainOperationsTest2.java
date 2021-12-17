package org.elastos.did;

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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;

@TestMethodOrder(OrderAnnotation.class)
@ExtendWith(DIDTestExtension.class)
public class IDChainOperationsTest2 {
	static private List<Entity> persons;

	static Entity Alice;
	static Entity Bob;
	static Entity Carol;
	static Entity Dave;
	static Entity Erin;
	static Entity Frank;
	static Entity Grace;

	static DID foo1, foo2;
	static DID bar1, bar2, bar3;
	static DID baz1, baz2, baz3;

	static class Entity {
		// Mnemonic passphrase and the store password should set by the end user.
		private final static String passphrase = "";  // Default is an empty string, or any user defined word
		private final static String storepass = "mypassword" + System.currentTimeMillis();

		// The entity name
		private String name;

		private DIDStore store;
		private DID did;
		private DID customizedDid;

		protected Entity(String name) throws DIDException {
			this.name = name;

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
			System.out.format("%s created DID: %s\n", getName(), did.toString());
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
	}

    @BeforeAll
    public static void beforeAll() throws DIDException {
    	System.out.println("Prepareing the DIDs for testing...");
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

    	System.out.println("Ready!");
    }

    @Test
    @Order(1)
    public void testCreateCustomizedDid() throws DIDException {
    	for (Entity person : persons) {
    		DIDDocument doc = person.getDocument();

    		DID customizedDid = new DID("did:elastos:" + person.getName() + "-" + System.currentTimeMillis());
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
		DID customizedDid = new DID("did:elastos:foo1" + "-" + System.currentTimeMillis());

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
		DID customizedDid = new DID("did:elastos:foo2" + "-" + System.currentTimeMillis());

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
		DID customizedDid = new DID("did:elastos:bar1" + "-" + System.currentTimeMillis());

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
		DID customizedDid = new DID("did:elastos:bar2" + "-" + System.currentTimeMillis());

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
		DID customizedDid = new DID("did:elastos:bar3" + "-" + System.currentTimeMillis());

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

		DID customizedDid = new DID("did:elastos:baz1" + "-" + System.currentTimeMillis());
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

		baz1 = customizedDid;
    }

    @Test
    @Order(18)
    public void testTransferCustomizedDid_1to2() throws DIDException {
    	// Alice create a customized did: baz2
    	DIDDocument doc = Alice.getDocument();

		DID customizedDid = new DID("did:elastos:baz2" + "-" + System.currentTimeMillis());
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

		baz2 = customizedDid;
    }

    @Test
    @Order(19)
    public void testTransferCustomizedDid_1to3_WithoutRequiredSig() throws DIDException {
    	// Alice create a customized did: baz3
    	DIDDocument doc = Alice.getDocument();

		DID customizedDid = new DID("did:elastos:baz3" + "-" + System.currentTimeMillis());
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

		baz3 = customizedDid;
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
    @Order(20)
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
}
