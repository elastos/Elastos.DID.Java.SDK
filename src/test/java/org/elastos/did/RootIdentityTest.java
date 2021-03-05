package org.elastos.did;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.elastos.did.exception.DIDAlreadyExistException;
import org.elastos.did.exception.DIDException;
import org.elastos.did.utils.DIDTestExtension;
import org.elastos.did.utils.TestConfig;
import org.elastos.did.utils.TestData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(DIDTestExtension.class)
public class RootIdentityTest {
	private TestData testData;
	private DIDStore store;

    @BeforeEach
    public void beforeEach() throws DIDException {
    	testData = new TestData();
    	store = testData.getStore();
    }

    @AfterEach
    public void afterEach() {
    	testData.cleanup();
    }

	@Test
	public void testInitPrivateIdentity() throws DIDException {
    	assertFalse(store.containsRootIdentities());

    	RootIdentity identity = testData.getRootIdentity();
    	assertTrue(store.containsRootIdentities());

    	DIDStore store2 = DIDStore.open(TestConfig.storeRoot);
    	assertTrue(store2.containsRootIdentities());
    	RootIdentity identity2 = store2.loadRootIdentity();
    	assertNotNull(identity2);

    	assertEquals(identity.getPreDerivedPublicKey().serializePublicKeyBase58(),
    			identity2.getPreDerivedPublicKey().serializePublicKeyBase58());

    	String exportedMnemonic = identity2.exportMnemonic(TestConfig.storePass);
    	assertEquals(testData.getMnemonic(), exportedMnemonic);
	}

	@Test
	public void testInitPrivateIdentityWithMnemonic() throws DIDException {
		String expectedIDString = "iY4Ghz9tCuWvB5rNwvn4ngWvthZMNzEA7U";
		String mnemonic = "cloth always junk crash fun exist stumble shift over benefit fun toe";

    	assertFalse(store.containsRootIdentities());

    	RootIdentity.create(mnemonic, "", store, TestConfig.storePass);
    	assertTrue(store.containsRootIdentities());

    	DIDStore store2 = DIDStore.open(TestConfig.storeRoot);
    	assertTrue(store2.containsRootIdentities());

    	RootIdentity identity2 = store2.loadRootIdentity();

    	DIDDocument doc = identity2.newDid(TestConfig.storePass);
    	assertNotNull(doc);
    	assertEquals(expectedIDString, doc.getSubject().getMethodSpecificId());
	}

	@Test
	public void testInitPrivateIdentityWithRootKey() throws DIDException {
		String expectedIDString = "iYbPqEA98rwvDyA5YT6a3mu8UZy87DLEMR";
		String rootKey = "xprv9s21ZrQH143K4biiQbUq8369meTb1R8KnstYFAKtfwk3vF8uvFd1EC2s49bMQsbdbmdJxUWRkuC48CXPutFfynYFVGnoeq8LJZhfd9QjvUt";

    	assertFalse(store.containsRootIdentities());

    	RootIdentity.create(rootKey, store, TestConfig.storePass);
    	assertTrue(store.containsRootIdentities());

    	DIDStore store2 = DIDStore.open(TestConfig.storeRoot);
    	assertTrue(store2.containsRootIdentities());

    	RootIdentity identity2 = store2.loadRootIdentity();

    	DIDDocument doc = identity2.newDid(TestConfig.storePass);
    	assertNotNull(doc);
    	assertEquals(expectedIDString, doc.getSubject().getMethodSpecificId());
	}

	@Test
	public void testCreateDIDWithAlias() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	String alias = "my first did";

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	doc.getMetadata().setAlias(alias);
    	assertTrue(doc.isValid());

    	DIDDocument resolved = doc.getSubject().resolve();
    	assertNull(resolved);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);

    	// test alias
    	store.storeDid(resolved);
    	assertEquals(alias, resolved.getMetadata().getAlias());
    	assertEquals(doc.getSubject(), resolved.getSubject());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());
	}

	@Test
	public void testCreateDIDWithoutAlias() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	DIDDocument resolved = doc.getSubject().resolve();
    	assertNull(resolved);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.getSubject(), resolved.getSubject());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());
    }

	@Test
	public void testCreateDIDByIndex() throws DIDException {
	    RootIdentity identity = testData.getRootIdentity();

	    DID did = identity.getDid(0);
	    DIDDocument doc = identity.newDid(0, TestConfig.storePass);
	    assertTrue(doc.isValid());
	    assertEquals(did, doc.getSubject());

	    Exception e = assertThrows(DIDAlreadyExistException.class, () -> {
	    	identity.newDid(TestConfig.storePass);
	    });
	    assertEquals("DID already exists in the store.", e.getMessage());

	    boolean success = store.deleteDid(did);
	    assertTrue(success);
	    doc = identity.newDid(TestConfig.storePass);
	    assertTrue(doc.isValid());
	    assertEquals(did, doc.getSubject());
	}

	@Test
	public void testGetDid() throws DIDException {
	    RootIdentity identity = testData.getRootIdentity();

	    for (int i = 0; i < 100; i++) {
		    DIDDocument doc = identity.newDid(i, TestConfig.storePass);
		    assertTrue(doc.isValid());

		    DID did = identity.getDid(i);

		    assertEquals(doc.getSubject(), did);
	    }
	}

}
