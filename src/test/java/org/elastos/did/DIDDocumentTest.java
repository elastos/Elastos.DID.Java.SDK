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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.elastos.did.DIDDocument.PublicKey;
import org.elastos.did.DIDDocument.Service;
import org.elastos.did.crypto.Base58;
import org.elastos.did.crypto.HDKey;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDNotUpToDateException;
import org.elastos.did.exception.DIDObjectAlreadyExistException;
import org.elastos.did.exception.DIDObjectNotExistException;
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

@ExtendWith(DIDTestExtension.class)
public class DIDDocumentTest {
	private TestData testData;
	private DIDStore store;

	// private static final Logger log = LoggerFactory.getLogger(DIDDocumentTest.class);

    @BeforeEach
    public void beforeEach() throws DIDException {
    	testData = new TestData();
    	store = testData.getStore();
    }

    @AfterEach
    public void afterEach() {
    	testData.cleanup();
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testGetPublicKey(int version) throws IOException, DIDException {
		DIDDocument doc = testData.getCompatibleData(version).getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list.
		assertEquals(4, doc.getPublicKeyCount());

		List<PublicKey> pks = doc.getPublicKeys();
		assertEquals(4, pks.size());

		for (PublicKey pk : pks) {
			assertEquals(doc.getSubject(), pk.getId().getDid());
			assertEquals(Constants.DEFAULT_PUBLICKEY_TYPE, pk.getType());

			if (pk.getId().getFragment().equals("recovery"))
				assertNotEquals(doc.getSubject(), pk.getController());
			else
				assertEquals(doc.getSubject(), pk.getController());

			assertTrue(pk.getId().getFragment().equals("primary")
					|| pk.getId().getFragment().equals("key2")
					|| pk.getId().getFragment().equals("key3")
					|| pk.getId().getFragment().equals("recovery"));
		}

		// PublicKey getter.
		PublicKey pk = doc.getPublicKey("primary");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "primary"), pk.getId());

		DIDURL id = new DIDURL(doc.getSubject(), "key2");
		pk = doc.getPublicKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		id = doc.getDefaultPublicKeyId();
		assertNotNull(id);
		assertEquals(new DIDURL(doc.getSubject(), "primary"), id);

		// Key not exist, should fail.
		pk = doc.getPublicKey("notExist");
		assertNull(pk);

		id = new DIDURL(doc.getSubject(), "notExist");
		pk = doc.getPublicKey(id);
		assertNull(pk);

		// Selector
		id = doc.getDefaultPublicKeyId();
		pks = doc.selectPublicKeys(id, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "primary"),
				pks.get(0).getId());

		pks = doc.selectPublicKeys(id, null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "primary"),
				pks.get(0).getId());

		pks = doc.selectPublicKeys((DIDURL) null,
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(4, pks.size());

		pks = doc.selectPublicKeys("key2", Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "key2"), pks.get(0).getId());

		pks = doc.selectPublicKeys("key3", null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "key3"), pks.get(0).getId());
	}

	//@Test
	public void testGetPublicKeyWithEmptyCid() throws IOException, DIDException {
		DIDDocument doc = null; // TODO: testData.getCompatibleData().loadEmptyCustomizedDidDocument();
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list.
		assertEquals(4, doc.getPublicKeyCount());

		List<PublicKey> pks = doc.getPublicKeys();
		assertEquals(4, pks.size());

		for (PublicKey pk : pks) {
			assertEquals(doc.getController(), pk.getId().getDid());
			assertEquals(Constants.DEFAULT_PUBLICKEY_TYPE, pk.getType());

			if (pk.getId().getFragment().equals("recovery"))
				assertNotEquals(doc.getController(), pk.getController());
			else
				assertEquals(doc.getController(), pk.getController());

			assertTrue(pk.getId().getFragment().equals("primary")
					|| pk.getId().getFragment().equals("key2")
					|| pk.getId().getFragment().equals("key3")
					|| pk.getId().getFragment().equals("recovery"));
		}

		// PublicKey getter.
		PublicKey pk = doc.getPublicKey("primary");
		assertNull(pk);
		pk = doc.getPublicKey(new DIDURL(doc.getController(), "primary"));
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getController(), "primary"), pk.getId());

		DIDURL id = new DIDURL(doc.getController(), "key2");
		pk = doc.getPublicKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		id = doc.getDefaultPublicKeyId();
		assertNotNull(id);
		assertEquals(new DIDURL(doc.getController(), "primary"), id);

		// Key not exist, should fail.
		pk = doc.getPublicKey("notExist");
		assertNull(pk);

		id = new DIDURL(doc.getController(), "notExist");
		pk = doc.getPublicKey(id);
		assertNull(pk);

		// Selector
		id = doc.getDefaultPublicKeyId();
		pks = doc.selectPublicKeys(id, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getController(), "primary"),
				pks.get(0).getId());

		pks = doc.selectPublicKeys(id, null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getController(), "primary"),
				pks.get(0).getId());

		pks = doc.selectPublicKeys((DIDURL) null,
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(4, pks.size());

		pks = doc.selectPublicKeys(new DIDURL(doc.getController(), "key2"), Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getController(), "key2"), pks.get(0).getId());

		pks = doc.selectPublicKeys(new DIDURL(doc.getController(), "key3"), null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getController(), "key3"), pks.get(0).getId());
	}

	//@Test
	public void testGetPublicKeyWithCid() throws IOException, DIDException {
		DIDDocument doc = null; // TODO: testData.getCompatibleData().loadCustomizedDidDocument();
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list.
		assertEquals(6, doc.getPublicKeyCount());

		List<PublicKey> pks = doc.getPublicKeys();
		assertEquals(6, pks.size());

		for (PublicKey pk : pks) {
			assertTrue(pk.getId().getDid().equals(doc.getSubject()) ||
					pk.getId().getDid().equals(doc.getController()));
			assertEquals(Constants.DEFAULT_PUBLICKEY_TYPE, pk.getType());

			if (pk.getId().getFragment().equals("recovery"))
				assertNotEquals(doc.getController(), pk.getController());
			else
				assertTrue(pk.getController().equals(doc.getSubject()) ||
						pk.getController().equals(doc.getController()));

			assertTrue(pk.getId().getFragment().equals("k1")
					|| pk.getId().getFragment().equals("k2")
					|| pk.getId().getFragment().equals("primary")
					|| pk.getId().getFragment().equals("key2")
					|| pk.getId().getFragment().equals("key3")
					|| pk.getId().getFragment().equals("recovery"));
		}

		// PublicKey getter.
		PublicKey pk = doc.getPublicKey("k1");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "k1"), pk.getId());

		pk = doc.getPublicKey(new DIDURL(doc.getController(), "primary"));
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getController(), "primary"), pk.getId());

		DIDURL id = new DIDURL(doc.getController(), "key2");
		pk = doc.getPublicKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		id = doc.getDefaultPublicKeyId();
		assertNotNull(id);
		assertEquals(new DIDURL(doc.getController(), "primary"), id);

		// Key not exist, should fail.
		pk = doc.getPublicKey("notExist");
		assertNull(pk);

		id = new DIDURL(doc.getSubject(), "notExist");
		pk = doc.getPublicKey(id);
		assertNull(pk);

		id = new DIDURL(doc.getController(), "notExist");
		pk = doc.getPublicKey(id);
		assertNull(pk);

		// Selector
		id = doc.getDefaultPublicKeyId();
		pks = doc.selectPublicKeys(id, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getController(), "primary"),
				pks.get(0).getId());

		pks = doc.selectPublicKeys(id, null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getController(), "primary"),
				pks.get(0).getId());

		pks = doc.selectPublicKeys((DIDURL) null,
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(6, pks.size());

		pks = doc.selectPublicKeys("k2", Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "k2"), pks.get(0).getId());

		pks = doc.selectPublicKeys(new DIDURL(doc.getController(), "key3"), null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getController(), "key3"), pks.get(0).getId());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testAddPublicKey(int version) throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = testData.getCompatibleData(version).getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// Add 2 public keys
		DIDURL id = new DIDURL(db.getSubject(), "test1");
		HDKey key = TestData.generateKeypair();
		db.addPublicKey(id, db.getSubject(), key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addPublicKey("test2", doc.getSubject().toString(), key.getPublicKeyBase58());

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getPublicKey("test1");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test1"), pk.getId());

		pk = doc.getPublicKey("test2");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test2"), pk.getId());

		// Check the final count.
		assertEquals(6, doc.getPublicKeyCount());
		assertEquals(3, doc.getAuthenticationKeyCount());
		assertEquals(1, doc.getAuthorizationKeyCount());
	}

	//@Test
	public void testAddPublicKeyWithCid() throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = null; //TODO: testData.getCompatibleData().loadCustomizedDidDocument();
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// Add 2 public keys
		DIDURL id = new DIDURL(db.getSubject(), "test1");
		HDKey key = TestData.generateKeypair();
		db.addPublicKey(id, db.getSubject(), key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addPublicKey("test2", doc.getSubject().toString(), key.getPublicKeyBase58());

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getPublicKey("test1");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test1"), pk.getId());

		pk = doc.getPublicKey("test2");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test2"), pk.getId());

		// Check the final count.
		assertEquals(8, doc.getPublicKeyCount());
		assertEquals(5, doc.getAuthenticationKeyCount());
		assertEquals(1, doc.getAuthorizationKeyCount());
	}

	@ParameterizedTest
	@ValueSource(ints = {1, 2})
	public void testRemovePublicKey(int version) throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = testData.getCompatibleData(version).getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// recovery used by authorization, should failed.
		DIDURL id = new DIDURL(doc.getSubject(), "recovery");
		assertThrows(UnsupportedOperationException.class, () -> {
			db.removePublicKey(id);
	    });

		// force remove public key, should success
		db.removePublicKey(id, true);

		db.removePublicKey("key2", true);

		// Key not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removePublicKey("notExistKey", true);
	    });

		// Can not remove default publickey, should fail.
		final DIDDocument d = doc;
		assertThrows(UnsupportedOperationException.class, () -> {
			db.removePublicKey(d.getDefaultPublicKeyId(), true);
	    });

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getPublicKey("recovery");
		assertNull(pk);

		pk = doc.getPublicKey("key2");
		assertNull(pk);

		// Check the final count.
		assertEquals(2, doc.getPublicKeyCount());
		assertEquals(2, doc.getAuthenticationKeyCount());
		assertEquals(0, doc.getAuthorizationKeyCount());
	}

	//@Test
	public void testRemovePublicKeyWithCid() throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = null; // TODO: testData.getCompatibleData().loadCustomizedDidDocument();
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// Can not remove the controller's key
		DIDURL key2 = new DIDURL(doc.getController(), "key2");
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removePublicKey(key2);
	    });

		// recovery used by authentication, should failed.
		DIDURL id = new DIDURL(doc.getSubject(), "k1");
		assertThrows(UnsupportedOperationException.class, () -> {
			db.removePublicKey(id);
	    });

		// force remove public key, should success
		db.removePublicKey(id, true);

		db.removePublicKey("k2", true);

		// Key not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removePublicKey("notExistKey", true);
	    });

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getPublicKey("recovery");
		assertNull(pk);

		pk = doc.getPublicKey("k1");
		assertNull(pk);

		pk = doc.getPublicKey("k2");
		assertNull(pk);

		// Check the final count.
		assertEquals(4, doc.getPublicKeyCount());
		assertEquals(3, doc.getAuthenticationKeyCount());
		assertEquals(1, doc.getAuthorizationKeyCount());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testGetAuthenticationKey(int version) throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = testData.getCompatibleData(version).getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list.
		assertEquals(3, doc.getAuthenticationKeyCount());

		List<PublicKey> pks = doc.getAuthenticationKeys();
		assertEquals(3, pks.size());

		for (PublicKey pk : pks) {
			assertEquals(doc.getSubject(), pk.getId().getDid());
			assertEquals(Constants.DEFAULT_PUBLICKEY_TYPE, pk.getType());

			assertEquals(doc.getSubject(), pk.getController());

			assertTrue(pk.getId().getFragment().equals("primary")
					|| pk.getId().getFragment().equals("key2")
					|| pk.getId().getFragment().equals("key3"));
		}

		// AuthenticationKey getter
		PublicKey pk = doc.getAuthenticationKey("primary");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "primary"), pk.getId());

		DIDURL id = new DIDURL(doc.getSubject(), "key3");
		pk = doc.getAuthenticationKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		// Key not exist, should fail.
		pk = doc.getAuthenticationKey("notExist");
		assertNull(pk);

		id = new DIDURL(doc.getSubject(), "notExist");
		pk = doc.getAuthenticationKey(id);
		assertNull(pk);

		// selector
		id = new DIDURL(doc.getSubject(), "key3");
		pks = doc.selectAuthenticationKeys(id,
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectAuthenticationKeys(id, null);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectAuthenticationKeys((DIDURL) null,
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(3, pks.size());

		pks = doc.selectAuthenticationKeys("key2",
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "key2"), pks.get(0).getId());

		pks = doc.selectAuthenticationKeys("key2", null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "key2"), pks.get(0).getId());
	}

	//@Test
	public void testGetAuthenticationKeyWithCid() throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = null; // TODO: testData.getCompatibleData().loadCustomizedDidDocument();
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list.
		assertEquals(5, doc.getAuthenticationKeyCount());

		List<PublicKey> pks = doc.getAuthenticationKeys();
		assertEquals(5, pks.size());

		for (PublicKey pk : pks) {
			assertTrue(pk.getId().getDid().equals(doc.getSubject()) ||
					pk.getId().getDid().equals(doc.getController()));
			assertEquals(Constants.DEFAULT_PUBLICKEY_TYPE, pk.getType());

			assertTrue(pk.getController().equals(doc.getSubject()) ||
					pk.getController().equals(doc.getController()));

			assertTrue(pk.getId().getFragment().equals("k1")
					|| pk.getId().getFragment().equals("k2")
					|| pk.getId().getFragment().equals("primary")
					|| pk.getId().getFragment().equals("key2")
					|| pk.getId().getFragment().equals("key3"));
		}

		// AuthenticationKey getter
		PublicKey pk = doc.getAuthenticationKey(doc.getController().toString() + "#primary");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getController(), "primary"), pk.getId());

		DIDURL id = new DIDURL(doc.getController(), "key3");
		pk = doc.getAuthenticationKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		pk = doc.getAuthenticationKey("k1");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "k1"), pk.getId());

		id = new DIDURL(doc.getSubject(), "k2");
		pk = doc.getAuthenticationKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		// Key not exist, should fail.
		pk = doc.getAuthenticationKey("notExist");
		assertNull(pk);

		id = new DIDURL(doc.getController(), "notExist");
		pk = doc.getAuthenticationKey(id);
		assertNull(pk);

		// selector
		id = new DIDURL(doc.getController(), "key3");
		pks = doc.selectAuthenticationKeys(id,
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectAuthenticationKeys(id, null);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectAuthenticationKeys((DIDURL) null,
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(5, pks.size());

		pks = doc.selectAuthenticationKeys("k1",
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "k1"), pks.get(0).getId());

		pks = doc.selectAuthenticationKeys("k2", null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "k2"), pks.get(0).getId());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testAddAuthenticationKey(int version) throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = testData.getCompatibleData(version).getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// Add 2 public keys for test.
		DIDURL id = new DIDURL(db.getSubject(), "test1");
		HDKey key = TestData.generateKeypair();
		db.addPublicKey(id, db.getSubject(), key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addPublicKey("test2", doc.getSubject().toString(), key.getPublicKeyBase58());

		// Add by reference
		db.addAuthenticationKey(new DIDURL(doc.getSubject(), "test1"));

		db.addAuthenticationKey("test2");

		// Add new keys
		key = TestData.generateKeypair();
		db.addAuthenticationKey(new DIDURL(doc.getSubject(), "test3"),
				key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addAuthenticationKey("test4", key.getPublicKeyBase58());

		// Try to add a non existing key, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.addAuthenticationKey("notExistKey");
		});

		// Try to add a key not owned by self, should fail.
		assertThrows(UnsupportedOperationException.class, () -> {
			db.addAuthenticationKey("recovery");
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getAuthenticationKey("test1");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test1"), pk.getId());

		pk = doc.getAuthenticationKey("test2");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test2"), pk.getId());

		pk = doc.getAuthenticationKey("test3");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test3"), pk.getId());

		pk = doc.getAuthenticationKey("test4");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test4"), pk.getId());

		// Check the final count.
		assertEquals(8, doc.getPublicKeyCount());
		assertEquals(7, doc.getAuthenticationKeyCount());
		assertEquals(1, doc.getAuthorizationKeyCount());
	}

	//@Test
	public void testAddAuthenticationKeyWithCid() throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = null; // TODO: testData.getCompatibleData().loadEmptyCustomizedDidDocument();
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// Add 2 public keys for test.
		DIDURL id = new DIDURL(db.getSubject(), "test1");
		HDKey key = TestData.generateKeypair();
		db.addPublicKey(id, db.getSubject(), key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addPublicKey("test2", doc.getSubject().toString(), key.getPublicKeyBase58());

		// Add by reference
		db.addAuthenticationKey(new DIDURL(doc.getSubject(), "test1"));

		db.addAuthenticationKey("test2");

		// Add new keys
		key = TestData.generateKeypair();
		db.addAuthenticationKey(new DIDURL(doc.getSubject(), "test3"),
				key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addAuthenticationKey("test4", key.getPublicKeyBase58());

		// Try to add a controller's key, should fail.
		DIDURL key3 = new DIDURL(doc.getController(), "key3");
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.addAuthenticationKey(key3);
		});

		// Try to add a non existing key, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.addAuthenticationKey("notExistKey");
		});

		// Try to add a key not owned by self, should fail.
		DIDURL recovery = new DIDURL(doc.getController(), "recovery");
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.addAuthenticationKey(recovery);
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getAuthenticationKey("test1");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test1"), pk.getId());

		pk = doc.getAuthenticationKey("test2");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test2"), pk.getId());

		pk = doc.getAuthenticationKey("test3");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test3"), pk.getId());

		pk = doc.getAuthenticationKey("test4");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test4"), pk.getId());

		// Check the final count.
		assertEquals(8, doc.getPublicKeyCount());
		assertEquals(7, doc.getAuthenticationKeyCount());
		assertEquals(1, doc.getAuthorizationKeyCount());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    public void testRemoveAuthenticationKey(int version) throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = testData.getCompatibleData(version).getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// Add 2 public keys for test
		HDKey key = TestData.generateKeypair();
		db.addAuthenticationKey(
				new DIDURL(doc.getSubject(), "test1"),
				key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addAuthenticationKey("test2", key.getPublicKeyBase58());

		// Remote keys
		db.removeAuthenticationKey(new DIDURL(doc.getSubject(), "test1"))
			.removeAuthenticationKey("test2")
			.removeAuthenticationKey("key2");

		// Key not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeAuthenticationKey("notExistKey");
		});

		// Default publickey, can not remove, should fail.
		DIDURL id = doc.getDefaultPublicKeyId();
		assertThrows(UnsupportedOperationException.class, () -> {
			db.removeAuthenticationKey(id);
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getAuthenticationKey("test1");
		assertNull(pk);

		pk = doc.getAuthenticationKey("test2");
		assertNull(pk);

		pk = doc.getAuthenticationKey("key2");
		assertNull(pk);

		// Check the final count.
		assertEquals(6, doc.getPublicKeyCount());
		assertEquals(2, doc.getAuthenticationKeyCount());
		assertEquals(1, doc.getAuthorizationKeyCount());
	}

	//@Test
	public void testRemoveAuthenticationKeyWithCid() throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = null; // TODO: testData.getCompatibleData().loadCustomizedDidDocument();
		assertNotNull(doc);
		assertTrue(doc.isValid());

		assertEquals(6, doc.getPublicKeyCount());
		assertEquals(5, doc.getAuthenticationKeyCount());
		assertEquals(1, doc.getAuthorizationKeyCount());

		DIDDocument.Builder db = doc.edit();

		// Remote keys
		db.removeAuthenticationKey(new DIDURL(doc.getSubject(), "k1"))
			.removeAuthenticationKey("k2");

		// Key not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeAuthenticationKey("notExistKey");
		});

		// Remove controller's key, should fail.
		DIDURL key2 = new DIDURL(doc.getController(), "key2");
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeAuthenticationKey(key2);
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getAuthenticationKey("k1");
		assertNull(pk);

		pk = doc.getAuthenticationKey("k2");
		assertNull(pk);

		// Check the final count.
		assertEquals(6, doc.getPublicKeyCount());
		assertEquals(3, doc.getAuthenticationKeyCount());
		assertEquals(1, doc.getAuthorizationKeyCount());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testGetAuthorizationKey(int version) throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = testData.getCompatibleData(version).getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list.
		assertEquals(1, doc.getAuthorizationKeyCount());

		List<PublicKey> pks = doc.getAuthorizationKeys();
		assertEquals(1, pks.size());

		for (PublicKey pk : pks) {
			assertEquals(doc.getSubject(), pk.getId().getDid());
			assertEquals(Constants.DEFAULT_PUBLICKEY_TYPE, pk.getType());

			assertNotEquals(doc.getSubject(), pk.getController());

			assertTrue(pk.getId().getFragment().equals("recovery"));
		}

		// AuthorizationKey getter
		PublicKey pk = doc.getAuthorizationKey("recovery");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "recovery"), pk.getId());

		DIDURL id = new DIDURL(doc.getSubject(), "recovery");
		pk = doc.getAuthorizationKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		// Key not exist, should fail.
		pk = doc.getAuthorizationKey("notExistKey");
		assertNull(pk);

		id = new DIDURL(doc.getSubject(), "notExistKey");
		pk = doc.getAuthorizationKey(id);
		assertNull(pk);

		// Selector
		id = new DIDURL(doc.getSubject(), "recovery");
		pks = doc.selectAuthorizationKeys(id, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectAuthorizationKeys(id, null);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectAuthorizationKeys((DIDURL) null,
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
	}

	//@Test
	public void testGetAuthorizationKeyWithCid() throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = null; // TODO: testData.getCompatibleData().loadCustomizedDidDocument();
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list.
		assertEquals(1, doc.getAuthorizationKeyCount());

		List<PublicKey> pks = doc.getAuthorizationKeys();
		assertEquals(1, pks.size());

		for (PublicKey pk : pks) {
			assertEquals(doc.getController(), pk.getId().getDid());
			assertEquals(Constants.DEFAULT_PUBLICKEY_TYPE, pk.getType());

			assertNotEquals(doc.getController(), pk.getController());

			assertTrue(pk.getId().getFragment().equals("recovery"));
		}

		// AuthorizationKey getter
		DIDURL id = new DIDURL(doc.getController(), "recovery");
		PublicKey pk = doc.getAuthorizationKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		// Key not exist, should fail.
		pk = doc.getAuthorizationKey("notExistKey");
		assertNull(pk);

		id = new DIDURL(doc.getController(), "notExistKey");
		pk = doc.getAuthorizationKey(id);
		assertNull(pk);

		// Selector
		id = new DIDURL(doc.getController(), "recovery");
		pks = doc.selectAuthorizationKeys(id, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectAuthorizationKeys(id, null);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectAuthorizationKeys((DIDURL) null,
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testAddAuthorizationKey(int version) throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = testData.getCompatibleData(version).getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// Add 2 public keys for test.
		DIDURL id = new DIDURL(db.getSubject(), "test1");
		HDKey key = TestData.generateKeypair();
		db.addPublicKey(id,
				new DID(DID.METHOD, key.getAddress()),
				key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addPublicKey("test2",
				new DID(DID.METHOD, key.getAddress()).toString(),
				key.getPublicKeyBase58());

		// Add by reference
		db.addAuthorizationKey(new DIDURL(doc.getSubject(), "test1"));

		db.addAuthorizationKey("test2");

		// Add new keys
		key = TestData.generateKeypair();
		db.addAuthorizationKey(new DIDURL(doc.getSubject(), "test3"),
				new DID(DID.METHOD, key.getAddress()),
				key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addAuthorizationKey("test4",
				new DID(DID.METHOD, key.getAddress()).toString(),
				key.getPublicKeyBase58());

		// Try to add a non existing key, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.addAuthorizationKey("notExistKey");
		});

		// Try to add key owned by self, should fail.
		assertThrows(UnsupportedOperationException.class, () -> {
			db.addAuthorizationKey("key2");
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		PublicKey pk = doc.getAuthorizationKey("test1");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test1"), pk.getId());

		pk = doc.getAuthorizationKey("test2");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test2"), pk.getId());

		pk = doc.getAuthorizationKey("test3");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test3"), pk.getId());

		pk = doc.getAuthorizationKey("test4");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test4"), pk.getId());

		// Check the final key count.
		assertEquals(8, doc.getPublicKeyCount());
		assertEquals(3, doc.getAuthenticationKeyCount());
		assertEquals(5, doc.getAuthorizationKeyCount());
	}

	//@Test
	public void testAddAuthorizationKeyWithCid() throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = null; // TODO: testData.getCompatibleData().loadCustomizedDidDocument();
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// Add 2 public keys for test.
		DIDURL id = new DIDURL(db.getSubject(), "test1");
		HDKey key = TestData.generateKeypair();
		db.addPublicKey(id,
				new DID(DID.METHOD, key.getAddress()),
				key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addPublicKey("test2",
				new DID(DID.METHOD, key.getAddress()).toString(),
				key.getPublicKeyBase58());

		// Add by reference
		db.addAuthorizationKey(new DIDURL(doc.getSubject(), "test1"));

		db.addAuthorizationKey("test2");

		// Add new keys
		key = TestData.generateKeypair();
		db.addAuthorizationKey(new DIDURL(doc.getSubject(), "test3"),
				new DID(DID.METHOD, key.getAddress()),
				key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addAuthorizationKey("test4",
				new DID(DID.METHOD, key.getAddress()).toString(),
				key.getPublicKeyBase58());

		// Try to add a non existing key, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.addAuthorizationKey("notExistKey");
		});

		// Try to add controller's, should fail.
		DIDURL recovery = new DIDURL(doc.getController(), "recovery");
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.addAuthorizationKey(recovery);
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		PublicKey pk = doc.getAuthorizationKey("test1");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test1"), pk.getId());

		pk = doc.getAuthorizationKey("test2");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test2"), pk.getId());

		pk = doc.getAuthorizationKey("test3");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test3"), pk.getId());

		pk = doc.getAuthorizationKey("test4");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "test4"), pk.getId());

		// Check the final key count.
		assertEquals(10, doc.getPublicKeyCount());
		assertEquals(5, doc.getAuthenticationKeyCount());
		assertEquals(5, doc.getAuthorizationKeyCount());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testRemoveAuthorizationKey(int version) throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = testData.getCompatibleData(version).getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// Add 2 keys for test.
		DIDURL id = new DIDURL(db.getSubject(), "test1");
		HDKey key = TestData.generateKeypair();
		db.addAuthorizationKey(id,
				new DID(DID.METHOD, key.getAddress()),
				key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addAuthorizationKey("test2",
				new DID(DID.METHOD, key.getAddress()).toString(),
				key.getPublicKeyBase58());

		// Remove keys.
		db.removeAuthorizationKey(new DIDURL(doc.getSubject(), "test1"))
			.removeAuthorizationKey("recovery");

		// Key not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeAuthorizationKey("notExistKey");
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getAuthorizationKey("test1");
		assertNull(pk);

		pk = doc.getAuthorizationKey("test2");
		assertNotNull(pk);

		pk = doc.getAuthorizationKey("recovery");
		assertNull(pk);

		// Check the final count.
		assertEquals(6, doc.getPublicKeyCount());
		assertEquals(3, doc.getAuthenticationKeyCount());
		assertEquals(1, doc.getAuthorizationKeyCount());
	}

	//@Test
	public void testRemoveAuthorizationKeyWithCid() throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = null; //TODO: testData.getCompatibleData().loadCustomizedDidDocument();
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// Add 2 keys for test.
		DIDURL id = new DIDURL(db.getSubject(), "test1");
		HDKey key = TestData.generateKeypair();
		db.addAuthorizationKey(id,
				new DID(DID.METHOD, key.getAddress()),
				key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addAuthorizationKey("test2",
				new DID(DID.METHOD, key.getAddress()).toString(),
				key.getPublicKeyBase58());

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		assertEquals(8, doc.getPublicKeyCount());
		assertEquals(5, doc.getAuthenticationKeyCount());
		assertEquals(3, doc.getAuthorizationKeyCount());

		DIDDocument.Builder db2 = doc.edit();

		db2.removeAuthorizationKey(id)
			.removeAuthorizationKey("test2");

		// Key not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db2.removeAuthorizationKey("notExistKey");
		});

		DIDURL recovery = new DIDURL(doc.getController(), "recovery");
		assertThrows(DIDObjectNotExistException.class, () -> {
			db2.removeAuthorizationKey(recovery);
		});

		doc = db2.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getAuthorizationKey("test1");
		assertNull(pk);

		pk = doc.getAuthorizationKey("test2");
		assertNull(pk);

		pk = doc.getAuthorizationKey(recovery);
		assertNotNull(pk);

		// Check the final count.
		assertEquals(8, doc.getPublicKeyCount());
		assertEquals(5, doc.getAuthenticationKeyCount());
		assertEquals(1, doc.getAuthorizationKeyCount());
	}

	/*
	@Test
	public void testGetJceKeyPair() throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = testData.loadTestDocument();
		assertNotNull(doc);
		assertTrue(doc.isValid());

		KeyPair keypair = doc.getKeyPair(doc.getDefaultPublicKey());
		assertNotNull(keypair);
		assertNotNull(keypair.getPublic());
		assertNull(keypair.getPrivate());

		keypair = doc.getKeyPair(doc.getDefaultPublicKey(), TestConfig.storePass);
		assertNotNull(keypair);
		assertNotNull(keypair.getPublic());
		assertNotNull(keypair.getPrivate());

		keypair = doc.getKeyPair("key2");
		assertNotNull(keypair);
		assertNotNull(keypair.getPublic());
		assertNull(keypair.getPrivate());

		keypair = doc.getKeyPair("key2", TestConfig.storePass);
		assertNotNull(keypair);
		assertNotNull(keypair.getPublic());
		assertNotNull(keypair.getPrivate());

		keypair = doc.getKeyPair("recovery");
		assertNotNull(keypair);
		assertNotNull(keypair.getPublic());
		assertNull(keypair.getPrivate());

		Exception e = assertThrows(InvalidKeyException.class, () -> {
			doc.getKeyPair("recovery", TestConfig.storePass);
		});
		assertEquals("Don't have private key", e.getMessage());
	}
	*/

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testGetCredential(int version) throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = testData.getCompatibleData(version).getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list.
		assertEquals(2, doc.getCredentialCount());
		List<VerifiableCredential> vcs = doc.getCredentials();
		assertEquals(2, vcs.size());

		for (VerifiableCredential vc : vcs) {
			assertEquals(doc.getSubject(), vc.getId().getDid());
			assertEquals(doc.getSubject(), vc.getSubject().getId());

			assertTrue(vc.getId().getFragment().equals("profile")
					|| vc.getId().getFragment().equals("email"));
		}

		// Credential getter.
		VerifiableCredential vc = doc.getCredential("profile");
		assertNotNull(vc);
		assertEquals(new DIDURL(doc.getSubject(), "profile"), vc.getId());

		vc = doc.getCredential(new DIDURL(doc.getSubject(), "email"));
		assertNotNull(vc);
		assertEquals(new DIDURL(doc.getSubject(), "email"), vc.getId());

		// Credential not exist.
		vc = doc.getCredential("notExistVc");
		assertNull(vc);

		// Credential selector.
		vcs = doc.selectCredentials(new DIDURL(doc.getSubject(), "profile"),
				"SelfProclaimedCredential");
		assertEquals(1, vcs.size());
		assertEquals(new DIDURL(doc.getSubject(), "profile"),
				vcs.get(0).getId());

		vcs = doc.selectCredentials(new DIDURL(doc.getSubject(), "profile"),
				null);
		assertEquals(1, vcs.size());
		assertEquals(new DIDURL(doc.getSubject(), "profile"),
				vcs.get(0).getId());

		vcs = doc.selectCredentials((DIDURL) null, "SelfProclaimedCredential");
		assertEquals(1, vcs.size());
		assertEquals(new DIDURL(doc.getSubject(), "profile"),
				vcs.get(0).getId());

		vcs = doc.selectCredentials((DIDURL) null, "TestingCredential");
		assertEquals(0, vcs.size());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testAddCredential(int version) throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(version);

		testData.getRootIdentity();

		DIDDocument doc = cd.getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// Add credentials.
		VerifiableCredential vc = cd.getCredential("user1", "passport");
		db.addCredential(vc);

		vc = cd.getCredential("user1", "twitter");
		db.addCredential(vc);

		final VerifiableCredential fvc = vc;
		// Credential already exist, should fail.
		assertThrows(DIDObjectAlreadyExistException.class, () -> {
			db.addCredential(fvc);
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check new added credential.
		vc = doc.getCredential("passport");
		assertNotNull(vc);
		assertEquals(new DIDURL(doc.getSubject(), "passport"), vc.getId());

		DIDURL id = new DIDURL(doc.getSubject(), "twitter");
		vc = doc.getCredential(id);
		assertNotNull(vc);
		assertEquals(id, vc.getId());

		// Should contains 3 credentials.
		assertEquals(4, doc.getCredentialCount());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testAddSelfClaimedCredential(int version) throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = testData.getCompatibleData(version).getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// Add credentials.
		Map<String, Object> subject = new HashMap<String, Object>();
		subject.put("passport", "S653258Z07");
		db.addCredential("passport", subject, TestConfig.storePass);

		String json = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\"}";
		db.addCredential("name", json, TestConfig.storePass);

		json = "{\"twitter\":\"@john\"}";
		db.addCredential("twitter", json, TestConfig.storePass);

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check new added credential.
		VerifiableCredential vc = doc.getCredential("passport");
		assertNotNull(vc);
		assertEquals(new DIDURL(doc.getSubject(), "passport"), vc.getId());
		assertTrue(vc.isSelfProclaimed());

		DIDURL id = new DIDURL(doc.getSubject(), "name");
		vc = doc.getCredential(id);
		assertNotNull(vc);
		assertEquals(id, vc.getId());
		assertTrue(vc.isSelfProclaimed());

		id = new DIDURL(doc.getSubject(), "twitter");
		vc = doc.getCredential(id);
		assertNotNull(vc);
		assertEquals(id, vc.getId());
		assertTrue(vc.isSelfProclaimed());

		// Should contains 3 credentials.
		assertEquals(5, doc.getCredentialCount());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testRemoveCredential(int version) throws DIDException, IOException {
    	testData.getRootIdentity();
    	TestData.CompatibleData cd = testData.getCompatibleData(version);

		DIDDocument doc = cd.getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// Add test credentials.
		VerifiableCredential vc = cd.getCredential("user1", "passport");
		db.addCredential(vc);

		vc = cd.getCredential("user1", "twitter");
		db.addCredential(vc);

		// Remove credentials
		db.removeCredential("profile");

		db.removeCredential(new DIDURL(doc.getSubject(), "twitter"));

		// Credential not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeCredential("notExistCredential");
		});

		DID did = doc.getSubject();
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeCredential(new DIDURL(did, "notExistCredential"));
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		vc = doc.getCredential("profile");
		assertNull(vc);

		vc = doc.getCredential(new DIDURL(doc.getSubject(), "twitter"));
		assertNull(vc);

		// Check the final count.
		assertEquals(2, doc.getCredentialCount());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testGetService(int version) throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = testData.getCompatibleData(version).getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list
		assertEquals(3, doc.getServiceCount());
		List<Service> svcs = doc.getServices();
		assertEquals(3, svcs.size());

		for (Service svc : svcs) {
			assertEquals(doc.getSubject(), svc.getId().getDid());

			assertTrue(svc.getId().getFragment().equals("openid")
					|| svc.getId().getFragment().equals("vcr")
					|| svc.getId().getFragment().equals("carrier"));
		}

		// Service getter, should success.
		Service svc = doc.getService("openid");
		assertNotNull(svc);
		assertEquals(new DIDURL(doc.getSubject(), "openid"), svc.getId());
		assertEquals("OpenIdConnectVersion1.0Service", svc.getType());
		assertEquals("https://openid.example.com/", svc.getServiceEndpoint());

		svc = doc.getService(new DIDURL(doc.getSubject(), "vcr"));
		assertNotNull(svc);
		assertEquals(new DIDURL(doc.getSubject(), "vcr"), svc.getId());

		// Service not exist, should fail.
		svc = doc.getService("notExistService");
		assertNull(svc);

		// Service selector.
		svcs = doc.selectServices("vcr", "CredentialRepositoryService");
		assertEquals(1, svcs.size());
		assertEquals(new DIDURL(doc.getSubject(), "vcr"), svcs.get(0).getId());

		svcs = doc.selectServices(new DIDURL(doc.getSubject(), "openid"), null);
		assertEquals(1, svcs.size());
		assertEquals(new DIDURL(doc.getSubject(), "openid"),
				svcs.get(0).getId());

		svcs = doc.selectServices((DIDURL) null, "CarrierAddress");
		assertEquals(1, svcs.size());
		assertEquals(new DIDURL(doc.getSubject(), "carrier"),
				svcs.get(0).getId());

		// Service not exist, should return a empty list.
		svcs = doc.selectServices("notExistService",
				"CredentialRepositoryService");
		assertEquals(0, svcs.size());

		svcs = doc.selectServices((DIDURL) null, "notExistType");
		assertEquals(0, svcs.size());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testAddService(int version) throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = testData.getCompatibleData(version).getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// Add services
		db.addService("test-svc-1", "Service.Testing",
				"https://www.elastos.org/testing1");

		db.addService(new DIDURL(doc.getSubject(), "test-svc-2"),
				"Service.Testing", "https://www.elastos.org/testing2");

		// Service id already exist, should failed.
		assertThrows(DIDObjectAlreadyExistException.class, () -> {
			db.addService("vcr", "test", "https://www.elastos.org/test");
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check the final count
		assertEquals(5, doc.getServiceCount());

		// Try to select new added 2 services
		List<Service> svcs = doc.selectServices((DIDURL) null,
				"Service.Testing");
		assertEquals(2, svcs.size());
		assertEquals("Service.Testing", svcs.get(0).getType());
		assertEquals("Service.Testing", svcs.get(1).getType());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testRemoveService(int version) throws DIDException, IOException {
		testData.getRootIdentity();

		DIDDocument doc = testData.getCompatibleData(version).getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// remove services
		db.removeService("openid");

		db.removeService(new DIDURL(doc.getSubject(), "vcr"));

		// Service not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeService("notExistService");
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		Service svc = doc.getService("openid");
		assertNull(svc);

		svc = doc.getService(new DIDURL(doc.getSubject(), "vcr"));
		assertNull(svc);

		// Check the final count
		assertEquals(1, doc.getServiceCount());
	}

    @ParameterizedTest
    @CsvSource({"1,issuer", "1,user1", "1,user2", "1,user3",
    		"2,examplecorp", "2,foobar", "2,foo", "2,bar", "2,baz"})
	public void testParseAndSerializeDocument(int version, String did)
			throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(version);
    	cd.loadAll();

    	String compactJson = cd.getDocumentJson(did, "compact");
		DIDDocument compact = DIDDocument.parse(compactJson);
		assertNotNull(compact);
		assertTrue(compact.isValid());

	   	String normalizedJson = cd.getDocumentJson(did, "normalized");
		DIDDocument normalized = DIDDocument.parse(normalizedJson);
		assertNotNull(normalized);
		assertTrue(normalized.isValid());

		DIDDocument doc = cd.getDocument(did);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		assertEquals(normalizedJson, compact.toString(true));
		assertEquals(normalizedJson, normalized.toString(true));
		assertEquals(normalizedJson, doc.toString(true));

		// Don't check the compact mode for the old versions
		if (cd.isLatestVersion()) {
			assertEquals(compactJson, compact.toString(false));
			assertEquals(compactJson, normalized.toString(false));
			assertEquals(compactJson, doc.toString(false));
		}
	}

	@Test
	public void testSignAndVerify() throws DIDException, IOException {
		RootIdentity identity = testData.getRootIdentity();
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		byte[] data = new byte[1024];
		DIDURL pkid = new DIDURL(doc.getSubject(), "primary");

		for (int i = 0; i < 10; i++) {
			Arrays.fill(data, (byte) i);

			String sig = doc.sign(pkid, TestConfig.storePass, data);
			boolean result = doc.verify(pkid, sig, data);
			assertTrue(result);

			data[0] = 0xF;
			result = doc.verify(pkid, sig, data);
			assertFalse(result);

			sig = doc.sign(TestConfig.storePass, data);
			result = doc.verify(sig, data);
			assertTrue(result);

			data[0] = (byte) i;
			result = doc.verify(sig, data);
			assertFalse(result);
		}
	}

	@Test
	public void testDerive() throws DIDException, IOException {
		RootIdentity identity = testData.getRootIdentity();
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		for (int i = 0; i < 1000; i++) {
			String strKey = doc.derive(i, TestConfig.storePass);
			HDKey key = HDKey.deserializeBase58(strKey);

			byte[] binKey = Base58.decode(strKey);
			byte[] sk = Arrays.copyOfRange(binKey, 46, 78);

			assertEquals(key.getPrivateKeyBytes().length, sk.length);
			assertArrayEquals(key.getPrivateKeyBytes(), sk);
		}
	}

	@Test
	public void testDeriveFromIdentifier() throws DIDException, IOException {
		String identifier = "org.elastos.did.test";

		RootIdentity identity = testData.getRootIdentity();
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		for (int i = -100; i < 100; i++) {
			String strKey = doc.derive(identifier, i, TestConfig.storePass);
			HDKey key = HDKey.deserializeBase58(strKey);

			byte[] binKey = Base58.decode(strKey);
			byte[] sk = Arrays.copyOfRange(binKey, 46, 78);

			assertEquals(key.getPrivateKeyBytes().length, sk.length);
			assertArrayEquals(key.getPrivateKeyBytes(), sk);
		}
	}

	//@Test
	public void testCreateCustomizedDid() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument controller = identity.newDid(TestConfig.storePass);
    	assertTrue(controller.isValid());

    	DIDDocument resolved = controller.getSubject().resolve(true);
    	assertNull(resolved);

    	controller.publish(TestConfig.storePass);

    	resolved = controller.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(controller.getSubject(), resolved.getSubject());
    	assertEquals(controller.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:foobar");
    	DIDDocument doc = controller.newCustomizedDid(did, TestConfig.storePass);
    	assertTrue(doc.isValid());

    	assertEquals(did, doc.getSubject());
    	assertEquals(controller.getSubject(), doc.getController());

    	resolved = did.resolve(true);
    	assertNull(resolved);

    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve(true);
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(controller.getSubject(), resolved.getController());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());
    }

	//@Test
	public void testCreateMultisigCustomizedDid() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument ctrl1 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl1.isValid());
    	ctrl1.publish(TestConfig.storePass);

    	DIDDocument resolved = ctrl1.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(ctrl1.getSubject(), resolved.getSubject());
    	assertEquals(ctrl1.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl2 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl2.isValid());
    	ctrl2.publish(TestConfig.storePass);

    	resolved = ctrl2.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(ctrl2.getSubject(), resolved.getSubject());
    	assertEquals(ctrl2.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl3 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl3.isValid());
    	ctrl3.publish(TestConfig.storePass);

    	resolved = ctrl3.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(ctrl3.getSubject(), resolved.getSubject());
    	assertEquals(ctrl3.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());


    	// Create customized DID
    	DID did = new DID("did:elastos:foobar");
    	DIDDocument doc = ctrl1.newCustomizedDid(did, new DID[] { ctrl2.getSubject(), ctrl3.getSubject() },
    			2, TestConfig.storePass);
    	assertFalse(doc.isValid());

    	doc = ctrl2.sign(doc, TestConfig.storePass);
    	assertTrue(doc.isValid());

    	assertEquals(did, doc.getSubject());
    	assertEquals(3, doc.getControllerCount());
    	List<DID> ctrls = new ArrayList<DID>();
    	ctrls.add(ctrl1.getSubject());
    	ctrls.add(ctrl2.getSubject());
    	ctrls.add(ctrl3.getSubject());
    	Collections.sort(ctrls);
    	assertArrayEquals(doc.getControllers().toArray(), ctrls.toArray());

    	resolved = did.resolve(true);
    	assertNull(resolved);

    	doc.setEffectiveController(ctrl1.getSubject());
    	doc.publish(TestConfig.storePass);

    	// TODO: improve the checks
    	resolved = did.resolve(true);
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());
    }

	@Test
	public void testUpdateDid() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Update again
    	db = doc.edit();
    	key = TestData.generateKeypair();
    	db.addAuthenticationKey("key2", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(3, doc.getPublicKeyCount());
    	assertEquals(3, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
	}

	//@Test
	public void testUpdateCustomizedDid() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument controller = identity.newDid(TestConfig.storePass);
    	assertTrue(controller.isValid());

    	DIDDocument resolved = controller.getSubject().resolve(true);
    	assertNull(resolved);

    	controller.publish(TestConfig.storePass);

    	resolved = controller.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(controller.getSubject(), resolved.getSubject());
    	assertEquals(controller.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:foobar");
    	DIDDocument doc = controller.newCustomizedDid(did, TestConfig.storePass);
    	assertTrue(doc.isValid());

    	assertEquals(did, doc.getSubject());
    	assertEquals(controller.getSubject(), doc.getController());

    	resolved = did.resolve(true);
    	assertNull(resolved);

    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve(true);
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(controller.getSubject(), resolved.getController());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("foobar-key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Update again
    	db = doc.edit();
    	key = TestData.generateKeypair();
    	db.addAuthenticationKey("foobar-key2", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(3, doc.getPublicKeyCount());
    	assertEquals(3, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    }

	@Test
	public void testUpdateDidWithoutPrevSignature() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.getMetadata().setPreviousSignature(null);

    	// Update again
    	db = doc.edit();
    	key = TestData.generateKeypair();
    	db.addAuthenticationKey("key2", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(3, doc.getPublicKeyCount());
    	assertEquals(3, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
	}


	@Test
	public void testUpdateDidWithoutSignature() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.getMetadata().setSignature(null);

    	// Update again
    	db = doc.edit();
    	key = TestData.generateKeypair();
    	db.addAuthenticationKey("key2", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(3, doc.getPublicKeyCount());
    	assertEquals(3, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	DIDDocument d = doc;
    	Exception e = assertThrows(DIDNotUpToDateException.class, () -> {
    		d.publish(TestConfig.storePass);
    	});
    	assertEquals(d.getSubject().toString(), e.getMessage());
	}

	@Test
	public void testUpdateDidWithoutAllSignatures() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.getMetadata().setPreviousSignature(null);
    	doc.getMetadata().setSignature(null);

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	DIDDocument d = doc;
    	Exception e = assertThrows(DIDNotUpToDateException.class, () -> {
    		d.publish(TestConfig.storePass);
    	});
    	assertEquals(d.getSubject().toString(), e.getMessage());
	}

	@Test
	public void testForceUpdateDidWithoutAllSignatures() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.getMetadata().setPreviousSignature(null);
    	doc.getMetadata().setSignature(null);

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(doc.getDefaultPublicKeyId(), true, TestConfig.storePass);

    	resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
	}

	@Test
	public void testUpdateDidWithWrongPrevSignature() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

		doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.getMetadata().setPreviousSignature("1234567890");

    	// Update
    	db = doc.edit();
    	key = TestData.generateKeypair();
    	db.addAuthenticationKey("key2", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(3, doc.getPublicKeyCount());
    	assertEquals(3, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

		doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
	}

	@Test
	public void testUpdateDidWithWrongSignature() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

   		doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.getMetadata().setSignature("1234567890");

    	// Update
    	db = doc.edit();
    	key = TestData.generateKeypair();
    	db.addAuthenticationKey("key2", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(3, doc.getPublicKeyCount());
    	assertEquals(3, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	DIDDocument d = doc;
    	Exception e = assertThrows(DIDNotUpToDateException.class, () -> {
    		d.publish(TestConfig.storePass);
    	});
    	assertEquals(d.getSubject().toString(), e.getMessage());
	}

	@Test
	public void testForceUpdateDidWithWrongPrevSignature() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.getMetadata().setPreviousSignature("1234567890");
    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(doc.getDefaultPublicKeyId(), true, TestConfig.storePass);

    	resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
	}

	@Test
	public void testForceUpdateDidWithWrongSignature() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.getMetadata().setSignature("1234567890");

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(doc.getDefaultPublicKeyId(), true, TestConfig.storePass);

    	resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
	}

	@Test
	public void testDeactivateSelfAfterCreate() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.deactivate(TestConfig.storePass);

    	doc = doc.getSubject().resolve(true);
    	assertTrue(doc.isDeactivated());
	}

	@Test
	public void testDeactivateSelfAfterUpdate() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.deactivate(TestConfig.storePass);
    	doc = doc.getSubject().resolve(true);
    	assertTrue(doc.isDeactivated());
	}

	@Test
	public void testDeactivateWithAuthorization1() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	DIDDocument target = identity.newDid(TestConfig.storePass);
    	DIDDocument.Builder db = target.edit();
    	db.authorizationDid("recovery", doc.getSubject().toString());
    	target = db.seal(TestConfig.storePass);
    	assertNotNull(target);
    	assertEquals(1, target.getAuthorizationKeyCount());
    	assertEquals(doc.getSubject(), target.getAuthorizationKeys().get(0).getController());
    	store.storeDid(target);

    	target.publish(TestConfig.storePass);

    	resolved = target.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(target.toString(), resolved.toString());

    	doc.deactivate(target.getSubject(), TestConfig.storePass);
    	target = target.getSubject().resolve(true);
    	assertTrue(target.isDeactivated());

    	doc = doc.getSubject().resolve(true);
    	assertFalse(doc.isDeactivated());
	}

	@Test
	public void testDeactivateWithAuthorization2() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	DIDURL id = new DIDURL(doc.getSubject(), "key-2");
    	db.addAuthenticationKey(id, key.getPublicKeyBase58());
    	store.storePrivateKey(id, key.serialize(), TestConfig.storePass);
    	doc = db.seal(TestConfig.storePass);
    	assertTrue(doc.isValid());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	DIDDocument target = identity.newDid(TestConfig.storePass);
    	db = target.edit();
    	db.addAuthorizationKey("recovery", doc.getSubject().toString(),
    			key.getPublicKeyBase58());
    	target = db.seal(TestConfig.storePass);
    	assertNotNull(target);
    	assertEquals(1, target.getAuthorizationKeyCount());
    	assertEquals(doc.getSubject(), target.getAuthorizationKeys().get(0).getController());
    	store.storeDid(target);

    	target.publish(TestConfig.storePass);

    	resolved = target.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(target.toString(), resolved.toString());

    	doc.deactivate(target.getSubject(), id, TestConfig.storePass);
    	target = target.getSubject().resolve(true);
    	assertTrue(target.isDeactivated());

    	doc = doc.getSubject().resolve(true);
    	assertFalse(doc.isDeactivated());
	}

	@Test
	public void testDeactivateWithAuthorization3() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	DIDURL id = new DIDURL(doc.getSubject(), "key-2");
    	db.addAuthenticationKey(id, key.getPublicKeyBase58());
    	store.storePrivateKey(id, key.serialize(), TestConfig.storePass);
    	doc = db.seal(TestConfig.storePass);
    	assertTrue(doc.isValid());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve(true);
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	DIDDocument target = identity.newDid(TestConfig.storePass);
    	db = target.edit();
    	db.addAuthorizationKey("recovery", doc.getSubject().toString(),
    			key.getPublicKeyBase58());
    	target = db.seal(TestConfig.storePass);
    	assertNotNull(target);
    	assertEquals(1, target.getAuthorizationKeyCount());
    	assertEquals(doc.getSubject(), target.getAuthorizationKeys().get(0).getController());
    	store.storeDid(target);

    	target.publish(TestConfig.storePass);

    	resolved = target.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(target.toString(), resolved.toString());

    	doc.deactivate(target.getSubject(), TestConfig.storePass);
    	target = target.getSubject().resolve(true);
    	assertTrue(target.isDeactivated());

    	doc = doc.getSubject().resolve(true);
    	assertFalse(doc.isDeactivated());
	}
}
