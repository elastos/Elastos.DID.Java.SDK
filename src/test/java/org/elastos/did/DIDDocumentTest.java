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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.elastos.did.DIDDocument.PublicKey;
import org.elastos.did.DIDDocument.Service;
import org.elastos.did.crypto.Base58;
import org.elastos.did.crypto.HDKey;
import org.elastos.did.exception.AlreadySignedException;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDNotUpToDateException;
import org.elastos.did.exception.DIDObjectAlreadyExistException;
import org.elastos.did.exception.DIDObjectNotExistException;
import org.elastos.did.exception.IllegalUsage;
import org.elastos.did.exception.NotPrimitiveDIDException;
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
		PublicKey pk = doc.getPublicKey("#primary");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#primary"), pk.getId());

		DIDURL id = new DIDURL(doc.getSubject(), "#key2");
		pk = doc.getPublicKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		id = doc.getDefaultPublicKeyId();
		assertNotNull(id);
		assertEquals(new DIDURL(doc.getSubject(), "#primary"), id);

		// Key not exist, should fail.
		pk = doc.getPublicKey("#notExist");
		assertNull(pk);

		id = new DIDURL(doc.getSubject(), "#notExist");
		pk = doc.getPublicKey(id);
		assertNull(pk);

		// Selector
		id = doc.getDefaultPublicKeyId();
		pks = doc.selectPublicKeys(id, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "#primary"), pks.get(0).getId());

		pks = doc.selectPublicKeys(id, null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "#primary"), pks.get(0).getId());

		pks = doc.selectPublicKeys((DIDURL) null,
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(4, pks.size());

		pks = doc.selectPublicKeys("#key2", Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "#key2"), pks.get(0).getId());

		pks = doc.selectPublicKeys("#key3", null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "#key3"), pks.get(0).getId());
	}

	@Test
	public void testGetPublicKeyWithCid() throws IOException, DIDException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);

		DIDDocument issuer = cd.getDocument("issuer");
		DIDDocument doc = cd.getDocument("examplecorp");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list.
		assertEquals(1, doc.getPublicKeyCount());

		List<PublicKey> pks = doc.getPublicKeys();
		assertEquals(1, pks.size());

		assertEquals(issuer.getDefaultPublicKeyId(), pks.get(0).getId());

		// PublicKey getter.
		PublicKey pk = doc.getPublicKey("#primary");
		assertNull(pk);

		DIDURL id = new DIDURL(doc.getController(), "#primary");
		pk = doc.getPublicKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		id = doc.getDefaultPublicKeyId();
		assertNotNull(id);
		assertEquals(issuer.getDefaultPublicKeyId(), id);

		// Key not exist, should fail.
		pk = doc.getPublicKey("#notExist");
		assertNull(pk);

		id = new DIDURL(doc.getController(), "#notExist");
		pk = doc.getPublicKey(id);
		assertNull(pk);

		// Selector
		id = doc.getDefaultPublicKeyId();
		pks = doc.selectPublicKeys(id, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getController(), "#primary"), pks.get(0).getId());

		pks = doc.selectPublicKeys(id, null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getController(), "#primary"), pks.get(0).getId());

		pks = doc.selectPublicKeys((DIDURL)null, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
	}

	@Test
	public void testGetPublicKeyWithMultiControllerCid1() throws IOException, DIDException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);

		DIDDocument user1 = cd.getDocument("user1");
		DIDDocument user2 = cd.getDocument("user2");
		DIDDocument user3 = cd.getDocument("user3");
		DIDDocument doc = cd.getDocument("foobar");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list.
		assertEquals(7, doc.getPublicKeyCount());

		List<PublicKey> pks = doc.getPublicKeys();
		assertEquals(7, pks.size());

		List<DIDURL> ids = new ArrayList<DIDURL>(5);
		for (PublicKey pk : pks)
			ids.add(pk.getId());

		Collections.sort(ids);

		List<DIDURL> refs = new ArrayList<DIDURL>(5);
		refs.add(user1.getDefaultPublicKeyId());
		refs.add(user2.getDefaultPublicKeyId());
		refs.add(user3.getDefaultPublicKeyId());
		refs.add(new DIDURL(user1.getSubject(), "#key2"));
		refs.add(new DIDURL(user1.getSubject(), "#key3"));
		refs.add(new DIDURL(doc.getSubject(), "#key2"));
		refs.add(new DIDURL(doc.getSubject(), "#key3"));

		Collections.sort(refs);

		assertArrayEquals(refs.toArray(), ids.toArray());

		// PublicKey getter.
		PublicKey pk = doc.getPublicKey("#primary");
		assertNull(pk);

		DIDURL id = new DIDURL(user1.getSubject(), "#primary");
		pk = doc.getPublicKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		id = new DIDURL(user1.getSubject(), "#key2");
		pk = doc.getPublicKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		id = new DIDURL(doc.getSubject(), "#key2");
		pk = doc.getPublicKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		id = new DIDURL(doc.getSubject(), "#key3");
		pk = doc.getPublicKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		id = doc.getDefaultPublicKeyId();
		assertNull(id);

		// Key not exist, should fail.
		pk = doc.getPublicKey("#notExist");
		assertNull(pk);

		id = new DIDURL(doc.getController(), "#notExist");
		pk = doc.getPublicKey(id);
		assertNull(pk);

		// Selector
		id = user1.getDefaultPublicKeyId();
		pks = doc.selectPublicKeys(id, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectPublicKeys(id, null);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectPublicKeys((DIDURL) null,
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(7, pks.size());

		pks = doc.selectPublicKeys(new DIDURL(user1.getSubject(), "#key2"),
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(user1.getSubject(), "#key2"), pks.get(0).getId());

		pks = doc.selectPublicKeys(new DIDURL(doc.getSubject(), "#key3"), null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "#key3"), pks.get(0).getId());
	}

	@Test
	public void testGetPublicKeyWithMultiControllerCid2() throws IOException, DIDException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);

		DIDDocument user1 = cd.getDocument("user1");
		DIDDocument user2 = cd.getDocument("user2");
		DIDDocument user3 = cd.getDocument("user3");
		DIDDocument doc = cd.getDocument("baz");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list.
		assertEquals(5, doc.getPublicKeyCount());

		List<PublicKey> pks = doc.getPublicKeys();
		assertEquals(5, pks.size());

		List<DIDURL> ids = new ArrayList<DIDURL>(5);
		for (PublicKey pk : pks)
			ids.add(pk.getId());

		Collections.sort(ids);

		List<DIDURL> refs = new ArrayList<DIDURL>(5);
		refs.add(user1.getDefaultPublicKeyId());
		refs.add(user2.getDefaultPublicKeyId());
		refs.add(user3.getDefaultPublicKeyId());
		refs.add(new DIDURL(user1.getSubject(), "#key2"));
		refs.add(new DIDURL(user1.getSubject(), "#key3"));

		Collections.sort(refs);

		assertArrayEquals(refs.toArray(), ids.toArray());

		// PublicKey getter.
		PublicKey pk = doc.getPublicKey("#primary");
		assertNull(pk);

		DIDURL id = new DIDURL(user1.getSubject(), "#primary");
		pk = doc.getPublicKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		id = new DIDURL(user1.getSubject(), "#key2");
		pk = doc.getPublicKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		id = doc.getDefaultPublicKeyId();
		assertNull(id);

		// Key not exist, should fail.
		pk = doc.getPublicKey("#notExist");
		assertNull(pk);

		id = new DIDURL(user2.getSubject(), "#notExist");
		pk = doc.getPublicKey(id);
		assertNull(pk);

		// Selector
		id = user2.getDefaultPublicKeyId();
		pks = doc.selectPublicKeys(id, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		id = user3.getDefaultPublicKeyId();
		pks = doc.selectPublicKeys(id, null);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectPublicKeys((DIDURL) null, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(5, pks.size());

		pks = doc.selectPublicKeys(new DIDURL(user1.getSubject(), "#key2"),
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(user1.getSubject(), "#key2"), pks.get(0).getId());

		pks = doc.selectPublicKeys(new DIDURL(user1.getSubject(), "#key3"), null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(user1.getSubject(), "#key3"), pks.get(0).getId());
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
		DIDURL id = new DIDURL(db.getSubject(), "#test1");
		HDKey key = TestData.generateKeypair();
		db.addPublicKey(id, db.getSubject(), key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addPublicKey("#test2", doc.getSubject().toString(), key.getPublicKeyBase58());

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getPublicKey("#test1");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#test1"), pk.getId());

		pk = doc.getPublicKey("#test2");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#test2"), pk.getId());

		// Check the final count.
		assertEquals(6, doc.getPublicKeyCount());
		assertEquals(3, doc.getAuthenticationKeyCount());
		assertEquals(1, doc.getAuthorizationKeyCount());
	}

	@Test
	public void testAddPublicKeyWithCid() throws DIDException, IOException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);
		testData.getRootIdentity();

		cd.getDocument("issuer");
		DIDDocument user1 = cd.getDocument("user1");
		DIDDocument user2 = cd.getDocument("user2");
		cd.getDocument("user3");
		cd.getDocument("examplecorp");

		DIDDocument doc = cd.getDocument("foobar");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit(user1);

		// Add 2 public keys
		DIDURL id = new DIDURL(db.getSubject(), "#test1");
		HDKey key = TestData.generateKeypair();
		db.addPublicKey(id, db.getSubject(), key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addPublicKey("#test2", doc.getSubject().toString(), key.getPublicKeyBase58());

		doc = db.seal(TestConfig.storePass);
		doc = user2.sign(doc, TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getPublicKey("#test1");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#test1"), pk.getId());

		pk = doc.getPublicKey("#test2");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#test2"), pk.getId());

		// Check the final count.
		assertEquals(9, doc.getPublicKeyCount());
		assertEquals(7, doc.getAuthenticationKeyCount());
		assertEquals(0, doc.getAuthorizationKeyCount());
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
		DIDURL id = new DIDURL(doc.getSubject(), "#recovery");
		assertThrows(UnsupportedOperationException.class, () -> {
			db.removePublicKey(id);
	    });

		// force remove public key, should success
		db.removePublicKey(id, true);

		db.removePublicKey("#key2", true);

		// Key not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removePublicKey("#notExistKey", true);
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
		PublicKey pk = doc.getPublicKey("#recovery");
		assertNull(pk);

		pk = doc.getPublicKey("#key2");
		assertNull(pk);

		// Check the final count.
		assertEquals(2, doc.getPublicKeyCount());
		assertEquals(2, doc.getAuthenticationKeyCount());
		assertEquals(0, doc.getAuthorizationKeyCount());
	}

	@Test
	public void testRemovePublicKeyWithCid() throws DIDException, IOException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);
		testData.getRootIdentity();

		cd.getDocument("issuer");
		DIDDocument user1 = cd.getDocument("user1");
		DIDDocument user2 = cd.getDocument("user2");
		cd.getDocument("user3");
		cd.getDocument("examplecorp");

		DIDDocument doc = cd.getDocument("foobar");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit(user2);

		// Can not remove the controller's key
		DIDURL key2 = new DIDURL(user1.getSubject(), "#key2");
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removePublicKey(key2);
	    });

		// key2 used by authentication, should failed.
		DIDURL id = new DIDURL(doc.getSubject(), "#key2");
		assertThrows(UnsupportedOperationException.class, () -> {
			db.removePublicKey(id);
	    });

		// force remove public key, should success
		db.removePublicKey(id, true);

		db.removePublicKey("#key3", true);

		// Key not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removePublicKey("#notExistKey", true);
	    });

		doc = db.seal(TestConfig.storePass);
		doc = user1.sign(doc, TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getPublicKey("#key2");
		assertNull(pk);

		pk = doc.getPublicKey("#key3");
		assertNull(pk);

		// Check the final count.
		assertEquals(5, doc.getPublicKeyCount());
		assertEquals(5, doc.getAuthenticationKeyCount());
		assertEquals(0, doc.getAuthorizationKeyCount());
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
		PublicKey pk = doc.getAuthenticationKey("#primary");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#primary"), pk.getId());

		DIDURL id = new DIDURL(doc.getSubject(), "#key3");
		pk = doc.getAuthenticationKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		// Key not exist, should fail.
		pk = doc.getAuthenticationKey("#notExist");
		assertNull(pk);

		id = new DIDURL(doc.getSubject(), "#notExist");
		pk = doc.getAuthenticationKey(id);
		assertNull(pk);

		// selector
		id = new DIDURL(doc.getSubject(), "#key3");
		pks = doc.selectAuthenticationKeys(id, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectAuthenticationKeys(id, null);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectAuthenticationKeys((DIDURL)null, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(3, pks.size());

		pks = doc.selectAuthenticationKeys("#key2", Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "#key2"), pks.get(0).getId());

		pks = doc.selectAuthenticationKeys("#key2", null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "#key2"), pks.get(0).getId());
	}

	@Test
	public void testGetAuthenticationKeyWithCid() throws IOException, DIDException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);

		DIDDocument issuer = cd.getDocument("issuer");
		DIDDocument doc = cd.getDocument("examplecorp");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list.
		assertEquals(1, doc.getAuthenticationKeyCount());

		List<PublicKey> pks = doc.getAuthenticationKeys();
		assertEquals(1, pks.size());

		assertEquals(issuer.getDefaultPublicKeyId(), pks.get(0).getId());

		PublicKey pk = doc.getAuthenticationKey("#primary");
		assertNull(pk);

		DIDURL id = new DIDURL(doc.getController(), "#primary");
		pk = doc.getAuthenticationKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		// Key not exist, should fail.
		pk = doc.getAuthenticationKey("#notExist");
		assertNull(pk);

		id = new DIDURL(doc.getController(), "#notExist");
		pk = doc.getAuthenticationKey(id);
		assertNull(pk);

		// Selector
		id = doc.getDefaultPublicKeyId();
		pks = doc.selectAuthenticationKeys(id, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getController(), "#primary"),
				pks.get(0).getId());

		pks = doc.selectPublicKeys(id, null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getController(), "#primary"),
				pks.get(0).getId());

		pks = doc.selectAuthenticationKeys((DIDURL) null,
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
	}

	@Test
	public void testGetAuthenticationKeyWithMultiControllerCid1() throws IOException, DIDException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);

		DIDDocument user1 = cd.getDocument("user1");
		DIDDocument user2 = cd.getDocument("user2");
		DIDDocument user3 = cd.getDocument("user3");
		DIDDocument doc = cd.getDocument("foobar");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list.
		assertEquals(7, doc.getAuthenticationKeyCount());

		List<PublicKey> pks = doc.getAuthenticationKeys();
		assertEquals(7, pks.size());

		List<DIDURL> ids = new ArrayList<DIDURL>(5);
		for (PublicKey pk : pks)
			ids.add(pk.getId());

		Collections.sort(ids);

		List<DIDURL> refs = new ArrayList<DIDURL>(5);
		refs.add(user1.getDefaultPublicKeyId());
		refs.add(user2.getDefaultPublicKeyId());
		refs.add(user3.getDefaultPublicKeyId());
		refs.add(new DIDURL(user1.getSubject(), "#key2"));
		refs.add(new DIDURL(user1.getSubject(), "#key3"));
		refs.add(new DIDURL(doc.getSubject(), "#key2"));
		refs.add(new DIDURL(doc.getSubject(), "#key3"));

		Collections.sort(refs);

		assertArrayEquals(refs.toArray(), ids.toArray());

		// PublicKey getter.
		PublicKey pk = doc.getAuthenticationKey("#primary");
		assertNull(pk);

		DIDURL id = new DIDURL(user1.getSubject(), "#primary");
		pk = doc.getAuthenticationKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		id = new DIDURL(user1.getSubject(), "#key2");
		pk = doc.getAuthenticationKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		id = new DIDURL(doc.getSubject(), "#key2");
		pk = doc.getAuthenticationKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		id = new DIDURL(doc.getSubject(), "#key3");
		pk = doc.getAuthenticationKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		// Key not exist, should fail.
		pk = doc.getAuthenticationKey("#notExist");
		assertNull(pk);

		id = new DIDURL(doc.getController(), "#notExist");
		pk = doc.getAuthenticationKey(id);
		assertNull(pk);

		// Selector
		id = user1.getDefaultPublicKeyId();
		pks = doc.selectAuthenticationKeys(id, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectAuthenticationKeys(id, null);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectAuthenticationKeys((DIDURL)null, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(7, pks.size());

		pks = doc.selectAuthenticationKeys(new DIDURL(user1.getSubject(), "#key2"),
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(user1.getSubject(), "#key2"), pks.get(0).getId());

		pks = doc.selectAuthenticationKeys(new DIDURL(doc.getSubject(), "#key3"), null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(doc.getSubject(), "#key3"), pks.get(0).getId());
	}

	@Test
	public void testGetAuthenticationKeyWithMultiControllerCid2() throws IOException, DIDException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);

		DIDDocument user1 = cd.getDocument("user1");
		DIDDocument user2 = cd.getDocument("user2");
		DIDDocument user3 = cd.getDocument("user3");
		DIDDocument doc = cd.getDocument("baz");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list.
		assertEquals(5, doc.getAuthenticationKeyCount());

		List<PublicKey> pks = doc.getAuthenticationKeys();
		assertEquals(5, pks.size());

		List<DIDURL> ids = new ArrayList<DIDURL>(5);
		for (PublicKey pk : pks)
			ids.add(pk.getId());

		Collections.sort(ids);

		List<DIDURL> refs = new ArrayList<DIDURL>(5);
		refs.add(user1.getDefaultPublicKeyId());
		refs.add(user2.getDefaultPublicKeyId());
		refs.add(user3.getDefaultPublicKeyId());
		refs.add(new DIDURL(user1.getSubject(), "#key2"));
		refs.add(new DIDURL(user1.getSubject(), "#key3"));

		Collections.sort(refs);

		assertArrayEquals(refs.toArray(), ids.toArray());

		// PublicKey getter.
		PublicKey pk = doc.getAuthenticationKey("#primary");
		assertNull(pk);

		DIDURL id = new DIDURL(user1.getSubject(), "#primary");
		pk = doc.getAuthenticationKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		id = new DIDURL(user1.getSubject(), "#key2");
		pk = doc.getAuthenticationKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		// Key not exist, should fail.
		pk = doc.getAuthenticationKey("#notExist");
		assertNull(pk);

		id = new DIDURL(user2.getSubject(), "#notExist");
		pk = doc.getPublicKey(id);
		assertNull(pk);

		// Selector
		id = user2.getDefaultPublicKeyId();
		pks = doc.selectAuthenticationKeys(id, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		id = user3.getDefaultPublicKeyId();
		pks = doc.selectAuthenticationKeys(id, null);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectAuthenticationKeys((DIDURL)null, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(5, pks.size());

		pks = doc.selectAuthenticationKeys(new DIDURL(user1.getSubject(), "#key2"),
				Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(user1.getSubject(), "#key2"), pks.get(0).getId());

		pks = doc.selectAuthenticationKeys(new DIDURL(user1.getSubject(), "#key3"), null);
		assertEquals(1, pks.size());
		assertEquals(new DIDURL(user1.getSubject(), "#key3"), pks.get(0).getId());
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
		DIDURL id = new DIDURL(db.getSubject(), "#test1");
		HDKey key = TestData.generateKeypair();
		db.addPublicKey(id, db.getSubject(), key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addPublicKey("#test2", doc.getSubject().toString(), key.getPublicKeyBase58());

		// Add by reference
		db.addAuthenticationKey(new DIDURL(doc.getSubject(), "#test1"));

		db.addAuthenticationKey("#test2");

		// Add new keys
		key = TestData.generateKeypair();
		db.addAuthenticationKey(new DIDURL(doc.getSubject(), "#test3"),
				key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addAuthenticationKey("#test4", key.getPublicKeyBase58());

		// Try to add a non existing key, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.addAuthenticationKey("#notExistKey");
		});

		// Try to add a key not owned by self, should fail.
		assertThrows(IllegalUsage.class, () -> {
			db.addAuthenticationKey("#recovery");
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getAuthenticationKey("#test1");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#test1"), pk.getId());

		pk = doc.getAuthenticationKey("#test2");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#test2"), pk.getId());

		pk = doc.getAuthenticationKey("#test3");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#test3"), pk.getId());

		pk = doc.getAuthenticationKey("#test4");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#test4"), pk.getId());

		// Check the final count.
		assertEquals(8, doc.getPublicKeyCount());
		assertEquals(7, doc.getAuthenticationKeyCount());
		assertEquals(1, doc.getAuthorizationKeyCount());
	}

	@Test
	public void testAddAuthenticationKeyWithCid() throws DIDException, IOException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);

		DIDDocument user1 = cd.getDocument("user1");
		cd.getDocument("user2");
		DIDDocument user3 = cd.getDocument("user3");
		DIDDocument doc = cd.getDocument("foobar");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit(user1);

		// Add 2 public keys for test.
		DIDURL id = new DIDURL(db.getSubject(), "#test1");
		HDKey key = TestData.generateKeypair();
		db.addPublicKey(id, db.getSubject(), key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addPublicKey("#test2", doc.getSubject().toString(), key.getPublicKeyBase58());

		// Add by reference
		db.addAuthenticationKey(new DIDURL(doc.getSubject(), "#test1"));

		db.addAuthenticationKey("#test2");

		// Add new keys
		key = TestData.generateKeypair();
		db.addAuthenticationKey(new DIDURL(doc.getSubject(), "#test3"),
				key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addAuthenticationKey("#test4", key.getPublicKeyBase58());

		// Try to add a controller's key, should fail.
		DIDURL key3 = new DIDURL(user1.getSubject(), "#testkey");
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.addAuthenticationKey(key3);
		});

		// Try to add a non existing key, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.addAuthenticationKey("#notExistKey");
		});

		// Try to add a key not owned by self, should fail.
		DIDURL recovery = new DIDURL(user1.getSubject(), "#recovery");
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.addAuthenticationKey(recovery);
		});

		doc = db.seal(TestConfig.storePass);
		doc = user3.sign(doc, TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getAuthenticationKey("#test1");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#test1"), pk.getId());

		pk = doc.getAuthenticationKey("#test2");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#test2"), pk.getId());

		pk = doc.getAuthenticationKey("#test3");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#test3"), pk.getId());

		pk = doc.getAuthenticationKey("#test4");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#test4"), pk.getId());

		// Check the final count.
		assertEquals(11, doc.getPublicKeyCount());
		assertEquals(11, doc.getAuthenticationKeyCount());
		assertEquals(0, doc.getAuthorizationKeyCount());
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
				new DIDURL(doc.getSubject(), "#test1"),
				key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addAuthenticationKey("#test2", key.getPublicKeyBase58());

		// Remote keys
		db.removeAuthenticationKey(new DIDURL(doc.getSubject(), "#test1"))
			.removeAuthenticationKey("#test2")
			.removeAuthenticationKey("#key2");

		// Key not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeAuthenticationKey("#notExistKey");
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
		PublicKey pk = doc.getAuthenticationKey("#test1");
		assertNull(pk);

		pk = doc.getAuthenticationKey("#test2");
		assertNull(pk);

		pk = doc.getAuthenticationKey("#key2");
		assertNull(pk);

		// Check the final count.
		assertEquals(6, doc.getPublicKeyCount());
		assertEquals(2, doc.getAuthenticationKeyCount());
		assertEquals(1, doc.getAuthorizationKeyCount());
	}

	@Test
	public void testRemoveAuthenticationKeyWithCid() throws DIDException, IOException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);
		testData.getRootIdentity();

		cd.getDocument("issuer");
		DIDDocument user1 = cd.getDocument("user1");
		DIDDocument user2 = cd.getDocument("user2");
		cd.getDocument("user3");
		cd.getDocument("examplecorp");

		DIDDocument doc = cd.getDocument("foobar");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		assertEquals(7, doc.getPublicKeyCount());
		assertEquals(7, doc.getAuthenticationKeyCount());
		assertEquals(0, doc.getAuthorizationKeyCount());

		DIDDocument.Builder db = doc.edit(user1);

		// Remote keys
		db.removeAuthenticationKey(new DIDURL(doc.getSubject(), "#key2"))
			.removeAuthenticationKey("#key3");

		db.removePublicKey("#key3");

		// Key not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeAuthenticationKey("#notExistKey");
		});

		// Remove controller's key, should fail.
		DIDURL key2 = new DIDURL(user1.getSubject(), "#key2");
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeAuthenticationKey(key2);
		});

		doc = db.seal(TestConfig.storePass);
		doc = user2.sign(doc, TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getAuthenticationKey("#key2");
		assertNull(pk);

		pk = doc.getAuthenticationKey("#key3");
		assertNull(pk);

		// Check the final count.
		assertEquals(6, doc.getPublicKeyCount());
		assertEquals(5, doc.getAuthenticationKeyCount());
		assertEquals(0, doc.getAuthorizationKeyCount());
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
		PublicKey pk = doc.getAuthorizationKey("#recovery");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#recovery"), pk.getId());

		DIDURL id = new DIDURL(doc.getSubject(), "#recovery");
		pk = doc.getAuthorizationKey(id);
		assertNotNull(pk);
		assertEquals(id, pk.getId());

		// Key not exist, should fail.
		pk = doc.getAuthorizationKey("#notExistKey");
		assertNull(pk);

		id = new DIDURL(doc.getSubject(), "#notExistKey");
		pk = doc.getAuthorizationKey(id);
		assertNull(pk);

		// Selector
		id = new DIDURL(doc.getSubject(), "#recovery");
		pks = doc.selectAuthorizationKeys(id, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectAuthorizationKeys(id, null);
		assertEquals(1, pks.size());
		assertEquals(id, pks.get(0).getId());

		pks = doc.selectAuthorizationKeys((DIDURL)null, Constants.DEFAULT_PUBLICKEY_TYPE);
		assertEquals(1, pks.size());
	}

	@Test
	public void testGetAuthorizationKeyWithCid() throws DIDException, IOException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);
		testData.getRootIdentity();

		cd.getDocument("issuer");
		cd.getDocument("user1");
		cd.getDocument("user2");
		cd.getDocument("user3");
		cd.getDocument("examplecorp");

		DIDDocument doc = cd.getDocument("foobar");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list.
		assertEquals(0, doc.getAuthorizationKeyCount());

		List<PublicKey> pks = doc.getAuthorizationKeys();
		assertEquals(0, pks.size());
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
		DIDURL id = new DIDURL(db.getSubject(), "#test1");
		HDKey key = TestData.generateKeypair();
		db.addPublicKey(id,
				new DID(DID.METHOD, key.getAddress()),
				key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addPublicKey("#test2",
				new DID(DID.METHOD, key.getAddress()).toString(),
				key.getPublicKeyBase58());

		// Add by reference
		db.addAuthorizationKey(new DIDURL(doc.getSubject(), "#test1"));

		db.addAuthorizationKey("#test2");

		// Add new keys
		key = TestData.generateKeypair();
		db.addAuthorizationKey(new DIDURL(doc.getSubject(), "#test3"),
				new DID(DID.METHOD, key.getAddress()),
				key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addAuthorizationKey("#test4",
				new DID(DID.METHOD, key.getAddress()).toString(),
				key.getPublicKeyBase58());

		// Try to add a non existing key, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.addAuthorizationKey("#notExistKey");
		});

		// Try to add key owned by self, should fail.
		assertThrows(IllegalUsage.class, () -> {
			db.addAuthorizationKey("#key2");
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		PublicKey pk = doc.getAuthorizationKey("#test1");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#test1"), pk.getId());

		pk = doc.getAuthorizationKey("#test2");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#test2"), pk.getId());

		pk = doc.getAuthorizationKey("#test3");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#test3"), pk.getId());

		pk = doc.getAuthorizationKey("#test4");
		assertNotNull(pk);
		assertEquals(new DIDURL(doc.getSubject(), "#test4"), pk.getId());

		// Check the final key count.
		assertEquals(8, doc.getPublicKeyCount());
		assertEquals(3, doc.getAuthenticationKeyCount());
		assertEquals(5, doc.getAuthorizationKeyCount());
	}

	@Test
	public void testAddAuthorizationKeyWithCid() throws DIDException, IOException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);
		testData.getRootIdentity();

		cd.getDocument("issuer");
		DIDDocument user1 = cd.getDocument("user1");
		DIDDocument user2 = cd.getDocument("user2");
		cd.getDocument("user3");
		cd.getDocument("examplecorp");

		DIDDocument doc = cd.getDocument("foobar");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DID did = doc.getSubject();
		DIDDocument.Builder db = doc.edit(user1);

		// Add 2 public keys for test.
		DIDURL id = new DIDURL(db.getSubject(), "#test1");
		HDKey key = TestData.generateKeypair();
		db.addPublicKey(id,
				new DID(DID.METHOD, key.getAddress()),
				key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addPublicKey("#test2",
				new DID(DID.METHOD, key.getAddress()).toString(),
				key.getPublicKeyBase58());

		assertThrows(NotPrimitiveDIDException.class, () -> {
			db.addAuthorizationKey(new DIDURL(did, "#test1"));
		});

		assertThrows(NotPrimitiveDIDException.class, () -> {
			db.addAuthorizationKey("#test2");
		});

		// Try to add a non existing key, should fail.
		assertThrows(NotPrimitiveDIDException.class, () -> {
			db.addAuthorizationKey("#notExistKey");
		});

		// Try to add controller's, should fail.
		DIDURL recovery = new DIDURL(user1.getSubject(), "#recovery");
		assertThrows(NotPrimitiveDIDException.class, () -> {
			db.addAuthorizationKey(recovery);
		});

		doc = db.seal(TestConfig.storePass);
		doc = user2.sign(doc, TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		PublicKey pk = doc.getAuthorizationKey("#test1");
		assertNull(pk);

		pk = doc.getAuthorizationKey("#test2");
		assertNull(pk);

		pk = doc.getAuthorizationKey("#test3");
		assertNull(pk);

		pk = doc.getAuthorizationKey("#test4");
		assertNull(pk);

		// Check the final key count.
		assertEquals(9, doc.getPublicKeyCount());
		assertEquals(7, doc.getAuthenticationKeyCount());
		assertEquals(0, doc.getAuthorizationKeyCount());
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
		DIDURL id = new DIDURL(db.getSubject(), "#test1");
		HDKey key = TestData.generateKeypair();
		db.addAuthorizationKey(id,
				new DID(DID.METHOD, key.getAddress()),
				key.getPublicKeyBase58());

		key = TestData.generateKeypair();
		db.addAuthorizationKey("#test2",
				new DID(DID.METHOD, key.getAddress()).toString(),
				key.getPublicKeyBase58());

		// Remove keys.
		db.removeAuthorizationKey(new DIDURL(doc.getSubject(), "#test1"))
			.removeAuthorizationKey("#recovery");

		// Key not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeAuthorizationKey("#notExistKey");
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		PublicKey pk = doc.getAuthorizationKey("#test1");
		assertNull(pk);

		pk = doc.getAuthorizationKey("#test2");
		assertNotNull(pk);

		pk = doc.getAuthorizationKey("#recovery");
		assertNull(pk);

		// Check the final count.
		assertEquals(6, doc.getPublicKeyCount());
		assertEquals(3, doc.getAuthenticationKeyCount());
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
		VerifiableCredential vc = doc.getCredential("#profile");
		assertNotNull(vc);
		assertEquals(new DIDURL(doc.getSubject(), "#profile"), vc.getId());

		vc = doc.getCredential(new DIDURL(doc.getSubject(), "#email"));
		assertNotNull(vc);
		assertEquals(new DIDURL(doc.getSubject(), "#email"), vc.getId());

		// Credential not exist.
		vc = doc.getCredential("#notExistVc");
		assertNull(vc);

		// Credential selector.
		vcs = doc.selectCredentials(new DIDURL(doc.getSubject(), "#profile"),
				"SelfProclaimedCredential");
		assertEquals(1, vcs.size());
		assertEquals(new DIDURL(doc.getSubject(), "#profile"),
				vcs.get(0).getId());

		vcs = doc.selectCredentials(new DIDURL(doc.getSubject(), "#profile"), null);
		assertEquals(1, vcs.size());
		assertEquals(new DIDURL(doc.getSubject(), "#profile"), vcs.get(0).getId());

		vcs = doc.selectCredentials((DIDURL) null, "SelfProclaimedCredential");
		assertEquals(1, vcs.size());
		assertEquals(new DIDURL(doc.getSubject(), "#profile"), vcs.get(0).getId());

		vcs = doc.selectCredentials((DIDURL) null, "TestingCredential");
		assertEquals(0, vcs.size());
	}

    @Test
	public void testGetCredentialWithCid() throws DIDException, IOException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);
		testData.getRootIdentity();

		cd.getDocument("issuer");
		cd.getDocument("user1");
		cd.getDocument("user2");
		cd.getDocument("user3");
		cd.getDocument("examplecorp");

		DIDDocument doc = cd.getDocument("foobar");
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
		VerifiableCredential vc = doc.getCredential("#profile");
		assertNotNull(vc);
		assertEquals(new DIDURL(doc.getSubject(), "#profile"), vc.getId());

		vc = doc.getCredential(new DIDURL(doc.getSubject(), "#email"));
		assertNotNull(vc);
		assertEquals(new DIDURL(doc.getSubject(), "#email"), vc.getId());

		// Credential not exist.
		vc = doc.getCredential("#notExistVc");
		assertNull(vc);

		// Credential selector.
		vcs = doc.selectCredentials(new DIDURL(doc.getSubject(), "#profile"),
				"SelfProclaimedCredential");
		assertEquals(1, vcs.size());
		assertEquals(new DIDURL(doc.getSubject(), "#profile"), vcs.get(0).getId());

		vcs = doc.selectCredentials(new DIDURL(doc.getSubject(), "#profile"), null);
		assertEquals(1, vcs.size());
		assertEquals(new DIDURL(doc.getSubject(), "#profile"), vcs.get(0).getId());

		vcs = doc.selectCredentials((DIDURL) null, "SelfProclaimedCredential");
		assertEquals(1, vcs.size());
		assertEquals(new DIDURL(doc.getSubject(), "#profile"), vcs.get(0).getId());

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
		vc = doc.getCredential("#passport");
		assertNotNull(vc);
		assertEquals(new DIDURL(doc.getSubject(), "#passport"), vc.getId());

		DIDURL id = new DIDURL(doc.getSubject(), "#twitter");
		vc = doc.getCredential(id);
		assertNotNull(vc);
		assertEquals(id, vc.getId());

		// Should contains 3 credentials.
		assertEquals(4, doc.getCredentialCount());
	}

    @Test
	public void testAddCredentialWithCid() throws DIDException, IOException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);
		testData.getRootIdentity();

		cd.getDocument("issuer");
		DIDDocument user1 = cd.getDocument("user1");
		DIDDocument user2 = cd.getDocument("user2");
		cd.getDocument("user3");
		cd.getDocument("examplecorp");

		DIDDocument doc = cd.getDocument("foobar");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit(user1);

		// Add credentials.
		VerifiableCredential vc = cd.getCredential("foobar", "license");
		db.addCredential(vc);

		vc = cd.getCredential("foobar", "services");
		db.addCredential(vc);

		final VerifiableCredential fvc = vc;
		// Credential already exist, should fail.
		assertThrows(DIDObjectAlreadyExistException.class, () -> {
			db.addCredential(fvc);
		});

		// Credential not belongs to current did, should fail.
		assertThrows(IllegalUsage.class, () -> {
			db.addCredential(cd.getCredential("user1", "passport"));
		});

		doc = db.seal(TestConfig.storePass);
		doc = user2.sign(doc, TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check new added credential.
		vc = doc.getCredential("#license");
		assertNotNull(vc);
		assertEquals(new DIDURL(doc.getSubject(), "#license"), vc.getId());

		DIDURL id = new DIDURL(doc.getSubject(), "#services");
		vc = doc.getCredential(id);
		assertNotNull(vc);
		assertEquals(id, vc.getId());

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
		db.addCredential("#passport", subject, TestConfig.storePass);

		String json = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\"}";
		db.addCredential("#name", json, TestConfig.storePass);

		json = "{\"twitter\":\"@john\"}";
		db.addCredential("#twitter", json, TestConfig.storePass);

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check new added credential.
		VerifiableCredential vc = doc.getCredential("#passport");
		assertNotNull(vc);
		assertEquals(new DIDURL(doc.getSubject(), "#passport"), vc.getId());
		assertTrue(vc.isSelfProclaimed());

		DIDURL id = new DIDURL(doc.getSubject(), "#name");
		vc = doc.getCredential(id);
		assertNotNull(vc);
		assertEquals(id, vc.getId());
		assertTrue(vc.isSelfProclaimed());

		id = new DIDURL(doc.getSubject(), "#twitter");
		vc = doc.getCredential(id);
		assertNotNull(vc);
		assertEquals(id, vc.getId());
		assertTrue(vc.isSelfProclaimed());

		assertEquals(5, doc.getCredentialCount());
	}

    @Test
	public void testAddSelfClaimedCredentialWithCid() throws DIDException, IOException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);
		testData.getRootIdentity();

		cd.getDocument("issuer");
		DIDDocument user1 = cd.getDocument("user1");
		DIDDocument user2 = cd.getDocument("user2");
		cd.getDocument("user3");
		cd.getDocument("examplecorp");

		DIDDocument doc = cd.getDocument("foobar");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit(user2);

		// Add credentials.
		Map<String, Object> subject = new HashMap<String, Object>();
		subject.put("foo", "bar");
		db.addCredential("#testvc", subject, TestConfig.storePass);

		String json = "{\"name\":\"Foo Bar\",\"alternateName\":\"Jason Holtslander\"}";
		db.addCredential("#name", json, TestConfig.storePass);

		json = "{\"twitter\":\"@foobar\"}";
		db.addCredential("#twitter", json, TestConfig.storePass);

		doc = db.seal(TestConfig.storePass);
		doc = user1.sign(doc, TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check new added credential.
		VerifiableCredential vc = doc.getCredential("#testvc");
		assertNotNull(vc);
		assertEquals(new DIDURL(doc.getSubject(), "#testvc"), vc.getId());
		assertTrue(vc.isSelfProclaimed());

		DIDURL id = new DIDURL(doc.getSubject(), "#name");
		vc = doc.getCredential(id);
		assertNotNull(vc);
		assertEquals(id, vc.getId());
		assertTrue(vc.isSelfProclaimed());

		id = new DIDURL(doc.getSubject(), "#twitter");
		vc = doc.getCredential(id);
		assertNotNull(vc);
		assertEquals(id, vc.getId());
		assertTrue(vc.isSelfProclaimed());

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
		db.removeCredential("#profile");

		db.removeCredential(new DIDURL(doc.getSubject(), "#twitter"));

		// Credential not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeCredential("#notExistCredential");
		});

		DID did = doc.getSubject();
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeCredential(new DIDURL(did, "#notExistCredential"));
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		vc = doc.getCredential("#profile");
		assertNull(vc);

		vc = doc.getCredential(new DIDURL(doc.getSubject(), "#twitter"));
		assertNull(vc);

		// Check the final count.
		assertEquals(2, doc.getCredentialCount());
	}

    @Test
	public void testRemoveCredentialWithCid() throws DIDException, IOException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);
		testData.getRootIdentity();

		cd.getDocument("issuer");
		DIDDocument user1 = cd.getDocument("user1");
		DIDDocument user2 = cd.getDocument("user2");
		cd.getDocument("user3");
		cd.getDocument("examplecorp");

		DIDDocument doc = cd.getDocument("foobar");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit(user1);

		// Remove credentials
		db.removeCredential("#profile");

		db.removeCredential(new DIDURL(doc.getSubject(), "#email"));

		// Credential not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeCredential("#notExistCredential");
		});

		DID did = doc.getSubject();
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeCredential(new DIDURL(did, "#notExistCredential"));
		});

		doc = db.seal(TestConfig.storePass);
		doc = user2.sign(doc, TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check existence
		VerifiableCredential vc = doc.getCredential("#profile");
		assertNull(vc);

		vc = doc.getCredential(new DIDURL(doc.getSubject(), "#email"));
		assertNull(vc);

		// Check the final count.
		assertEquals(0, doc.getCredentialCount());
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
		Service svc = doc.getService("#openid");
		assertNotNull(svc);
		assertEquals(new DIDURL(doc.getSubject(), "#openid"), svc.getId());
		assertEquals("OpenIdConnectVersion1.0Service", svc.getType());
		assertEquals("https://openid.example.com/", svc.getServiceEndpoint());
		Map<String, Object> props = svc.getProperties();
		assertTrue(props.isEmpty());

		svc = doc.getService(new DIDURL(doc.getSubject(), "#vcr"));
		assertNotNull(svc);
		assertEquals(new DIDURL(doc.getSubject(), "#vcr"), svc.getId());
		props = svc.getProperties();
		assertTrue(props.isEmpty());

		// Service not exist, should fail.
		svc = doc.getService("#notExistService");
		assertNull(svc);

		// Service selector.
		svcs = doc.selectServices("#vcr", "CredentialRepositoryService");
		assertEquals(1, svcs.size());
		assertEquals(new DIDURL(doc.getSubject(), "#vcr"), svcs.get(0).getId());

		svcs = doc.selectServices(new DIDURL(doc.getSubject(), "#openid"), null);
		assertEquals(1, svcs.size());
		assertEquals(new DIDURL(doc.getSubject(), "#openid"),
				svcs.get(0).getId());

		svcs = doc.selectServices((DIDURL) null, "CarrierAddress");
		assertEquals(1, svcs.size());
		assertEquals(new DIDURL(doc.getSubject(), "#carrier"),
				svcs.get(0).getId());
		props = svcs.get(0).getProperties();
		if (version == 1) {
			assertTrue(props.isEmpty());
		} else {
			assertEquals(12, props.size());
			assertEquals("lalala...", props.get("foobar"));
			assertEquals("Lalala...", props.get("FOOBAR"));
		}

		// Service not exist, should return a empty list.
		svcs = doc.selectServices("#notExistService",
				"CredentialRepositoryService");
		assertEquals(0, svcs.size());

		svcs = doc.selectServices((DIDURL)null, "notExistType");
		assertEquals(0, svcs.size());
	}

    @Test
	public void testGetServiceWithCid() throws DIDException, IOException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);
		testData.getRootIdentity();

		cd.getDocument("issuer");
		cd.getDocument("user1");
		cd.getDocument("user2");
		cd.getDocument("user3");
		cd.getDocument("examplecorp");

		DIDDocument doc = cd.getDocument("foobar");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Count and list
		assertEquals(2, doc.getServiceCount());
		List<Service> svcs = doc.getServices();
		assertEquals(2, svcs.size());

		for (Service svc : svcs) {
			assertEquals(doc.getSubject(), svc.getId().getDid());

			assertTrue(svc.getId().getFragment().equals("vault")
					|| svc.getId().getFragment().equals("vcr"));
		}

		// Service getter, should success.
		Service svc = doc.getService("#vault");
		assertNotNull(svc);
		assertEquals(new DIDURL(doc.getSubject(), "#vault"), svc.getId());
		assertEquals("Hive.Vault.Service", svc.getType());
		assertEquals("https://foobar.com/vault", svc.getServiceEndpoint());
		Map<String, Object> props = svc.getProperties();
		assertTrue(props.isEmpty());

		svc = doc.getService(new DIDURL(doc.getSubject(), "#vcr"));
		assertNotNull(svc);
		assertEquals(new DIDURL(doc.getSubject(), "#vcr"), svc.getId());
		props = svc.getProperties();
		assertEquals(12, props.size());
		assertEquals("lalala...", props.get("foobar"));
		assertEquals("Lalala...", props.get("FOOBAR"));

		// Service not exist, should fail.
		svc = doc.getService("#notExistService");
		assertNull(svc);

		// Service selector.
		svcs = doc.selectServices("#vcr", "CredentialRepositoryService");
		assertEquals(1, svcs.size());
		assertEquals(new DIDURL(doc.getSubject(), "#vcr"), svcs.get(0).getId());

		svcs = doc.selectServices(new DIDURL(doc.getSubject(), "#openid"), null);
		assertEquals(0, svcs.size());

		// Service not exist, should return a empty list.
		svcs = doc.selectServices("#notExistService", "CredentialRepositoryService");
		assertEquals(0, svcs.size());

		svcs = doc.selectServices((DIDURL)null, "notExistType");
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
		db.addService("#test-svc-1", "Service.Testing",
				"https://www.elastos.org/testing1");

		db.addService(new DIDURL(doc.getSubject(), "#test-svc-2"),
				"Service.Testing", "https://www.elastos.org/testing2");

		// Service id already exist, should failed.
		assertThrows(DIDObjectAlreadyExistException.class, () -> {
			db.addService("#vcr", "test", "https://www.elastos.org/test");
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check the final count
		assertEquals(5, doc.getServiceCount());

		// Try to select new added 2 services
		List<Service> svcs = doc.selectServices((DIDURL)null, "Service.Testing");
		assertEquals(2, svcs.size());
		assertEquals("Service.Testing", svcs.get(0).getType());
		assertEquals("Service.Testing", svcs.get(1).getType());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testAddServiceWithDescription(int version) throws DIDException, IOException {
		testData.getRootIdentity();

		Map<String, Object> map = new HashMap<String, Object>();
		map.put("abc", "helloworld");
		map.put("foo", 123);
		map.put("bar", "foobar");
		map.put("foobar", "lalala...");
		map.put("date", Calendar.getInstance().getTime());
		map.put("ABC", "Helloworld");
		map.put("FOO", 678);
		map.put("BAR", "Foobar");
		map.put("FOOBAR", "Lalala...");
		map.put("DATE", Calendar.getInstance().getTime());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("abc", "helloworld");
		props.put("foo", 123);
		props.put("bar", "foobar");
		props.put("foobar", "lalala...");
		props.put("date", Calendar.getInstance().getTime());
		props.put("map", map);
		props.put("ABC", "Helloworld");
		props.put("FOO", 678);
		props.put("BAR", "Foobar");
		props.put("FOOBAR", "Lalala...");
		props.put("DATE", Calendar.getInstance().getTime());
		props.put("MAP", map);

		DIDDocument doc = testData.getCompatibleData(version).getDocument("user1");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit();

		// Add services
		db.addService("#test-svc-1", "Service.Testing",
				"https://www.elastos.org/testing1", props);

		db.addService(new DIDURL(doc.getSubject(), "#test-svc-2"),
				"Service.Testing", "https://www.elastos.org/testing2", props);

		db.addService(new DIDURL(doc.getSubject(), "#test-svc-3"),
				"Service.Testing", "https://www.elastos.org/testing3");

		// Service id already exist, should failed.
		assertThrows(DIDObjectAlreadyExistException.class, () -> {
			db.addService("#vcr", "test", "https://www.elastos.org/test", props);
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check the final count
		assertEquals(6, doc.getServiceCount());

		// Try to select new added 2 services
		List<Service> svcs = doc.selectServices((DIDURL)null, "Service.Testing");
		assertEquals(3, svcs.size());
		assertEquals("Service.Testing", svcs.get(0).getType());
		assertTrue(!svcs.get(0).getProperties().isEmpty());
		assertEquals("Service.Testing", svcs.get(1).getType());
		assertTrue(!svcs.get(1).getProperties().isEmpty());
		assertEquals("Service.Testing", svcs.get(2).getType());
		assertTrue(svcs.get(2).getProperties().isEmpty());
	}

    @Test
	public void testAddServiceWithCid() throws DIDException, IOException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);
		testData.getRootIdentity();

		cd.getDocument("issuer");
		DIDDocument user1 = cd.getDocument("user1");
		cd.getDocument("user2");
		DIDDocument user3 = cd.getDocument("user3");
		cd.getDocument("examplecorp");

		DIDDocument doc = cd.getDocument("foobar");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit(user3);

		// Add services
		db.addService("#test-svc-1", "Service.Testing",
				"https://www.elastos.org/testing1");

		db.addService(new DIDURL(doc.getSubject(), "#test-svc-2"),
				"Service.Testing", "https://www.elastos.org/testing2");

		// Service id already exist, should failed.
		assertThrows(DIDObjectAlreadyExistException.class, () -> {
			db.addService("#vcr", "test", "https://www.elastos.org/test");
		});

		doc = db.seal(TestConfig.storePass);
		doc = user1.sign(doc, TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check the final count
		assertEquals(4, doc.getServiceCount());

		// Try to select new added 2 services
		List<Service> svcs = doc.selectServices((DIDURL)null, "Service.Testing");
		assertEquals(2, svcs.size());
		assertEquals("Service.Testing", svcs.get(0).getType());
		assertEquals("Service.Testing", svcs.get(1).getType());
	}

    @Test
	public void testAddServiceWithCidAndDescription() throws DIDException, IOException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);
		testData.getRootIdentity();

		cd.getDocument("issuer");
		DIDDocument user1 = cd.getDocument("user1");
		cd.getDocument("user2");
		DIDDocument user3 = cd.getDocument("user3");
		cd.getDocument("examplecorp");

		DIDDocument doc = cd.getDocument("foobar");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit(user3);

		Map<String, Object> map = new HashMap<String, Object>();
		map.put("abc", "helloworld");
		map.put("foo", 123);
		map.put("bar", "foobar");
		map.put("foobar", "lalala...");
		map.put("date", Calendar.getInstance().getTime());
		map.put("ABC", "Helloworld");
		map.put("FOO", 678);
		map.put("BAR", "Foobar");
		map.put("FOOBAR", "Lalala...");
		map.put("DATE", Calendar.getInstance().getTime());

		Map<String, Object> props = new HashMap<String, Object>();
		props.put("abc", "helloworld");
		props.put("foo", 123);
		props.put("bar", "foobar");
		props.put("foobar", "lalala...");
		props.put("date", Calendar.getInstance().getTime());
		props.put("map", map);
		props.put("ABC", "Helloworld");
		props.put("FOO", 678);
		props.put("BAR", "Foobar");
		props.put("FOOBAR", "Lalala...");
		props.put("DATE", Calendar.getInstance().getTime());
		props.put("MAP", map);

		// Add services
		db.addService("#test-svc-1", "Service.Testing",
				"https://www.elastos.org/testing1", props);

		db.addService(new DIDURL(doc.getSubject(), "#test-svc-2"),
				"Service.Testing", "https://www.elastos.org/testing2", props);

		db.addService(new DIDURL(doc.getSubject(), "#test-svc-3"),
				"Service.Testing", "https://www.elastos.org/testing3");

		// Service id already exist, should failed.
		assertThrows(DIDObjectAlreadyExistException.class, () -> {
			db.addService("#vcr", "test", "https://www.elastos.org/test", props);
		});

		doc = db.seal(TestConfig.storePass);
		doc = user1.sign(doc, TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		// Check the final count
		assertEquals(5, doc.getServiceCount());

		// Try to select new added 2 services
		List<Service> svcs = doc.selectServices((DIDURL)null, "Service.Testing");
		assertEquals(3, svcs.size());
		assertEquals("Service.Testing", svcs.get(0).getType());
		assertTrue(!svcs.get(0).getProperties().isEmpty());
		assertEquals("Service.Testing", svcs.get(1).getType());
		assertTrue(!svcs.get(1).getProperties().isEmpty());
		assertEquals("Service.Testing", svcs.get(2).getType());
		assertTrue(svcs.get(2).getProperties().isEmpty());
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
		db.removeService("#openid");

		db.removeService(new DIDURL(doc.getSubject(), "#vcr"));

		// Service not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeService("#notExistService");
		});

		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		Service svc = doc.getService("#openid");
		assertNull(svc);

		svc = doc.getService(new DIDURL(doc.getSubject(), "#vcr"));
		assertNull(svc);

		// Check the final count
		assertEquals(1, doc.getServiceCount());
	}

    @Test
	public void testRemoveServiceWithCid() throws DIDException, IOException {
		TestData.CompatibleData cd = testData.getCompatibleData(2);
		testData.getRootIdentity();

		cd.getDocument("issuer");
		DIDDocument user1 = cd.getDocument("user1");
		cd.getDocument("user2");
		DIDDocument user3 = cd.getDocument("user3");
		cd.getDocument("examplecorp");

		DIDDocument doc = cd.getDocument("foobar");
		assertNotNull(doc);
		assertTrue(doc.isValid());

		DIDDocument.Builder db = doc.edit(user1);

		// remove services
		db.removeService("#vault");

		db.removeService(new DIDURL(doc.getSubject(), "#vcr"));

		// Service not exist, should fail.
		assertThrows(DIDObjectNotExistException.class, () -> {
			db.removeService("#notExistService");
		});

		doc = db.seal(TestConfig.storePass);
		doc = user3.sign(doc, TestConfig.storePass);
		assertNotNull(doc);
		assertTrue(doc.isValid());

		Service svc = doc.getService("#openid");
		assertNull(svc);

		svc = doc.getService(new DIDURL(doc.getSubject(), "#vcr"));
		assertNull(svc);

		// Check the final count
		assertEquals(0, doc.getServiceCount());
	}

    @ParameterizedTest
    @CsvSource({
    	"1,issuer",
    	"1,user1",
    	"1,user2",
    	"1,user3",
    	"2,examplecorp",
    	"2,foobar",
    	"2,foo",
    	"2,bar",
    	"2,baz"
    })
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
		DIDURL pkid = new DIDURL(doc.getSubject(), "#primary");

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

	@Test
	public void testCreateCustomizedDid() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument controller = identity.newDid(TestConfig.storePass);
    	assertTrue(controller.isValid());

    	DIDDocument resolved = controller.getSubject().resolve();
    	assertNull(resolved);

    	controller.publish(TestConfig.storePass);

    	resolved = controller.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(controller.getSubject(), resolved.getSubject());
    	assertEquals(controller.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:helloworld");
    	DIDDocument doc = controller.newCustomizedDid(did, TestConfig.storePass);
    	assertTrue(doc.isValid());

    	assertEquals(did, doc.getSubject());
    	assertEquals(controller.getSubject(), doc.getController());

    	resolved = did.resolve();
    	assertNull(resolved);

    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(controller.getSubject(), resolved.getController());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());
    }

	@Test
	public void testCreateMultisigCustomizedDid() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument ctrl1 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl1.isValid());
    	ctrl1.publish(TestConfig.storePass);

    	DIDDocument resolved = ctrl1.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl1.getSubject(), resolved.getSubject());
    	assertEquals(ctrl1.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl2 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl2.isValid());
    	ctrl2.publish(TestConfig.storePass);

    	resolved = ctrl2.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl2.getSubject(), resolved.getSubject());
    	assertEquals(ctrl2.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl3 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl3.isValid());
    	ctrl3.publish(TestConfig.storePass);

    	resolved = ctrl3.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl3.getSubject(), resolved.getSubject());
    	assertEquals(ctrl3.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:helloworld3");
    	DIDDocument doc = ctrl1.newCustomizedDid(did, new DID[] { ctrl2.getSubject(), ctrl3.getSubject() },
    			2, TestConfig.storePass);
    	assertFalse(doc.isValid());

    	final DIDDocument d = doc;
    	assertThrows(AlreadySignedException.class, () -> {
    		ctrl1.sign(d, TestConfig.storePass);
    	});

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

    	resolved = did.resolve();
    	assertNull(resolved);

    	doc.setEffectiveController(ctrl1.getSubject());
    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve();
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

    	DIDDocument resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Update again
    	db = doc.edit();
    	key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key2", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(3, doc.getPublicKeyCount());
    	assertEquals(3, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
	}

	@Test
	public void testUpdateCustomizedDid() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument controller = identity.newDid(TestConfig.storePass);
    	assertTrue(controller.isValid());

    	DIDDocument resolved = controller.getSubject().resolve();
    	assertNull(resolved);

    	controller.publish(TestConfig.storePass);

    	resolved = controller.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(controller.getSubject(), resolved.getSubject());
    	assertEquals(controller.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:helloworld");
    	DIDDocument doc = controller.newCustomizedDid(did, TestConfig.storePass);
    	assertTrue(doc.isValid());

    	assertEquals(did, doc.getSubject());
    	assertEquals(controller.getSubject(), doc.getController());

    	resolved = did.resolve();
    	assertNull(resolved);

    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(controller.getSubject(), resolved.getController());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Update again
    	db = doc.edit();
    	key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key2", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(3, doc.getPublicKeyCount());
    	assertEquals(3, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
    }

	@Test
	public void testUpdateMultisigCustomizedDid() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument ctrl1 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl1.isValid());
    	ctrl1.publish(TestConfig.storePass);

    	DIDDocument resolved = ctrl1.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl1.getSubject(), resolved.getSubject());
    	assertEquals(ctrl1.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl2 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl2.isValid());
    	ctrl2.publish(TestConfig.storePass);

    	resolved = ctrl2.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl2.getSubject(), resolved.getSubject());
    	assertEquals(ctrl2.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl3 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl3.isValid());
    	ctrl3.publish(TestConfig.storePass);

    	resolved = ctrl3.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl3.getSubject(), resolved.getSubject());
    	assertEquals(ctrl3.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:helloworld3");
    	DIDDocument doc = ctrl1.newCustomizedDid(did, new DID[] { ctrl2.getSubject(), ctrl3.getSubject() },
    			2, TestConfig.storePass);
    	assertFalse(doc.isValid());

    	final DIDDocument d = doc;
    	assertThrows(AlreadySignedException.class, () -> {
    		ctrl1.sign(d, TestConfig.storePass);
    	});

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

    	resolved = did.resolve();
    	assertNull(resolved);

    	doc.setEffectiveController(ctrl1.getSubject());
    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Update
    	DIDDocument.Builder db = doc.edit(ctrl2);
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	doc = ctrl1.sign(doc, TestConfig.storePass);
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
    	assertEquals(4, resolved.getPublicKeyCount());
    	assertEquals(4, resolved.getAuthenticationKeyCount());

    	// Update again
    	db = doc.edit(ctrl3);
    	key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key2", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	doc = ctrl2.sign(doc, TestConfig.storePass);
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
    	assertEquals(5, resolved.getPublicKeyCount());
    	assertEquals(5, resolved.getAuthenticationKeyCount());
	}

	@Test
	public void testTransferCustomizedDidAfterCreate() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument controller = identity.newDid(TestConfig.storePass);
    	assertTrue(controller.isValid());

    	DIDDocument resolved = controller.getSubject().resolve();
    	assertNull(resolved);

    	controller.publish(TestConfig.storePass);

    	resolved = controller.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(controller.getSubject(), resolved.getSubject());
    	assertEquals(controller.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:helloworld");
    	DIDDocument doc = controller.newCustomizedDid(did, TestConfig.storePass);
    	assertTrue(doc.isValid());

    	assertEquals(did, doc.getSubject());
    	assertEquals(controller.getSubject(), doc.getController());

    	resolved = did.resolve();
    	assertNull(resolved);

    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(controller.getSubject(), resolved.getController());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// create new controller
    	DIDDocument newController = identity.newDid(TestConfig.storePass);
    	assertTrue(controller.isValid());

    	resolved = newController.getSubject().resolve();
    	assertNull(resolved);

    	newController.publish(TestConfig.storePass);

    	resolved = newController.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(newController.getSubject(), resolved.getSubject());
    	assertEquals(newController.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// create the transfer ticket
    	doc.setEffectiveController(controller.getSubject());
    	TransferTicket ticket = doc.createTransferTicket(newController.getSubject(), TestConfig.storePass);
    	assertTrue(ticket.isValid());

    	// create new document for customized DID
    	doc = newController.newCustomizedDid(did, true, TestConfig.storePass);
    	assertTrue(doc.isValid());

    	assertEquals(did, doc.getSubject());
    	assertEquals(newController.getSubject(), doc.getController());

    	// transfer
    	doc.publish(ticket, TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(newController.getSubject(), resolved.getController());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());
    }

	@Test
	public void testTransferCustomizedDidAfterUpdate() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument controller = identity.newDid(TestConfig.storePass);
    	assertTrue(controller.isValid());

    	DIDDocument resolved = controller.getSubject().resolve();
    	assertNull(resolved);

    	controller.publish(TestConfig.storePass);

    	resolved = controller.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(controller.getSubject(), resolved.getSubject());
    	assertEquals(controller.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:helloworld");
    	DIDDocument doc = controller.newCustomizedDid(did, TestConfig.storePass);
    	assertTrue(doc.isValid());

    	assertEquals(did, doc.getSubject());
    	assertEquals(controller.getSubject(), doc.getController());

    	resolved = did.resolve();
    	assertNull(resolved);

    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(controller.getSubject(), resolved.getController());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// create new controller
    	DIDDocument newController = identity.newDid(TestConfig.storePass);
    	assertTrue(controller.isValid());

    	resolved = newController.getSubject().resolve();
    	assertNull(resolved);

    	newController.publish(TestConfig.storePass);

    	resolved = newController.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(newController.getSubject(), resolved.getSubject());
    	assertEquals(newController.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// create the transfer ticket
    	TransferTicket ticket = controller.createTransferTicket(did, newController.getSubject(), TestConfig.storePass);
    	assertTrue(ticket.isValid());

    	// create new document for customized DID
    	doc = newController.newCustomizedDid(did, true, TestConfig.storePass);
    	assertTrue(doc.isValid());

    	assertEquals(did, doc.getSubject());
    	assertEquals(newController.getSubject(), doc.getController());

    	// transfer
    	doc.publish(ticket, TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(newController.getSubject(), resolved.getController());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());
    }

	@Test
	public void testTransferMultisigCustomizedDidAfterCreate() throws DIDException, IOException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument ctrl1 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl1.isValid());
    	ctrl1.publish(TestConfig.storePass);

    	DIDDocument resolved = ctrl1.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl1.getSubject(), resolved.getSubject());
    	assertEquals(ctrl1.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl2 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl2.isValid());
    	ctrl2.publish(TestConfig.storePass);

    	resolved = ctrl2.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl2.getSubject(), resolved.getSubject());
    	assertEquals(ctrl2.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl3 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl3.isValid());
    	ctrl3.publish(TestConfig.storePass);

    	resolved = ctrl3.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl3.getSubject(), resolved.getSubject());
    	assertEquals(ctrl3.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:helloworld3");
    	DIDDocument doc = ctrl1.newCustomizedDid(did, new DID[] { ctrl2.getSubject(), ctrl3.getSubject() },
    			2, TestConfig.storePass);
    	assertFalse(doc.isValid());

    	final DIDDocument d = doc;
    	assertThrows(AlreadySignedException.class, () -> {
    		ctrl1.sign(d, TestConfig.storePass);
    	});

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

    	resolved = did.resolve();
    	assertNull(resolved);

    	doc.setEffectiveController(ctrl1.getSubject());
    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// new controllers for the did
    	TestData.InstantData td = testData.getInstantData();
    	td.getIssuerDocument();
    	DIDDocument u1 = td.getUser1Document();
    	DIDDocument u2 = td.getUser2Document();
    	DIDDocument u3 = td.getUser3Document();
    	DIDDocument u4 = td.getUser4Document();

    	// transfer ticket
    	TransferTicket ticket = ctrl1.createTransferTicket(did, u1.getSubject(), TestConfig.storePass);
    	ticket = ctrl2.sign(ticket, TestConfig.storePass);
    	assertTrue(ticket.isValid());

    	doc = u1.newCustomizedDid(did, new DID[] {u2.getSubject(), u3.getSubject(), u4.getSubject()},
    				3, true, TestConfig.storePass);
    	doc = u2.sign(doc, TestConfig.storePass);
    	doc = u3.sign(doc, TestConfig.storePass);
    	assertTrue(doc.isValid());

    	assertEquals(did, doc.getSubject());
    	assertEquals(4, doc.getControllerCount());
    	assertEquals("3:4", doc.getMultiSignature().toString());

    	// transfer
    	doc.publish(ticket, TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);

    	assertEquals(did, resolved.getSubject());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());
	}

	@Test
	public void testTransferMultisigCustomizedDidAfterUpdate() throws DIDException, IOException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument ctrl1 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl1.isValid());
    	ctrl1.publish(TestConfig.storePass);

    	DIDDocument resolved = ctrl1.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl1.getSubject(), resolved.getSubject());
    	assertEquals(ctrl1.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl2 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl2.isValid());
    	ctrl2.publish(TestConfig.storePass);

    	resolved = ctrl2.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl2.getSubject(), resolved.getSubject());
    	assertEquals(ctrl2.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl3 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl3.isValid());
    	ctrl3.publish(TestConfig.storePass);

    	resolved = ctrl3.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl3.getSubject(), resolved.getSubject());
    	assertEquals(ctrl3.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:helloworld3");
    	DIDDocument doc = ctrl1.newCustomizedDid(did, new DID[] { ctrl2.getSubject(), ctrl3.getSubject() },
    			2, TestConfig.storePass);
    	assertFalse(doc.isValid());

    	final DIDDocument d = doc;
    	assertThrows(AlreadySignedException.class, () -> {
    		ctrl1.sign(d, TestConfig.storePass);
    	});

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

    	resolved = did.resolve();
    	assertNull(resolved);

    	doc.setEffectiveController(ctrl1.getSubject());
    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Update
    	DIDDocument.Builder db = doc.edit(ctrl2);
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	doc = ctrl1.sign(doc, TestConfig.storePass);
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
    	assertEquals(4, resolved.getPublicKeyCount());
    	assertEquals(4, resolved.getAuthenticationKeyCount());

    	// new controllers for the did
    	TestData.InstantData td = testData.getInstantData();
    	td.getIssuerDocument();
    	DIDDocument u1 = td.getUser1Document();
    	DIDDocument u2 = td.getUser2Document();
    	DIDDocument u3 = td.getUser3Document();
    	DIDDocument u4 = td.getUser4Document();

    	// transfer ticket
    	doc.setEffectiveController(ctrl1.getSubject());
    	TransferTicket ticket = doc.createTransferTicket(u1.getSubject(), TestConfig.storePass);
    	ticket = ctrl2.sign(ticket, TestConfig.storePass);
    	assertTrue(ticket.isValid());

    	doc = u1.newCustomizedDid(did, new DID[] {u2.getSubject(), u3.getSubject(), u4.getSubject()},
    				3, true, TestConfig.storePass);
    	doc = u2.sign(doc, TestConfig.storePass);
    	doc = u3.sign(doc, TestConfig.storePass);
    	assertTrue(doc.isValid());

    	assertEquals(did, doc.getSubject());
    	assertEquals(4, doc.getControllerCount());
    	assertEquals("3:4", doc.getMultiSignature().toString());

    	// transfer
    	doc.publish(ticket, TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);

    	assertEquals(did, resolved.getSubject());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());
	}

	@Test
	public void testUpdateDidWithoutPrevSignature() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.getMetadata().setPreviousSignature(null);

    	// Update again
    	db = doc.edit();
    	key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key2", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(3, doc.getPublicKeyCount());
    	assertEquals(3, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
	}

	@Test
	public void testUpdateDidWithoutSignature() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.getMetadata().setSignature(null);

    	// Update again
    	db = doc.edit();
    	key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key2", key.getPublicKeyBase58());
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

    	DIDDocument resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.getMetadata().setPreviousSignature(null);
    	doc.getMetadata().setSignature(null);

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
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

    	DIDDocument resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.getMetadata().setPreviousSignature(null);
    	doc.getMetadata().setSignature(null);

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(doc.getDefaultPublicKeyId(), true, TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
	}

	@Test
	public void testUpdateDidWithWrongPrevSignature() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

		doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.getMetadata().setPreviousSignature("1234567890");

    	// Update
    	db = doc.edit();
    	key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key2", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(3, doc.getPublicKeyCount());
    	assertEquals(3, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

		doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
	}

	@Test
	public void testUpdateDidWithWrongSignature() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

   		doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.getMetadata().setSignature("1234567890");

    	// Update
    	db = doc.edit();
    	key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key2", key.getPublicKeyBase58());
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

    	DIDDocument resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.getMetadata().setPreviousSignature("1234567890");
    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(doc.getDefaultPublicKeyId(), true, TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
	}

	@Test
	public void testForceUpdateDidWithWrongSignature() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.getMetadata().setSignature("1234567890");

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(doc.getDefaultPublicKeyId(), true, TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
	}

	@Test
	public void testDeactivateSelfAfterCreate() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.deactivate(TestConfig.storePass);

    	doc = doc.getSubject().resolve();
    	assertTrue(doc.isDeactivated());
	}

	@Test
	public void testDeactivateSelfAfterUpdate() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	doc.deactivate(TestConfig.storePass);
    	doc = doc.getSubject().resolve();
    	assertTrue(doc.isDeactivated());
	}

	@Test
	public void testDeactivateCustomizedDidAfterCreate() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument controller = identity.newDid(TestConfig.storePass);
    	assertTrue(controller.isValid());

    	DIDDocument resolved = controller.getSubject().resolve();
    	assertNull(resolved);

    	controller.publish(TestConfig.storePass);

    	resolved = controller.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(controller.getSubject(), resolved.getSubject());
    	assertEquals(controller.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:helloworld");
    	DIDDocument doc = controller.newCustomizedDid(did, TestConfig.storePass);
    	assertTrue(doc.isValid());

    	assertEquals(did, doc.getSubject());
    	assertEquals(controller.getSubject(), doc.getController());

    	resolved = did.resolve();
    	assertNull(resolved);

    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(controller.getSubject(), resolved.getController());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Deactivate
    	doc.deactivate(TestConfig.storePass);
    	doc = doc.getSubject().resolve();
    	assertTrue(doc.isDeactivated());
    }

	@Test
	public void testDeactivateCustomizedDidAfterUpdate() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument controller = identity.newDid(TestConfig.storePass);
    	assertTrue(controller.isValid());

    	DIDDocument resolved = controller.getSubject().resolve();
    	assertNull(resolved);

    	controller.publish(TestConfig.storePass);

    	resolved = controller.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(controller.getSubject(), resolved.getSubject());
    	assertEquals(controller.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:helloworld");
    	DIDDocument doc = controller.newCustomizedDid(did, TestConfig.storePass);
    	assertTrue(doc.isValid());

    	assertEquals(did, doc.getSubject());
    	assertEquals(controller.getSubject(), doc.getController());

    	resolved = did.resolve();
    	assertNull(resolved);

    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(controller.getSubject(), resolved.getController());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Deactivate
    	doc.deactivate(TestConfig.storePass);
    	doc = doc.getSubject().resolve();
    	assertTrue(doc.isDeactivated());
    }

	@Test
	public void testDeactivateCidAfterCreateByController() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument controller = identity.newDid(TestConfig.storePass);
    	assertTrue(controller.isValid());

    	DIDDocument resolved = controller.getSubject().resolve();
    	assertNull(resolved);

    	controller.publish(TestConfig.storePass);

    	resolved = controller.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(controller.getSubject(), resolved.getSubject());
    	assertEquals(controller.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:helloworld");
    	DIDDocument doc = controller.newCustomizedDid(did, TestConfig.storePass);
    	assertTrue(doc.isValid());

    	assertEquals(did, doc.getSubject());
    	assertEquals(controller.getSubject(), doc.getController());

    	resolved = did.resolve();
    	assertNull(resolved);

    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(controller.getSubject(), resolved.getController());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Deactivate
    	controller.deactivate(did, TestConfig.storePass);
    	doc = did.resolve();
    	assertTrue(doc.isDeactivated());
    }

	@Test
	public void testDeactivateCidAfterUpdateByController() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument controller = identity.newDid(TestConfig.storePass);
    	assertTrue(controller.isValid());

    	DIDDocument resolved = controller.getSubject().resolve();
    	assertNull(resolved);

    	controller.publish(TestConfig.storePass);

    	resolved = controller.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(controller.getSubject(), resolved.getSubject());
    	assertEquals(controller.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:helloworld");
    	DIDDocument doc = controller.newCustomizedDid(did, TestConfig.storePass);
    	assertTrue(doc.isValid());

    	assertEquals(did, doc.getSubject());
    	assertEquals(controller.getSubject(), doc.getController());

    	resolved = did.resolve();
    	assertNull(resolved);

    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(controller.getSubject(), resolved.getController());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Update
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	assertEquals(2, doc.getPublicKeyCount());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	// Deactivate
    	controller.deactivate(did, TestConfig.storePass);
    	doc = did.resolve();
    	assertTrue(doc.isDeactivated());
    }

	@Test
	public void testDeactivateMultisigCustomizedDidAfterCreate() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument ctrl1 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl1.isValid());
    	ctrl1.publish(TestConfig.storePass);

    	DIDDocument resolved = ctrl1.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl1.getSubject(), resolved.getSubject());
    	assertEquals(ctrl1.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl2 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl2.isValid());
    	ctrl2.publish(TestConfig.storePass);

    	resolved = ctrl2.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl2.getSubject(), resolved.getSubject());
    	assertEquals(ctrl2.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl3 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl3.isValid());
    	ctrl3.publish(TestConfig.storePass);

    	resolved = ctrl3.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl3.getSubject(), resolved.getSubject());
    	assertEquals(ctrl3.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:helloworld3");
    	DIDDocument doc = ctrl1.newCustomizedDid(did, new DID[] { ctrl2.getSubject(), ctrl3.getSubject() },
    			2, TestConfig.storePass);
    	assertFalse(doc.isValid());

    	final DIDDocument d = doc;
    	assertThrows(AlreadySignedException.class, () -> {
    		ctrl1.sign(d, TestConfig.storePass);
    	});

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

    	resolved = did.resolve();
    	assertNull(resolved);

    	doc.setEffectiveController(ctrl1.getSubject());
    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Deactivate
    	doc.deactivate(ctrl1.getDefaultPublicKeyId(), TestConfig.storePass);
    	doc = doc.getSubject().resolve();
    	assertTrue(doc.isDeactivated());
	}

	@Test
	public void testDeactivateMultisigCustomizedDidAfterUpdate() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument ctrl1 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl1.isValid());
    	ctrl1.publish(TestConfig.storePass);

    	DIDDocument resolved = ctrl1.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl1.getSubject(), resolved.getSubject());
    	assertEquals(ctrl1.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl2 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl2.isValid());
    	ctrl2.publish(TestConfig.storePass);

    	resolved = ctrl2.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl2.getSubject(), resolved.getSubject());
    	assertEquals(ctrl2.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl3 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl3.isValid());
    	ctrl3.publish(TestConfig.storePass);

    	resolved = ctrl3.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl3.getSubject(), resolved.getSubject());
    	assertEquals(ctrl3.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:helloworld3");
    	DIDDocument doc = ctrl1.newCustomizedDid(did, new DID[] { ctrl2.getSubject(), ctrl3.getSubject() },
    			2, TestConfig.storePass);
    	assertFalse(doc.isValid());

    	final DIDDocument d = doc;
    	assertThrows(AlreadySignedException.class, () -> {
    		ctrl1.sign(d, TestConfig.storePass);
    	});

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

    	resolved = did.resolve();
    	assertNull(resolved);

    	doc.setEffectiveController(ctrl1.getSubject());
    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Update
    	DIDDocument.Builder db = doc.edit(ctrl2);
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	doc = ctrl1.sign(doc, TestConfig.storePass);
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
    	assertEquals(4, resolved.getPublicKeyCount());
    	assertEquals(4, resolved.getAuthenticationKeyCount());

    	// Deactivate
    	doc.deactivate(ctrl1.getDefaultPublicKeyId(), TestConfig.storePass);
    	doc = doc.getSubject().resolve();
    	assertTrue(doc.isDeactivated());
	}

	@Test
	public void testDeactivateMultisigCidAfterCreateByController() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument ctrl1 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl1.isValid());
    	ctrl1.publish(TestConfig.storePass);

    	DIDDocument resolved = ctrl1.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl1.getSubject(), resolved.getSubject());
    	assertEquals(ctrl1.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl2 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl2.isValid());
    	ctrl2.publish(TestConfig.storePass);

    	resolved = ctrl2.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl2.getSubject(), resolved.getSubject());
    	assertEquals(ctrl2.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl3 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl3.isValid());
    	ctrl3.publish(TestConfig.storePass);

    	resolved = ctrl3.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl3.getSubject(), resolved.getSubject());
    	assertEquals(ctrl3.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:helloworld3");
    	DIDDocument doc = ctrl1.newCustomizedDid(did, new DID[] { ctrl2.getSubject(), ctrl3.getSubject() },
    			2, TestConfig.storePass);
    	assertFalse(doc.isValid());

    	final DIDDocument d = doc;
    	assertThrows(AlreadySignedException.class, () -> {
    		ctrl1.sign(d, TestConfig.storePass);
    	});

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

    	resolved = did.resolve();
    	assertNull(resolved);

    	doc.setEffectiveController(ctrl1.getSubject());
    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Deactivate
    	ctrl1.deactivate(did, TestConfig.storePass);
    	doc = did.resolve();
    	assertTrue(doc.isDeactivated());
	}

	@Test
	public void testDeactivateMultisigCidAfterUpdateByController() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

    	// Create normal DID first
    	DIDDocument ctrl1 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl1.isValid());
    	ctrl1.publish(TestConfig.storePass);

    	DIDDocument resolved = ctrl1.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl1.getSubject(), resolved.getSubject());
    	assertEquals(ctrl1.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl2 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl2.isValid());
    	ctrl2.publish(TestConfig.storePass);

    	resolved = ctrl2.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl2.getSubject(), resolved.getSubject());
    	assertEquals(ctrl2.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

       	DIDDocument ctrl3 = identity.newDid(TestConfig.storePass);
    	assertTrue(ctrl3.isValid());
    	ctrl3.publish(TestConfig.storePass);

    	resolved = ctrl3.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(ctrl3.getSubject(), resolved.getSubject());
    	assertEquals(ctrl3.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Create customized DID
    	DID did = new DID("did:elastos:helloworld3");
    	DIDDocument doc = ctrl1.newCustomizedDid(did, new DID[] { ctrl2.getSubject(), ctrl3.getSubject() },
    			2, TestConfig.storePass);
    	assertFalse(doc.isValid());

    	final DIDDocument d = doc;
    	assertThrows(AlreadySignedException.class, () -> {
    		ctrl1.sign(d, TestConfig.storePass);
    	});

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

    	resolved = did.resolve();
    	assertNull(resolved);

    	doc.setEffectiveController(ctrl1.getSubject());
    	doc.publish(TestConfig.storePass);

    	resolved = did.resolve();
    	assertNotNull(resolved);
    	assertEquals(did, resolved.getSubject());
    	assertEquals(doc.getProof().getSignature(),
    			resolved.getProof().getSignature());

    	assertTrue(resolved.isValid());

    	// Update
    	DIDDocument.Builder db = doc.edit(ctrl2);
    	HDKey key = TestData.generateKeypair();
    	db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
    	doc = db.seal(TestConfig.storePass);
    	doc = ctrl1.sign(doc, TestConfig.storePass);
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());
    	assertEquals(4, resolved.getPublicKeyCount());
    	assertEquals(4, resolved.getAuthenticationKeyCount());

    	// Deactivate
    	ctrl2.deactivate(did, TestConfig.storePass);
    	doc = did.resolve();
    	assertTrue(doc.isDeactivated());
	}

	@Test
	public void testDeactivateWithAuthorization1() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	assertTrue(doc.isValid());

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	DIDDocument target = identity.newDid(TestConfig.storePass);
    	DIDDocument.Builder db = target.edit();
    	db.authorizationDid("#recovery", doc.getSubject().toString());
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
    	target = target.getSubject().resolve();
    	assertTrue(target.isDeactivated());

    	doc = doc.getSubject().resolve();
    	assertFalse(doc.isDeactivated());
	}

	@Test
	public void testDeactivateWithAuthorization2() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	DIDURL id = new DIDURL(doc.getSubject(), "#key-2");
    	db.addAuthenticationKey(id, key.getPublicKeyBase58());
    	store.storePrivateKey(id, key.serialize(), TestConfig.storePass);
    	doc = db.seal(TestConfig.storePass);
    	assertTrue(doc.isValid());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	DIDDocument target = identity.newDid(TestConfig.storePass);
    	db = target.edit();
    	db.addAuthorizationKey("#recovery", doc.getSubject().toString(),
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
    	target = target.getSubject().resolve();
    	assertTrue(target.isDeactivated());

    	doc = doc.getSubject().resolve();
    	assertFalse(doc.isDeactivated());
	}

	@Test
	public void testDeactivateWithAuthorization3() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	DIDDocument doc = identity.newDid(TestConfig.storePass);
    	DIDDocument.Builder db = doc.edit();
    	HDKey key = TestData.generateKeypair();
    	DIDURL id = new DIDURL(doc.getSubject(), "#key-2");
    	db.addAuthenticationKey(id, key.getPublicKeyBase58());
    	store.storePrivateKey(id, key.serialize(), TestConfig.storePass);
    	doc = db.seal(TestConfig.storePass);
    	assertTrue(doc.isValid());
    	assertEquals(2, doc.getAuthenticationKeyCount());
    	store.storeDid(doc);

    	doc.publish(TestConfig.storePass);

    	DIDDocument resolved = doc.getSubject().resolve();
    	assertNotNull(resolved);
    	assertEquals(doc.toString(), resolved.toString());

    	DIDDocument target = identity.newDid(TestConfig.storePass);
    	db = target.edit();
    	db.addAuthorizationKey("#recovery", doc.getSubject().toString(),
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
    	target = target.getSubject().resolve();
    	assertTrue(target.isDeactivated());

    	doc = doc.getSubject().resolve();
    	assertFalse(doc.isDeactivated());
	}
}
