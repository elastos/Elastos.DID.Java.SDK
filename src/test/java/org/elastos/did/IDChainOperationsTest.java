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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import org.elastos.did.backend.DIDBiography;
import org.elastos.did.backend.DIDTransaction;
import org.elastos.did.crypto.HDKey;
import org.elastos.did.exception.DIDException;
import org.elastos.did.utils.DIDTestExtension;
import org.elastos.did.utils.TestConfig;
import org.elastos.did.utils.TestData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//@RunWith(Parameterized.class)
@ExtendWith(DIDTestExtension.class)
public class IDChainOperationsTest {
	/*
	@Parameterized.Parameters
	public static Object[][] data() {
		return new Object[50][0];
	}
	*/

	private TestData testData;
	private DIDStore store;
	private RootIdentity identity;

	private static final Logger log = LoggerFactory.getLogger(IDChainOperationsTest.class);

    @BeforeEach
    public void beforeEach() throws DIDException {
    	testData = new TestData();
    	testData.initIdentity();

    	store = testData.getStore();
    	identity = testData.getRootIdentity();

		testData.waitForWalletAvaliable();
    }

    @AfterEach
    public void afterEach() {
    	testData.cleanup();
    }

	@Test
	public void testPublishAndResolve() throws DIDException {
		// Create new DID and publish to ID sidechain.
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		DID did = doc.getSubject();

		log.debug("Publishing new DID {}...", did);
		long start = System.currentTimeMillis();
		doc.publish(TestConfig.storePass);
		long duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Publish new DID {}...OK({}s)", did, duration);

		testData.waitForWalletAvaliable();
		DIDDocument resolved = did.resolve(true);
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));
	}

	@Test
	public void testPublishAndResolveAsync() throws DIDException {
		// Create new DID and publish to ID sidechain.
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		DID did = doc.getSubject();

        log.debug("Publishing new DID {}...", did);
		long start = System.currentTimeMillis();
		CompletableFuture<Void> tf = doc.publishAsync(TestConfig.storePass)
				.thenApply((tx) -> {
					long duration = (System.currentTimeMillis() - start + 500) / 1000;
			        log.debug("Publish new DID {}...OK({}s)", did, duration);
					return tx;
				});
		tf.join();

		testData.waitForWalletAvaliable();
		CompletableFuture<DIDDocument> rf = did.resolveAsync(true);
		DIDDocument resolved = rf.join();
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));
	}

	@Test
	public void testPublishAndResolveAsync2() throws DIDException {
		// Create new DID and publish to ID sidechain.
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		DID did = doc.getSubject();

		log.debug("Publishing new DID and resolve {}...", did);
		long start = System.currentTimeMillis();
		CompletableFuture<DIDDocument> tf = doc.publishAsync(TestConfig.storePass)
				.thenCompose((Void) -> {
					try {
						testData.waitForWalletAvaliable();
					} catch (DIDException e) {
						throw new CompletionException(e);
					}

					return did.resolveAsync(true);
				});
		DIDDocument resolved = tf.join();
		long duration = (System.currentTimeMillis() - start + 500) / 1000;
        log.debug("Publish new DID and resolve {}...OK({}s)", did, duration);

		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));
	}

	@Test
	public void testUpdateAndResolve() throws DIDException {
		String[] sigs = new String[3];

		// Create new DID and publish to ID sidechain.
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		DID did = doc.getSubject();

        log.debug("Publishing new DID {}...", did);
		long start = System.currentTimeMillis();
		doc.publish(TestConfig.storePass);
		long duration = (System.currentTimeMillis() - start + 500) / 1000;
        log.debug("Publish new DID {}...OK({}s)", did, duration);

		sigs[2] = doc.getProof().getSignature();

		testData.waitForWalletAvaliable();
		DIDDocument resolved = did.resolve(true);
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		String lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		// Update
		DIDDocument.Builder db = doc.edit();
		HDKey key = TestData.generateKeypair();
		db.addAuthenticationKey("key1", key.getPublicKeyBase58());
		doc = db.seal(TestConfig.storePass);
		assertEquals(2, doc.getPublicKeyCount());
		assertEquals(2, doc.getAuthenticationKeyCount());
		store.storeDid(doc);

        log.debug("Updating DID {}...", did);
		start = System.currentTimeMillis();
		doc.publish(TestConfig.storePass);
		duration = (System.currentTimeMillis() - start + 500) / 1000;
        log.debug("Update DID {}...OK({}s)", did, duration);

		sigs[1] = doc.getProof().getSignature();

		testData.waitForWalletAvaliable();
		resolved = did.resolve(true);
		assertNotEquals(lastTxid, resolved.getMetadata().getTransactionId());
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		lastTxid = resolved.getMetadata().getTransactionId();
        log.debug("Last transaction id {}", lastTxid);

		// Update again
		db = doc.edit();
		key = TestData.generateKeypair();
		db.addAuthenticationKey("key2", key.getPublicKeyBase58());
		doc = db.seal(TestConfig.storePass);
		assertEquals(3, doc.getPublicKeyCount());
		assertEquals(3, doc.getAuthenticationKeyCount());
		store.storeDid(doc);

        log.debug("Updating DID {}...", did);
		start = System.currentTimeMillis();
		doc.publish(TestConfig.storePass);
		duration = (System.currentTimeMillis() - start + 500) / 1000;
        log.debug("Update DID {}...OK({}s)", did, duration);

		sigs[0] = doc.getProof().getSignature();

		testData.waitForWalletAvaliable();
		resolved = did.resolve(true);
		assertNotEquals(lastTxid, resolved.getMetadata().getTransactionId());
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		lastTxid = resolved.getMetadata().getTransactionId();
        log.debug("Last transaction id {}", lastTxid);

		DIDBiography rr = did.resolveBiography();
		assertNotNull(rr);
		assertEquals(did, rr.getDid());
		assertEquals(DIDBiography.Status.VALID, rr.getStatus());
		assertEquals(3, rr.getTransactionCount());
		List<DIDTransaction> txs = rr.getAllTransactions();
		assertNotNull(txs);
		assertEquals(3, txs.size());

		for (int i = 0; i < txs.size(); i++) {
			DIDTransaction tx = txs.get(i);
			assertEquals(did, tx.getDid());
			assertEquals(sigs[i], tx.getRequest().getDocument().getProof().getSignature());
		}
	}

	@Test
	public void testUpdateAndResolveAsync() throws DIDException {
		String[] sigs = new String[3];

		// Create new DID and publish to ID sidechain.
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		DID did = doc.getSubject();

        log.debug("Publishing new DID {}...", did);
		long s1 = System.currentTimeMillis();
		CompletableFuture<Void> tf = doc.publishAsync(TestConfig.storePass)
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - s1 + 500) / 1000;
			        log.debug("Publish new DID {}...OK({}s)", did, duration);
				});
		tf.join();

		sigs[2] = doc.getProof().getSignature();

		testData.waitForWalletAvaliable();
		CompletableFuture<DIDDocument> rf = did.resolveAsync(true);
		DIDDocument resolved = rf.join();
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		String lastTxid = resolved.getMetadata().getTransactionId();
        log.debug("Last transaction id {}", lastTxid);

		// Update
		DIDDocument.Builder db = doc.edit();
		HDKey key = TestData.generateKeypair();
		db.addAuthenticationKey("key1", key.getPublicKeyBase58());
		doc = db.seal(TestConfig.storePass);
		assertEquals(2, doc.getPublicKeyCount());
		assertEquals(2, doc.getAuthenticationKeyCount());
		store.storeDid(doc);

        log.debug("Updating DID {}...", did);
		long s2 = System.currentTimeMillis();
		tf = doc.publishAsync(TestConfig.storePass)
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - s2 + 500) / 1000;
			        log.debug("Update DID {}...OK({}s)", did, duration);
				});
		tf.join();

		sigs[1] = doc.getProof().getSignature();

		testData.waitForWalletAvaliable();
		rf = did.resolveAsync(true);
		resolved = rf.join();
		assertNotEquals(lastTxid, resolved.getMetadata().getTransactionId());
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		lastTxid = resolved.getMetadata().getTransactionId();
        log.debug("Last transaction id {}", lastTxid);

		// Update again
		db = doc.edit();
		key = TestData.generateKeypair();
		db.addAuthenticationKey("key2", key.getPublicKeyBase58());
		doc = db.seal(TestConfig.storePass);
		assertEquals(3, doc.getPublicKeyCount());
		assertEquals(3, doc.getAuthenticationKeyCount());
		store.storeDid(doc);

        log.debug("Updating DID {}...", did);
		long s3 = System.currentTimeMillis();
		tf = doc.publishAsync(TestConfig.storePass)
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - s3 + 500) / 1000;
			        log.debug("Update DID {}...OK({}s)", did, duration);
				});
		tf.join();

		sigs[0] = doc.getProof().getSignature();

		testData.waitForWalletAvaliable();
		rf = did.resolveAsync(true);
		resolved = rf.join();
		assertNotEquals(lastTxid, resolved.getMetadata().getTransactionId());
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		lastTxid = resolved.getMetadata().getTransactionId();
        log.debug("Last transaction id {}", lastTxid);

		CompletableFuture<DIDBiography> rhf = did.resolveBiographyAsync();
		DIDBiography rr = rhf.join();
		assertNotNull(rr);
		assertEquals(did, rr.getDid());
		assertEquals(DIDBiography.Status.VALID, rr.getStatus());
		assertEquals(3, rr.getTransactionCount());
		List<DIDTransaction> txs = rr.getAllTransactions();
		assertNotNull(txs);
		assertEquals(3, txs.size());

		for (int i = 0; i < txs.size(); i++) {
			DIDTransaction tx = txs.get(i);
			assertEquals(did, tx.getDid());
			assertEquals(sigs[i], tx.getRequest().getDocument().getProof().getSignature());
		}
	}

	@Test
	public void testUpdateAndResolveWithCredentials() throws DIDException {
		// Create new DID and publish to ID sidechain.
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		DID did = doc.getSubject();

		Issuer selfIssuer = new Issuer(doc);
		VerifiableCredential.Builder cb = selfIssuer.issueFor(did);

		Map<String, Object> props= new HashMap<String, Object>();
		props.put("name", "John");
		props.put("gender", "Male");
		props.put("nation", "Singapore");
		props.put("language", "English");
		props.put("email", "john@example.com");
		props.put("twitter", "@john");

		VerifiableCredential vc = cb.id("profile")
				.type("BasicProfileCredential", "SelfProclaimedCredential")
				.properties(props)
				.seal(TestConfig.storePass);
		assertNotNull(vc);

		DIDDocument.Builder db = doc.edit();
		db.addCredential(vc);
		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertEquals(1, doc.getCredentialCount());
		store.storeDid(doc);

        log.debug("Publishing new DID {}...", did);
		long start = System.currentTimeMillis();
		doc.publish(TestConfig.storePass);
		long duration = (System.currentTimeMillis() - start + 500) / 1000;
        log.debug("Publish new DID {}...OK({}s)", did, duration);

		testData.waitForWalletAvaliable();
		DIDDocument resolved = did.resolve(true);
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		String lastTxid = resolved.getMetadata().getTransactionId();
        log.debug("Last transaction id {}", lastTxid);

		// Update
		selfIssuer = new Issuer(doc);
		cb = selfIssuer.issueFor(did);

		props.clear();
		props.put("nation", "Singapore");
		props.put("passport", "S653258Z07");

		vc = cb.id("passport")
				.type("BasicProfileCredential", "SelfProclaimedCredential")
				.properties(props)
				.seal(TestConfig.storePass);
		assertNotNull(vc);

		db = doc.edit();
		db.addCredential(vc);
		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertEquals(2, doc.getCredentialCount());
		store.storeDid(doc);

        log.debug("Updating DID {}...", did);
		start = System.currentTimeMillis();
		doc.publish(TestConfig.storePass);
		duration = (System.currentTimeMillis() - start + 500) / 1000;
        log.debug("Update DID {}...OK({}s)", did, duration);

		testData.waitForWalletAvaliable();
		resolved = did.resolve(true);
		assertNotEquals(lastTxid, resolved.getMetadata().getTransactionId());
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		// Update again
		selfIssuer = new Issuer(doc);
		cb = selfIssuer.issueFor(did);

		props.clear();
		props.put("Abc", "Abc");
		props.put("abc", "abc");
		props.put("Foobar", "Foobar");
		props.put("foobar", "foobar");
		props.put("zoo", "zoo");
		props.put("Zoo", "Zoo");

		vc = cb.id("test")
				.type("TestCredential", "SelfProclaimedCredential")
				.properties(props)
				.seal(TestConfig.storePass);
		assertNotNull(vc);

		db = doc.edit();
		db.addCredential(vc);
		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertEquals(3, doc.getCredentialCount());
		store.storeDid(doc);

		log.debug("Updating DID {}...", did);
		start = System.currentTimeMillis();
		doc.publish(TestConfig.storePass);
		duration = (System.currentTimeMillis() - start + 500) / 1000;
        log.debug("Update DID {}...OK({}s)", did, duration);

		testData.waitForWalletAvaliable();
		resolved = did.resolve(true);
		assertNotEquals(lastTxid, resolved.getMetadata().getTransactionId());
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);
	}

	@Test
	public void testUpdateAndResolveWithCredentialsAsync() throws DIDException {
		// Create new DID and publish to ID sidechain.
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		DID did = doc.getSubject();

		Issuer selfIssuer = new Issuer(doc);
		VerifiableCredential.Builder cb = selfIssuer.issueFor(did);

		Map<String, Object> props= new HashMap<String, Object>();
		props.put("name", "John");
		props.put("gender", "Male");
		props.put("nation", "Singapore");
		props.put("language", "English");
		props.put("email", "john@example.com");
		props.put("twitter", "@john");

		VerifiableCredential vc = cb.id("profile")
				.type("BasicProfileCredential", "SelfProclaimedCredential")
				.properties(props)
				.seal(TestConfig.storePass);
		assertNotNull(vc);

		DIDDocument.Builder db = doc.edit();
		db.addCredential(vc);
		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertEquals(1, doc.getCredentialCount());
		store.storeDid(doc);

        log.debug("Publishing new DID {}...", did);
		long s1 = System.currentTimeMillis();
		CompletableFuture<Void> tf = doc.publishAsync(TestConfig.storePass)
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - s1 + 500) / 1000;
			        log.debug("Publish new DID {}...OK({}s)", did, duration);
				});
		tf.join();

		testData.waitForWalletAvaliable();
		CompletableFuture<DIDDocument> rf = did.resolveAsync(true);
		DIDDocument resolved = rf.join();
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		String lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		// Update
		selfIssuer = new Issuer(doc);
		cb = selfIssuer.issueFor(did);

		props.clear();
		props.put("nation", "Singapore");
		props.put("passport", "S653258Z07");

		vc = cb.id("passport")
				.type("BasicProfileCredential", "SelfProclaimedCredential")
				.properties(props)
				.seal(TestConfig.storePass);
		assertNotNull(vc);

		db = doc.edit();
		db.addCredential(vc);
		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertEquals(2, doc.getCredentialCount());
		store.storeDid(doc);

        log.debug("Updating DID {}...", did);
		long s2 = System.currentTimeMillis();
		tf = doc.publishAsync(TestConfig.storePass)
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - s2 + 500) / 1000;
			        log.debug("Update DID {}...OK({}s)", did, duration);
				});
		tf.join();

		testData.waitForWalletAvaliable();
		rf = did.resolveAsync(true);
		resolved = rf.join();
		assertNotEquals(lastTxid, resolved.getMetadata().getTransactionId());
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		// Update again
		selfIssuer = new Issuer(doc);
		cb = selfIssuer.issueFor(did);

		props.clear();
		props.put("Abc", "Abc");
		props.put("abc", "abc");
		props.put("Foobar", "Foobar");
		props.put("foobar", "foobar");
		props.put("zoo", "zoo");
		props.put("Zoo", "Zoo");

		vc = cb.id("test")
				.type("TestCredential", "SelfProclaimedCredential")
				.properties(props)
				.seal(TestConfig.storePass);
		assertNotNull(vc);

		db = doc.edit();
		db.addCredential(vc);
		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertEquals(3, doc.getCredentialCount());
		store.storeDid(doc);

        log.debug("Updating DID {}...", did);
		long s3 = System.currentTimeMillis();
		tf = doc.publishAsync(TestConfig.storePass)
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - s3 + 500) / 1000;
			        log.debug("Update DID {}...OK({}s)", did, duration);
				});
		tf.join();

		testData.waitForWalletAvaliable();
		rf = did.resolveAsync(true);
		resolved = rf.join();
		assertNotEquals(lastTxid, resolved.getMetadata().getTransactionId());
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);
	}

	@Test
	@DisabledIfSystemProperty(named = "org.elastos.did.network", matches = "SimNet")
	public void testRestore() throws DIDException, IOException {
		String mnemonic = testData.loadRestoreMnemonic();

		RootIdentity rootIdentity = RootIdentity.create(Mnemonic.ENGLISH, mnemonic,
				TestConfig.passphrase, true, store, TestConfig.storePass);

		log.debug("Synchronizing from IDChain...");
		long start = System.currentTimeMillis();
		rootIdentity.synchronize();
		long duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Synchronize from IDChain...OK({}s)", duration);

		List<DID> dids = store.listDids();
		assertEquals(5, dids.size());

		ArrayList<String> didStrings = new ArrayList<String>(dids.size());
		for (DID id : dids)
			didStrings.add(id.toString());

		BufferedReader input = new BufferedReader(new InputStreamReader(
				getClass().getClassLoader().getResourceAsStream("testdata/dids.restore")));

		String didstr;
		while ((didstr = input.readLine()) != null) {
			assertTrue(didStrings.contains(didstr));

			DID did = new DID(didstr);
			DIDDocument doc = store.loadDid(did);
			assertNotNull(doc);
			assertEquals(did, doc.getSubject());
			assertEquals(4, doc.getCredentialCount());

			List<DIDURL> vcs = store.listCredentials(did);
			assertEquals(4, vcs.size());

			for (DIDURL id : vcs) {
				VerifiableCredential vc = store.loadCredential(id);
				assertNotNull(vc);
				assertEquals(id, vc.getId());
			}
		}

		input.close();
	}

	@Test
	@DisabledIfSystemProperty(named = "org.elastos.did.network", matches = "SimNet")
	public void testRestoreAsync() throws DIDException, IOException {
		String mnemonic = testData.loadRestoreMnemonic();

		RootIdentity rootIdentity = RootIdentity.create(Mnemonic.ENGLISH, mnemonic,
				TestConfig.passphrase, true, store, TestConfig.storePass);

		log.debug("Synchronizing from IDChain...");
		long start = System.currentTimeMillis();
		CompletableFuture<Void> f = rootIdentity.synchronizeAsync()
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - start + 500) / 1000;
					log.debug("Synchronize from IDChain...OK({}s)", duration);
				});

		f.join();

		List<DID> dids = store.listDids();
		assertEquals(5, dids.size());

		ArrayList<String> didStrings = new ArrayList<String>(dids.size());
		for (DID id : dids)
			didStrings.add(id.toString());

		BufferedReader input = new BufferedReader(new InputStreamReader(
				getClass().getClassLoader().getResourceAsStream("testdata/dids.restore")));

		String didstr;
		while ((didstr = input.readLine()) != null) {
			assertTrue(didStrings.contains(didstr));

			DID did = new DID(didstr);
			DIDDocument doc = store.loadDid(did);
			assertNotNull(doc);
			assertEquals(did, doc.getSubject());
			assertEquals(4, doc.getCredentialCount());

			List<DIDURL> vcs = store.listCredentials(did);
			assertEquals(4, vcs.size());

			for (DIDURL id : vcs) {
				VerifiableCredential vc = store.loadCredential(id);
				assertNotNull(vc);
				assertEquals(id, vc.getId());
			}
		}

		input.close();
	}

	@Test
	@DisabledIfSystemProperty(named = "org.elastos.did.network", matches = "SimNet")
	public void testSyncWithLocalModification1() throws DIDException, IOException {
		String mnemonic = testData.loadRestoreMnemonic();

		RootIdentity rootIdentity = RootIdentity.create(Mnemonic.ENGLISH, mnemonic,
				TestConfig.passphrase, true, store, TestConfig.storePass);

		log.debug("Synchronizing from IDChain...");
		long start = System.currentTimeMillis();
		rootIdentity.synchronize();
		long duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Synchronize from IDChain...OK({}s)", duration);

		List<DID> dids = store.listDids();
		assertEquals(5, dids.size());

		ArrayList<String> didStrings = new ArrayList<String>(dids.size());
		for (DID id : dids)
			didStrings.add(id.toString());

		BufferedReader input = new BufferedReader(new InputStreamReader(
				getClass().getClassLoader().getResourceAsStream("testdata/dids.restore")));

		String didstr;
		while ((didstr = input.readLine()) != null) {
			assertTrue(didStrings.contains(didstr));

			DID did = new DID(didstr);
			DIDDocument d = store.loadDid(did);
			assertNotNull(d);
			assertEquals(did, d.getSubject());
			assertEquals(4, d.getCredentialCount());

			List<DIDURL> vcs = store.listCredentials(did);
			assertEquals(4, vcs.size());

			for (DIDURL id : vcs) {
				VerifiableCredential vc = store.loadCredential(id);
				assertNotNull(vc);
				assertEquals(id, vc.getId());
			}
		}

		input.close();

		DID modifiedDid = dids.get(0);
		DIDDocument doc = store.loadDid(modifiedDid);
		DIDDocument.Builder db = doc.edit();
		db.addService("test1", "TestType", "http://test.com/");
		doc = db.seal(TestConfig.storePass);
		store.storeDid(doc);
		String modifiedSignature = doc.getProof().getSignature();

		log.debug("Synchronizing again from IDChain...");
		start = System.currentTimeMillis();
		rootIdentity.synchronize();
		duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Synchronize again from IDChain...OK({}s)", duration);

		dids = store.listDids();
		assertEquals(5, dids.size());

		didStrings = new ArrayList<String>(dids.size());
		for (DID id : dids)
			didStrings.add(id.toString());

		input = new BufferedReader(new InputStreamReader(
				getClass().getClassLoader().getResourceAsStream("testdata/dids.restore")));

		while ((didstr = input.readLine()) != null) {
			assertTrue(didStrings.contains(didstr));

			DID did = new DID(didstr);
			DIDDocument d = store.loadDid(did);
			assertNotNull(d);
			assertEquals(did, d.getSubject());
			assertEquals(4, d.getCredentialCount());

			List<DIDURL> vcs = store.listCredentials(did);
			assertEquals(4, vcs.size());

			for (DIDURL id : vcs) {
				VerifiableCredential vc = store.loadCredential(id);
				assertNotNull(vc);
				assertEquals(id, vc.getId());
			}
		}

		input.close();

		doc = store.loadDid(modifiedDid);
		assertEquals(modifiedSignature, doc.getProof().getSignature());
	}

	@Test
	@DisabledIfSystemProperty(named = "org.elastos.did.network", matches = "SimNet")
	public void testSyncWithLocalModification2() throws DIDException, IOException {
		String mnemonic = testData.loadRestoreMnemonic();

		RootIdentity rootIdentity = RootIdentity.create(Mnemonic.ENGLISH, mnemonic,
				TestConfig.passphrase, true, store, TestConfig.storePass);

		log.debug("Synchronizing from IDChain...");
		long start = System.currentTimeMillis();
		rootIdentity.synchronize();
		long duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Synchronize from IDChain...OK({}s)", duration);

		List<DID> dids = store.listDids();
		assertEquals(5, dids.size());

		ArrayList<String> didStrings = new ArrayList<String>(dids.size());
		for (DID id : dids)
			didStrings.add(id.toString());

		BufferedReader input = new BufferedReader(new InputStreamReader(
				getClass().getClassLoader().getResourceAsStream("testdata/dids.restore")));

		String didstr;
		while ((didstr = input.readLine()) != null) {
			assertTrue(didStrings.contains(didstr));

			DID did = new DID(didstr);
			DIDDocument d = store.loadDid(did);
			assertNotNull(d);
			assertEquals(did, d.getSubject());
			assertEquals(4, d.getCredentialCount());

			List<DIDURL> vcs = store.listCredentials(did);
			assertEquals(4, vcs.size());

			for (DIDURL id : vcs) {
				VerifiableCredential vc = store.loadCredential(id);
				assertNotNull(vc);
				assertEquals(id, vc.getId());
			}
		}

		input.close();

		DID modifiedDid = dids.get(0);
		DIDDocument doc = store.loadDid(modifiedDid);
		String originSignature = doc.getProof().getSignature();

		DIDDocument.Builder db = doc.edit();
		db.addService("test1", "TestType", "http://test.com/");
		doc = db.seal(TestConfig.storePass);
		store.storeDid(doc);
		assertNotEquals(originSignature, doc.getProof().getSignature());

		log.debug("Synchronizing again from IDChain...");
		start = System.currentTimeMillis();
		rootIdentity.synchronize((c, l) -> c);
		duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Synchronize again from IDChain...OK({}s)", duration);

		dids = store.listDids();
		assertEquals(5, dids.size());

		didStrings = new ArrayList<String>(dids.size());
		for (DID id : dids)
			didStrings.add(id.toString());

		input = new BufferedReader(new InputStreamReader(
				getClass().getClassLoader().getResourceAsStream("testdata/dids.restore")));

		while ((didstr = input.readLine()) != null) {
			assertTrue(didStrings.contains(didstr));

			DID did = new DID(didstr);
			DIDDocument d = store.loadDid(did);
			assertNotNull(d);
			assertEquals(did, d.getSubject());
			assertEquals(4, d.getCredentialCount());

			List<DIDURL> vcs = store.listCredentials(did);
			assertEquals(4, vcs.size());

			for (DIDURL id : vcs) {
				VerifiableCredential vc = store.loadCredential(id);
				assertNotNull(vc);
				assertEquals(id, vc.getId());
			}
		}

		input.close();

		doc = store.loadDid(modifiedDid);
		assertEquals(originSignature, doc.getProof().getSignature());
	}

	@Test
	@DisabledIfSystemProperty(named = "org.elastos.did.network", matches = "SimNet")
	public void testSyncWithLocalModificationAsync() throws DIDException, IOException {
		String mnemonic = testData.loadRestoreMnemonic();

		RootIdentity rootIdentity = RootIdentity.create(Mnemonic.ENGLISH, mnemonic,
				TestConfig.passphrase, true, store, TestConfig.storePass);

		log.debug("Synchronizing from IDChain...");
		long s1 = System.currentTimeMillis();
		CompletableFuture<Void> f = rootIdentity.synchronizeAsync()
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - s1 + 500) / 1000;
					log.debug("Synchronize from IDChain...OK({}s)", duration);
				});

		f.join();

		List<DID> dids = store.listDids();
		assertEquals(5, dids.size());

		ArrayList<String> didStrings = new ArrayList<String>(dids.size());
		for (DID id : dids)
			didStrings.add(id.toString());

		BufferedReader input = new BufferedReader(new InputStreamReader(
				getClass().getClassLoader().getResourceAsStream("testdata/dids.restore")));

		String didstr;
		while ((didstr = input.readLine()) != null) {
			assertTrue(didStrings.contains(didstr));

			DID did = new DID(didstr);
			DIDDocument d = store.loadDid(did);
			assertNotNull(d);
			assertEquals(did, d.getSubject());
			assertEquals(4, d.getCredentialCount());

			List<DIDURL> vcs = store.listCredentials(did);
			assertEquals(4, vcs.size());

			for (DIDURL id : vcs) {
				VerifiableCredential vc = store.loadCredential(id);
				assertNotNull(vc);
				assertEquals(id, vc.getId());
			}
		}

		input.close();

		DID modifiedDid = dids.get(0);
		DIDDocument doc = store.loadDid(modifiedDid);
		String originSignature = doc.getProof().getSignature();

		DIDDocument.Builder db = doc.edit();
		db.addService("test1", "TestType", "http://test.com/");
		doc = db.seal(TestConfig.storePass);
		store.storeDid(doc);
		assertNotEquals(originSignature, doc.getProof().getSignature());

		log.debug("Synchronizing again from IDChain...");
		long s2 = System.currentTimeMillis();
		f = rootIdentity.synchronizeAsync((c, l) -> c)
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - s2 + 500) / 1000;
					log.debug("Synchronize again from IDChain...OK({}s)", duration);
				});

		f.join();

		dids = store.listDids();
		assertEquals(5, dids.size());

		didStrings = new ArrayList<String>(dids.size());
		for (DID id : dids)
			didStrings.add(id.toString());

		input = new BufferedReader(new InputStreamReader(
				getClass().getClassLoader().getResourceAsStream("testdata/dids.restore")));

		while ((didstr = input.readLine()) != null) {
			assertTrue(didStrings.contains(didstr));

			DID did = new DID(didstr);
			DIDDocument d = store.loadDid(did);
			assertNotNull(d);
			assertEquals(did, d.getSubject());
			assertEquals(4, d.getCredentialCount());

			List<DIDURL> vcs = store.listCredentials(did);
			assertEquals(4, vcs.size());

			for (DIDURL id : vcs) {
				VerifiableCredential vc = store.loadCredential(id);
				assertNotNull(vc);
				assertEquals(id, vc.getId());
			}
		}

		input.close();

		doc = store.loadDid(modifiedDid);
		assertEquals(originSignature, doc.getProof().getSignature());
	}
}
