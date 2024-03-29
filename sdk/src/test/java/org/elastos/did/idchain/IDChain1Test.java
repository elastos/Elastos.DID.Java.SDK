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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.stream.Collectors;

import org.elastos.did.DID;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.DIDStore.ConflictHandle;
import org.elastos.did.Issuer;
import org.elastos.did.RootIdentity;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.backend.DIDBiography;
import org.elastos.did.backend.DIDTransaction;
import org.elastos.did.backend.IDChainRequest;
import org.elastos.did.crypto.HDKey;
import org.elastos.did.exception.DIDException;
import org.elastos.did.utils.DIDTestExtension;
import org.elastos.did.utils.TestConfig;
import org.elastos.did.utils.TestData;
import org.elastos.did.utils.Utils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
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
public class IDChain1Test {
	private static TestData testData;
	private static List<DID> dids;

	private DIDStore store;
	private String mnemonic;
	private RootIdentity identity;

	private static final Logger log = LoggerFactory.getLogger(IDChain1Test.class);

	@BeforeAll
	public static void beforeAll() throws DIDException {
		testData = new TestData();
		testData.getRootIdentity();
		dids = new ArrayList<DID>();
	}

	@AfterAll
	public static void afterEach() {
		testData.cleanup();
	}

	@BeforeEach
	public void beforeEach() throws DIDException {
		store = testData.getStore();
		mnemonic = testData.getMnemonic();
		identity = testData.getRootIdentity();

		TestData.waitForWalletAvaliable();
	}

	@Test
	@Order(1)
	public void testCreateAndResolve() throws DIDException {
		// Create new DID and publish to ID sidechain.
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		DID did = doc.getSubject();

		log.debug("Publishing new DID {}...", did);
		long start = System.currentTimeMillis();
		doc.publish(TestConfig.storePass);
		long duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Publish new DID {}...OK({}s)", did, duration);

		TestData.waitForWalletAvaliable();
		DIDDocument resolved = did.resolve();
		assertNotNull(resolved);
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		DIDBiography bio = did.resolveBiography();
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(resolved.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		dids.add(did); // 0
	}

	@Test
	@Order(2)
	public void testCreateAndResolveAsync() throws DIDException {
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

		TestData.waitForWalletAvaliable();
		CompletableFuture<DIDDocument> rf = did.resolveAsync(true);
		DIDDocument resolved = rf.join();
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		DIDBiography bio = did.resolveBiography();
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(resolved.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		dids.add(did); // 1
	}

	@Test
	@Order(3)
	public void testCreateAndResolveAsync2() throws DIDException {
		// Create new DID and publish to ID sidechain.
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		DID did = doc.getSubject();

		log.debug("Publishing new DID and resolve {}...", did);
		long start = System.currentTimeMillis();
		CompletableFuture<DIDDocument> tf = doc.publishAsync(TestConfig.storePass)
				.thenCompose((Void) -> {
					try {
						TestData.waitForWalletAvaliable();
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

		DIDBiography bio = did.resolveBiography();
		assertNotNull(bio);
		assertEquals(1, bio.size());
		assertEquals(resolved.getSignature(), bio.getTransaction(0).getRequest().getDocument().getSignature());

		dids.add(did); // 2
	}

	@Test
	@Order(4)
	public void testUpdateAndResolve() throws DIDException {
		// User the DID that created in previous case(1)
		DIDDocument doc = store.loadDid(dids.get(0));
		assertNotNull(doc);
		DID did = doc.getSubject();

		DIDDocument resolved = did.resolve();
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.getProof().getSignature(), resolved.getProof().getSignature());
		String lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		// Update
		DIDDocument.Builder db = doc.edit();
		HDKey key = TestData.generateKeypair();
		db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
		doc = db.seal(TestConfig.storePass);
		assertEquals(2, doc.getPublicKeyCount());
		assertEquals(2, doc.getAuthenticationKeyCount());
		store.storeDid(doc);

		log.debug("Updating DID {}...", did);
		long start = System.currentTimeMillis();
		doc.publish(TestConfig.storePass);
		long duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Update DID {}...OK({}s)", did, duration);

		TestData.waitForWalletAvaliable();
		resolved = did.resolve();
		assertNotEquals(lastTxid, resolved.getMetadata().getTransactionId());
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		DIDBiography bio = did.resolveBiography();
		assertNotNull(bio);
		assertEquals(did, bio.getDid());
		assertEquals(DIDBiography.Status.VALID, bio.getStatus());
		assertEquals(2, bio.size());
		List<DIDTransaction> txs = bio.getAllTransactions();
		assertNotNull(txs);
		assertEquals(2, txs.size());

		DIDTransaction tx = txs.get(0);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.UPDATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());

		tx = txs.get(1);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.CREATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());
	}

	@Test
	@Order(5)
	public void testUpdateAndResolveAgain() throws DIDException {
		// User the DID that created in previous case(1)
		DIDDocument doc = store.loadDid(dids.get(0));
		assertNotNull(doc);
		DID did = doc.getSubject();

		DIDDocument resolved = did.resolve();
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.getProof().getSignature(), resolved.getProof().getSignature());
		String lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		// Update again
		DIDDocument.Builder db = doc.edit();
		HDKey key = TestData.generateKeypair();
		db.addAuthenticationKey("#key2", key.getPublicKeyBase58());
		doc = db.seal(TestConfig.storePass);
		assertEquals(3, doc.getPublicKeyCount());
		assertEquals(3, doc.getAuthenticationKeyCount());
		store.storeDid(doc);

		log.debug("Updating DID {}...", did);
		long start = System.currentTimeMillis();
		doc.publish(TestConfig.storePass);
		long duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Update DID {}...OK({}s)", did, duration);

		TestData.waitForWalletAvaliable();
		resolved = did.resolve();
		assertNotEquals(lastTxid, resolved.getMetadata().getTransactionId());
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		DIDBiography bio = did.resolveBiography();
		assertNotNull(bio);
		assertEquals(did, bio.getDid());
		assertEquals(DIDBiography.Status.VALID, bio.getStatus());
		assertEquals(3, bio.size());
		List<DIDTransaction> txs = bio.getAllTransactions();
		assertNotNull(txs);
		assertEquals(3, txs.size());

		DIDTransaction tx = txs.get(0);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.UPDATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());

		tx = txs.get(1);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.UPDATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());

		tx = txs.get(2);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.CREATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());
	}

	@Test
	@Order(6)
	public void testUpdateAndResolveAsync() throws DIDException {
		// User the DID that created in previous case(2)
		DIDDocument doc = store.loadDid(dids.get(1));
		assertNotNull(doc);
		DID did = doc.getSubject();

		CompletableFuture<DIDDocument> rf = did.resolveAsync(true);
		DIDDocument resolved = rf.join();
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.getProof().getSignature(), resolved.getProof().getSignature());
		String lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		// Update
		DIDDocument.Builder db = doc.edit();
		HDKey key = TestData.generateKeypair();
		db.addAuthenticationKey("#key1", key.getPublicKeyBase58());
		doc = db.seal(TestConfig.storePass);
		assertEquals(2, doc.getPublicKeyCount());
		assertEquals(2, doc.getAuthenticationKeyCount());
		store.storeDid(doc);

		log.debug("Updating DID {}...", did);
		long start = System.currentTimeMillis();
		CompletableFuture<Void> tf = doc.publishAsync(TestConfig.storePass)
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - start + 500) / 1000;
					log.debug("Update DID {}...OK({}s)", did, duration);
				});
		tf.join();

		TestData.waitForWalletAvaliable();
		rf = did.resolveAsync(true);
		resolved = rf.join();
		assertNotEquals(lastTxid, resolved.getMetadata().getTransactionId());
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));
		lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		DIDBiography bio = did.resolveBiographyAsync().join();
		assertNotNull(bio);
		assertEquals(did, bio.getDid());
		assertEquals(DIDBiography.Status.VALID, bio.getStatus());
		assertEquals(2, bio.size());
		List<DIDTransaction> txs = bio.getAllTransactions();
		assertNotNull(txs);
		assertEquals(2, txs.size());

		DIDTransaction tx = txs.get(0);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.UPDATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());

		tx = txs.get(1);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.CREATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());
	}

	@Test
	@Order(7)
	public void testUpdateAndResolveAsyncAgain() throws DIDException {
		// User the DID that created in previous case(2)
		DIDDocument doc = store.loadDid(dids.get(1));
		assertNotNull(doc);
		DID did = doc.getSubject();

		CompletableFuture<DIDDocument> rf = did.resolveAsync(true);
		DIDDocument resolved = rf.join();
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.getProof().getSignature(), resolved.getProof().getSignature());
		String lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		// Update again
		DIDDocument.Builder db = doc.edit();
		HDKey key = TestData.generateKeypair();
		db.addAuthenticationKey("#key2", key.getPublicKeyBase58());
		doc = db.seal(TestConfig.storePass);
		assertEquals(3, doc.getPublicKeyCount());
		assertEquals(3, doc.getAuthenticationKeyCount());
		store.storeDid(doc);

		log.debug("Updating DID {}...", did);
		long start = System.currentTimeMillis();
		CompletableFuture<Void> tf = doc.publishAsync(TestConfig.storePass)
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - start + 500) / 1000;
					log.debug("Update DID {}...OK({}s)", did, duration);
				});
		tf.join();

		TestData.waitForWalletAvaliable();
		rf = did.resolveAsync(true);
		resolved = rf.join();
		assertNotEquals(lastTxid, resolved.getMetadata().getTransactionId());
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		DIDBiography bio = did.resolveBiography();
		assertNotNull(bio);
		assertEquals(did, bio.getDid());
		assertEquals(DIDBiography.Status.VALID, bio.getStatus());
		assertEquals(3, bio.size());
		List<DIDTransaction> txs = bio.getAllTransactions();
		assertNotNull(txs);
		assertEquals(3, txs.size());

		DIDTransaction tx = txs.get(0);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.UPDATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());

		tx = txs.get(1);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.UPDATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());

		tx = txs.get(2);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.CREATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());
	}

	@Test
	@Order(8)
	public void testCreateAndResolveWithCredentials() throws DIDException {
		// Create new DID and publish to ID sidechain.
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		DID did = doc.getSubject();

		Issuer selfIssuer = new Issuer(doc);
		VerifiableCredential.Builder cb = selfIssuer.issueFor(did);

		Map<String, Object> props= new HashMap<String, Object>();
		props.put("name", "John");
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", "john@example.com");
		props.put("twitter", "@john");

		VerifiableCredential vc = cb.id("#profile")
				.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
				.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
				.type("EmailCredential", "https://ns.elastos.org/credentials/email/v1")
				.type("SocialCredential", "https://ns.elastos.org/credentials/social/v1")
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

		TestData.waitForWalletAvaliable();
		DIDDocument resolved = did.resolve();
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		String lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		dids.add(did); // 3
	}

	@Test
	@Order(9)
	public void testUpdateAndResolveWithCredentials() throws DIDException {
		// User the DID that created in previous case(8)
		DIDDocument doc = store.loadDid(dids.get(3));
		assertNotNull(doc);
		DID did = doc.getSubject();

		DIDDocument resolved = did.resolve();
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.getProof().getSignature(), resolved.getProof().getSignature());
		String lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		Issuer selfIssuer = new Issuer(doc);
		VerifiableCredential.Builder cb = selfIssuer.issueFor(did);

		Map<String, Object> props= new HashMap<String, Object>();
		props.put("nationality", "Singapore");
		props.put("passport", "S653258Z07");

		VerifiableCredential vc = cb.id("#passport")
				.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
				.properties(props)
				.seal(TestConfig.storePass);
		assertNotNull(vc);

		DIDDocument.Builder db = doc.edit();
		db.addCredential(vc);
		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertEquals(2, doc.getCredentialCount());
		store.storeDid(doc);

		log.debug("Updating DID {}...", did);
		long start = System.currentTimeMillis();
		doc.publish(TestConfig.storePass);
		long duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Update DID {}...OK({}s)", did, duration);

		TestData.waitForWalletAvaliable();
		resolved = did.resolve();
		assertNotEquals(lastTxid, resolved.getMetadata().getTransactionId());
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		DIDBiography bio = did.resolveBiography();
		assertNotNull(bio);
		assertEquals(did, bio.getDid());
		assertEquals(DIDBiography.Status.VALID, bio.getStatus());
		assertEquals(2, bio.size());
		List<DIDTransaction> txs = bio.getAllTransactions();
		assertNotNull(txs);
		assertEquals(2, txs.size());

		DIDTransaction tx = txs.get(0);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.UPDATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());

		tx = txs.get(1);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.CREATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());
	}

	@Test
	@Order(10)
	public void testUpdateAndResolveWithCredentialsAgain() throws DIDException {
		// User the DID that created in previous case(8)
		DIDDocument doc = store.loadDid(dids.get(3));
		assertNotNull(doc);
		DID did = doc.getSubject();

		DIDDocument resolved = did.resolve();
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.getProof().getSignature(), resolved.getProof().getSignature());
		String lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		// Update again
		Issuer selfIssuer = new Issuer(doc);
		VerifiableCredential.Builder cb = selfIssuer.issueFor(did);

		Map<String, Object> props= new HashMap<String, Object>();
		props.put("Abc", "Abc");
		props.put("abc", "abc");
		props.put("Foobar", "Foobar");
		props.put("foobar", "foobar");
		props.put("zoo", "zoo");
		props.put("Zoo", "Zoo");

		VerifiableCredential vc = cb.id("#test")
				.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
				.properties(props)
				.seal(TestConfig.storePass);
		assertNotNull(vc);

		DIDDocument.Builder db = doc.edit();
		db.addCredential(vc);
		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertEquals(3, doc.getCredentialCount());
		store.storeDid(doc);

		log.debug("Updating DID {}...", did);
		long start = System.currentTimeMillis();
		doc.publish(TestConfig.storePass);
		long duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Update DID {}...OK({}s)", did, duration);

		TestData.waitForWalletAvaliable();
		resolved = did.resolve();
		assertNotEquals(lastTxid, resolved.getMetadata().getTransactionId());
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		DIDBiography bio = did.resolveBiography();
		assertNotNull(bio);
		assertEquals(did, bio.getDid());
		assertEquals(DIDBiography.Status.VALID, bio.getStatus());
		assertEquals(3, bio.size());
		List<DIDTransaction> txs = bio.getAllTransactions();
		assertNotNull(txs);
		assertEquals(3, txs.size());

		DIDTransaction tx = txs.get(0);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.UPDATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());

		tx = txs.get(1);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.UPDATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());

		tx = txs.get(2);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.CREATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());
	}

	@Test
	@Order(11)
	public void testCreateAndResolveWithCredentialsAsync() throws DIDException {
		// Create new DID and publish to ID sidechain.
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		DID did = doc.getSubject();

		Issuer selfIssuer = new Issuer(doc);
		VerifiableCredential.Builder cb = selfIssuer.issueFor(did);

		Map<String, Object> props= new HashMap<String, Object>();
		props.put("name", "John");
		props.put("gender", "Male");
		props.put("nationality", "Singapore");
		props.put("email", "john@example.com");
		props.put("twitter", "@john");

		VerifiableCredential vc = cb.id("#profile")
				.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
				.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
				.type("EmailCredential", "https://ns.elastos.org/credentials/email/v1")
				.type("SocialCredential", "https://ns.elastos.org/credentials/social/v1")
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

		TestData.waitForWalletAvaliable();
		CompletableFuture<DIDDocument> rf = did.resolveAsync(true);
		DIDDocument resolved = rf.join();
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		String lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		dids.add(did); // 4
	}

	@Test
	@Order(12)
	public void testUpdateAndResolveWithCredentialsAsync() throws DIDException {
		// User the DID that created in previous case(11)
		DIDDocument doc = store.loadDid(dids.get(4));
		assertNotNull(doc);
		DID did = doc.getSubject();

		DIDDocument resolved = did.resolveAsync(true).join();
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.getProof().getSignature(), resolved.getProof().getSignature());
		String lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		// Update
		Issuer selfIssuer = new Issuer(doc);
		VerifiableCredential.Builder cb = selfIssuer.issueFor(did);

		Map<String, Object> props= new HashMap<String, Object>();
		props.put("nationality", "Singapore");
		props.put("passport", "S653258Z07");

		VerifiableCredential vc = cb.id("#passport")
				.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
				.properties(props)
				.seal(TestConfig.storePass);
		assertNotNull(vc);

		DIDDocument.Builder db = doc.edit();
		db.addCredential(vc);
		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertEquals(2, doc.getCredentialCount());
		store.storeDid(doc);

		log.debug("Updating DID {}...", did);
		long start = System.currentTimeMillis();
		CompletableFuture<Void> tf = doc.publishAsync(TestConfig.storePass)
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - start + 500) / 1000;
					log.debug("Update DID {}...OK({}s)", did, duration);
				});
		tf.join();

		TestData.waitForWalletAvaliable();
		CompletableFuture<DIDDocument> rf = did.resolveAsync(true);
		resolved = rf.join();
		assertNotEquals(lastTxid, resolved.getMetadata().getTransactionId());
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);
	}

	@Test
	@Order(13)
	public void testUpdateAndResolveWithCredentialsAsyncAgain() throws DIDException {
		// User the DID that created in previous case(11)
		DIDDocument doc = store.loadDid(dids.get(4));
		assertNotNull(doc);
		DID did = doc.getSubject();

		DIDDocument resolved = did.resolveAsync(true).join();
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.getProof().getSignature(), resolved.getProof().getSignature());
		String lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		// Update again
		Issuer selfIssuer = new Issuer(doc);
		VerifiableCredential.Builder cb = selfIssuer.issueFor(did);

		Map<String, Object> props= new HashMap<String, Object>();
		props.put("Abc", "Abc");
		props.put("abc", "abc");
		props.put("Foobar", "Foobar");
		props.put("foobar", "foobar");
		props.put("zoo", "zoo");
		props.put("Zoo", "Zoo");

		VerifiableCredential vc = cb.id("#test")
				.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
				.properties(props)
				.seal(TestConfig.storePass);
		assertNotNull(vc);

		DIDDocument.Builder db = doc.edit();
		db.addCredential(vc);
		doc = db.seal(TestConfig.storePass);
		assertNotNull(doc);
		assertEquals(3, doc.getCredentialCount());
		store.storeDid(doc);

		log.debug("Updating DID {}...", did);
		long start = System.currentTimeMillis();
		CompletableFuture<Void> tf = doc.publishAsync(TestConfig.storePass)
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - start + 500) / 1000;
					log.debug("Update DID {}...OK({}s)", did, duration);
				});
		tf.join();

		TestData.waitForWalletAvaliable();
		CompletableFuture<DIDDocument> rf = did.resolveAsync(true);
		resolved = rf.join();
		assertNotEquals(lastTxid, resolved.getMetadata().getTransactionId());
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);

		DIDBiography bio = did.resolveBiography();
		assertNotNull(bio);
		assertEquals(did, bio.getDid());
		assertEquals(DIDBiography.Status.VALID, bio.getStatus());
		assertEquals(3, bio.size());
		List<DIDTransaction> txs = bio.getAllTransactions();
		assertNotNull(txs);
		assertEquals(3, txs.size());

		DIDTransaction tx = txs.get(0);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.UPDATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());

		tx = txs.get(1);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.UPDATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());

		tx = txs.get(2);
		assertEquals(did, tx.getDid());
		assertEquals(IDChainRequest.Operation.CREATE, tx.getRequest().getOperation());
		assertTrue(tx.getRequest().isValid());
	}

	@Test
	@Order(100)
	public void testSyncRootIdentityClean() throws DIDException, IOException {
		File path = new File(TestConfig.tempDir + "/cleanstore").getCanonicalFile();
		Utils.deleteFile(path);

		DIDStore cleanStore = DIDStore.open(path);
		RootIdentity rootIdentity = RootIdentity.create(mnemonic,
				TestConfig.passphrase, true, cleanStore, TestConfig.storePass);

		log.debug("Synchronizing from IDChain...");
		long start = System.currentTimeMillis();
		rootIdentity.synchronize();
		long duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Synchronize from IDChain...OK({}s)", duration);

		List<DID> restoredDids = new ArrayList<DID>(cleanStore.listDids());
		assertEquals(5, restoredDids.size());
		Collections.sort(restoredDids);

		//create a credential for testing lazy private key
		DID did = restoredDids.get(0);
		Issuer issuer = new Issuer(did, cleanStore);

		Map<String, Object> props= new HashMap<String, Object>();
		props.put("name", "John");
		props.put("gender", "Male");

		VerifiableCredential.Builder cb = issuer.issueFor(did);
		VerifiableCredential vc = cb.id("#selfCredential")
			.type("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
			.properties(props)
			.seal(TestConfig.storePass);
		assertEquals("John", vc.getSubject().getProperty("name"));

		List<DID> originalDids = new ArrayList<DID>(dids);
		Collections.sort(originalDids);

		assertArrayEquals(originalDids.toArray(new DID[0]),
				restoredDids.toArray(new DID[0]));
	}

	@Test
	@Order(101)
	public void testSyncRootIdentityCleanAsync() throws DIDException, IOException {
		File path = new File(TestConfig.tempDir + "/cleanstore").getCanonicalFile();
		Utils.deleteFile(path);

		DIDStore cleanStore = DIDStore.open(path);
		RootIdentity rootIdentity = RootIdentity.create(mnemonic,
				TestConfig.passphrase, true, cleanStore, TestConfig.storePass);

		log.debug("Synchronizing from IDChain...");
		long start = System.currentTimeMillis();
		CompletableFuture<Void> f = rootIdentity.synchronizeAsync()
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - start + 500) / 1000;
					log.debug("Synchronize from IDChain...OK({}s)", duration);
				});

		f.join();

		List<DID> restoredDids = new ArrayList<DID>(cleanStore.listDids());
		assertEquals(5, restoredDids.size());
		Collections.sort(restoredDids);

		List<DID> originalDids = new ArrayList<DID>(dids);
		Collections.sort(originalDids);

		assertArrayEquals(originalDids.toArray(new DID[0]),
				restoredDids.toArray(new DID[0]));
	}

	@Test
	@Order(16)
	public void testSyncRootIdentityWithoutModification() throws DIDException, IOException {
		log.debug("Synchronizing from IDChain...");
		long start = System.currentTimeMillis();
		identity.synchronize((c, l) -> {
			assertEquals(l.getProof().getSignature(), c.getProof().getSignature());
			assertEquals(l.getLastModified(), c.getLastModified());

			l.getMetadata().update(c.getMetadata());
			return l;
		});

		long duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Synchronize from IDChain...OK({}s)", duration);

		List<DID> restoredDids = new ArrayList<DID>(store.listDids());
		assertEquals(5, restoredDids.size());
		Collections.sort(restoredDids);

		List<DID> originalDids = new ArrayList<DID>(dids);
		Collections.sort(originalDids);

		assertArrayEquals(originalDids.toArray(new DID[0]),
				restoredDids.toArray(new DID[0]));
	}

	@Test
	@Order(102)
	public void testSyncRootIdentityWithoutModificationAsync() throws DIDException, IOException {
		log.debug("Synchronizing from IDChain...");
		long start = System.currentTimeMillis();

		ConflictHandle ch = (c, l) -> {
			assertEquals(l.getProof().getSignature(), c.getProof().getSignature());
			assertEquals(l.getLastModified(), c.getLastModified());

			l.getMetadata().update(c.getMetadata());
			return l;
		};

		CompletableFuture<Void> f = identity.synchronizeAsync(ch)
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - start + 500) / 1000;
					log.debug("Synchronize from IDChain...OK({}s)", duration);
				});

		f.join();

		List<DID> restoredDids = new ArrayList<DID>(store.listDids());
		assertEquals(5, restoredDids.size());
		Collections.sort(restoredDids);

		List<DID> originalDids = new ArrayList<DID>(dids);
		Collections.sort(originalDids);

		assertArrayEquals(originalDids.toArray(new DID[0]),
				restoredDids.toArray(new DID[0]));
	}

	@Test
	@Order(103)
	public void testSyncRootIdentityWithLocalModification1() throws DIDException, IOException {
		// Sync to a clean store first
		File path = new File(TestConfig.tempDir + "/cleanstore").getCanonicalFile();
		Utils.deleteFile(path);

		DIDStore cleanStore = DIDStore.open(path);
		RootIdentity rootIdentity = RootIdentity.create(mnemonic,
				TestConfig.passphrase, true, cleanStore, TestConfig.storePass);

		log.debug("Synchronizing from IDChain...");
		long start = System.currentTimeMillis();
		rootIdentity.synchronize();
		long duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Synchronize from IDChain...OK({}s)", duration);

		List<DID> restoredDids = new ArrayList<DID>(cleanStore.listDids());
		assertEquals(5, restoredDids.size());
		Collections.sort(restoredDids);

		List<DID> originalDids = new ArrayList<DID>(dids);
		Collections.sort(originalDids);

		assertArrayEquals(originalDids.toArray(new DID[0]),
				restoredDids.toArray(new DID[0]));

		// Modify a DID document
		DID modifiedDid = dids.get(0);
		DIDDocument doc = cleanStore.loadDid(modifiedDid);
		DIDDocument.Builder db = doc.edit();
		db.addService("#test1", "TestType", "http://test.com/");
		doc = db.seal(TestConfig.storePass);
		cleanStore.storeDid(doc);
		String modifiedSignature = doc.getProof().getSignature();

		log.debug("Synchronizing again from IDChain...");
		start = System.currentTimeMillis();
		rootIdentity.synchronize();
		duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Synchronize again from IDChain...OK({}s)", duration);

		restoredDids = new ArrayList<DID>(cleanStore.listDids());
		assertEquals(5, restoredDids.size());
		Collections.sort(restoredDids);

		originalDids = new ArrayList<DID>(dids);
		Collections.sort(originalDids);

		assertArrayEquals(originalDids.toArray(new DID[0]),
				restoredDids.toArray(new DID[0]));

		// Should keep the local modified copy after sync
		doc = cleanStore.loadDid(modifiedDid);
		assertEquals(modifiedSignature, doc.getProof().getSignature());
	}

	@Test
	@Order(104)
	public void testSyncRootIdentityWithLocalModification2() throws DIDException, IOException {
		// Sync to a clean store first
		File path = new File(TestConfig.tempDir + "/cleanstore").getCanonicalFile();
		Utils.deleteFile(path);

		DIDStore cleanStore = DIDStore.open(path);
		RootIdentity rootIdentity = RootIdentity.create(mnemonic,
				TestConfig.passphrase, true, cleanStore, TestConfig.storePass);

		log.debug("Synchronizing from IDChain...");
		long start = System.currentTimeMillis();
		rootIdentity.synchronize();
		long duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Synchronize from IDChain...OK({}s)", duration);

		List<DID> restoredDids = new ArrayList<DID>(cleanStore.listDids());
		assertEquals(5, restoredDids.size());
		Collections.sort(restoredDids);

		List<DID> originalDids = new ArrayList<DID>(dids);
		Collections.sort(originalDids);

		assertArrayEquals(originalDids.toArray(new DID[0]),
				restoredDids.toArray(new DID[0]));

		// Modify a DID document
		DID modifiedDid = dids.get(0);
		DIDDocument doc = cleanStore.loadDid(modifiedDid);
		String originalSignature = doc.getSignature();

		DIDDocument.Builder db = doc.edit();
		db.addService("#Stest1", "TestType", "http://test.com/");
		doc = db.seal(TestConfig.storePass);
		cleanStore.storeDid(doc);

		log.debug("Synchronizing again from IDChain...");
		start = System.currentTimeMillis();
		rootIdentity.synchronize((c, l) -> c);
		duration = (System.currentTimeMillis() - start + 500) / 1000;
		log.debug("Synchronize again from IDChain...OK({}s)", duration);

		restoredDids = new ArrayList<DID>(cleanStore.listDids());
		assertEquals(5, restoredDids.size());
		Collections.sort(restoredDids);

		originalDids = new ArrayList<DID>(dids);
		Collections.sort(originalDids);

		assertArrayEquals(originalDids.toArray(new DID[0]),
				restoredDids.toArray(new DID[0]));

		// Should overwrite the local modified copy with chain copy after sync
		doc = cleanStore.loadDid(modifiedDid);
		assertEquals(originalSignature, doc.getSignature());
	}

	@Test
	@Order(105)
	public void testSyncRootIdentityWithLocalModificationAsync() throws DIDException, IOException {
		// Sync to a clean store first
		File path = new File(TestConfig.tempDir + "/cleanstore").getCanonicalFile();
		Utils.deleteFile(path);

		DIDStore cleanStore = DIDStore.open(path);
		RootIdentity rootIdentity = RootIdentity.create(mnemonic,
				TestConfig.passphrase, true, cleanStore, TestConfig.storePass);

		log.debug("Synchronizing from IDChain...");
		long start = System.currentTimeMillis();
		CompletableFuture<Void> f = rootIdentity.synchronizeAsync()
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - start + 500) / 1000;
					log.debug("Synchronize from IDChain...OK({}s)", duration);
				});

		f.join();

		List<DID> restoredDids = new ArrayList<DID>(cleanStore.listDids());
		assertEquals(5, restoredDids.size());
		Collections.sort(restoredDids);

		List<DID> originalDids = new ArrayList<DID>(dids);
		Collections.sort(originalDids);

		assertArrayEquals(originalDids.toArray(new DID[0]),
				restoredDids.toArray(new DID[0]));

		// Modify a DID document
		DID modifiedDid = dids.get(0);
		DIDDocument doc = cleanStore.loadDid(modifiedDid);
		String originalSignature = doc.getSignature();

		DIDDocument.Builder db = doc.edit();
		db.addService("#test1", "TestType", "http://test.com/");
		doc = db.seal(TestConfig.storePass);
		cleanStore.storeDid(doc);

		log.debug("Synchronizing again from IDChain...");
		long start2 = System.currentTimeMillis();
		f = rootIdentity.synchronizeAsync((c, l) -> c)
				.thenRun(() -> {
					long duration = (System.currentTimeMillis() - start2 + 500) / 1000;
					log.debug("Synchronize again from IDChain...OK({}s)", duration);
				});

		f.join();

		restoredDids = new ArrayList<DID>(cleanStore.listDids());
		assertEquals(5, restoredDids.size());
		Collections.sort(restoredDids);

		originalDids = new ArrayList<DID>(dids);
		Collections.sort(originalDids);

		assertArrayEquals(originalDids.toArray(new DID[0]),
				restoredDids.toArray(new DID[0]));

		// Should overwrite the local modified copy with chain copy after sync
		doc = cleanStore.loadDid(modifiedDid);
		assertEquals(originalSignature, doc.getSignature());
	}

	@Test
	@Order(106)
	// TODO: should improve after all DID2 features online
	public void testSynchronizeStore() throws DIDException {
		List<DID> dids = new ArrayList<DID>(store.listDids());
		Collections.sort(dids);
		for (DID did : dids) {
			boolean success = store.deleteDid(did);
			assertTrue(success);
		}

		List<DID> empty = store.listDids();
		assertTrue(empty.isEmpty());

		store.synchronize();
		List<DID> syncedDids =  new ArrayList<DID>(store.listDids());
		Collections.sort(syncedDids);

		assertArrayEquals(dids.toArray(), syncedDids.toArray());
	}

	@Test
	@Order(200)
	public void testDeactivate() throws DIDException {
		for (int i = 0; i < dids.size(); i++) {
			DID did = dids.get(i);
			int txs = i != 2 ? 4 : 2;

			DIDDocument doc = store.loadDid(did);

			doc.deactivate(TestConfig.storePass);

			DIDDocument resolved = did.resolve();
			assertNotNull(resolved);
			assertTrue(resolved.isDeactivated());

			DIDBiography bio = did.resolveBiography();
			assertNotNull(bio);
			assertEquals(txs, bio.size());
			assertEquals(IDChainRequest.Operation.DEACTIVATE, bio.getTransaction(0).getRequest().getOperation());
		}
	}

	@Test
	@Order(300)
	public void testCreateAndResolveWithMultilangCredential() throws DIDException, IOException {
		DIDDocument doc = identity.newDid(TestConfig.storePass);
		DID did = doc.getSubject();

		Issuer selfIssuer = new Issuer(doc);
		VerifiableCredential.Builder cb = selfIssuer.issueFor(did);

		Map<String, Object> props= new HashMap<String, Object>();

		File i18nDir = new File(getClass().getResource("/i18n").getPath());
		File[] i18nRes = i18nDir.listFiles();
		for (File res : i18nRes) {
			BufferedReader reader = new BufferedReader(new FileReader(res));
			String text = reader.lines().collect(Collectors.joining(System.lineSeparator()));
			reader.close();

			props.put(res.getName(), text);
		}

		VerifiableCredential vc = cb.id("#profile")
				.type("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
				.type("TestCredential", "https://trinity-tech.io/credentials/i18n/v1")
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

		TestData.waitForWalletAvaliable();
		DIDDocument resolved = did.resolve();
		assertEquals(did, resolved.getSubject());
		assertTrue(resolved.isValid());
		assertEquals(doc.toString(true), resolved.toString(true));

		String lastTxid = resolved.getMetadata().getTransactionId();
		log.debug("Last transaction id {}", lastTxid);
	}
}
