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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.WrongPasswordException;
import org.elastos.did.utils.DIDTestExtension;
import org.elastos.did.utils.TestConfig;
import org.elastos.did.utils.TestData;
import org.elastos.did.utils.Utils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ExtendWith(DIDTestExtension.class)
public class DIDStoreTest {
	private TestData testData;
	private DIDStore store;

	private static final Logger log = LoggerFactory.getLogger(DIDStoreTest.class);

    @BeforeEach
    public void beforeEach() throws DIDException {
    	testData = new TestData();
    	store = testData.getStore();
    }

    @AfterEach
    public void afterEach() {
    	testData.cleanup();
    }

    private File getFile(String ... path) {
		StringBuffer relPath = new StringBuffer(256);

		relPath.append(TestConfig.storeRoot)
			.append(File.separator)
			.append("data");

		for (String p : path) {
			relPath.append(File.separator);
			relPath.append(p);
		}

		return new File(relPath.toString());
	}

	@Test
	public void testLoadRootIdentityFromEmptyStore() throws DIDException {
		File file = getFile(".metadata");;
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

		RootIdentity identity = store.loadRootIdentity();
    	assertNull(identity);
	}

	@Test
	public void testBulkCreate() throws DIDException {
		File file = getFile(".metadata");;
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

		RootIdentity identity = testData.getRootIdentity();

    	file = getFile("roots", identity.getId(), "mnemonic");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	file = getFile("roots", identity.getId(), "private");;
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	file = getFile("roots", identity.getId(), "public");;
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	file = getFile("roots", identity.getId(), "index");;
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	file = getFile("roots", identity.getId(), ".metadata");;
    	assertFalse(file.exists());

    	identity.setAlias("default");
    	file = getFile("roots", identity.getId(), ".metadata");;
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	for (int i = 0; i < 100; i++) {
    		String alias = "my did " + i;
        	DIDDocument doc = identity.newDid(TestConfig.storePass);
        	doc.getMetadata().setAlias(alias);
        	assertTrue(doc.isValid());

        	DIDDocument resolved = doc.getSubject().resolve();
        	assertNull(resolved);

        	doc.publish(TestConfig.storePass);

        	file = getFile("ids", doc.getSubject().getMethodSpecificId(), "document");
        	assertTrue(file.exists());
        	assertTrue(file.isFile());

        	file = getFile("ids", doc.getSubject().getMethodSpecificId(), ".metadata");
        	assertTrue(file.exists());
        	assertTrue(file.isFile());

        	resolved = doc.getSubject().resolve();
        	assertNotNull(resolved);
        	store.storeDid(resolved);
        	assertEquals(alias, resolved.getMetadata().getAlias());
        	assertEquals(doc.getSubject(), resolved.getSubject());
        	assertEquals(doc.getProof().getSignature(),
        			resolved.getProof().getSignature());

        	assertTrue(resolved.isValid());
    	}

		List<DID> dids = store.listDids();
		assertEquals(100, dids.size());
	}

	@Test
	public void testDeleteDID() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

    	// Create test DIDs
    	LinkedList<DID> dids = new LinkedList<DID>();
		for (int i = 0; i < 100; i++) {
    		String alias = "my did " + i;
        	DIDDocument doc = identity.newDid(TestConfig.storePass);
        	doc.getMetadata().setAlias(alias);
         	doc.publish(TestConfig.storePass);
         	dids.add(doc.getSubject());
    	}

		for (int i = 0; i < 100; i++) {
			if (i % 5 != 0)
				continue;

			DID did = dids.get(i);

    		boolean deleted = store.deleteDid(did);
    		assertTrue(deleted);

	    	File file = getFile("ids", did.getMethodSpecificId());
	    	assertFalse(file.exists());

    		deleted = store.deleteDid(did);
    		assertFalse(deleted);
    	}

		List<DID> remains = store.listDids();
		assertEquals(80, remains.size());
	}

	@Test
	public void testStoreAndLoadDID() throws DIDException, IOException {
    	// Store test data into current store
    	DIDDocument issuer = testData.getInstantData().getIssuerDocument();

    	File file = getFile("ids", issuer.getSubject().getMethodSpecificId(),
    			"document");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	file = getFile("ids", issuer.getSubject().getMethodSpecificId(),
    			".metadata");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	DIDDocument test = testData.getInstantData().getUser1Document();

    	file = getFile("ids", test.getSubject().getMethodSpecificId(),
    			"document");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	file = getFile("ids", test.getSubject().getMethodSpecificId(),
    			".metadata");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	DIDDocument doc = store.loadDid(issuer.getSubject());
    	assertEquals(issuer.getSubject(), doc.getSubject());
    	assertEquals(issuer.getProof().getSignature(), doc.getProof().getSignature());
    	assertTrue(doc.isValid());

    	doc = store.loadDid(test.getSubject().toString());
    	assertEquals(test.getSubject(), doc.getSubject());
    	assertEquals(test.getProof().getSignature(), doc.getProof().getSignature());
    	assertTrue(doc.isValid());

		List<DID> dids = store.listDids();
		assertEquals(2, dids.size());
	}

	@Test
	public void testLoadCredentials() throws DIDException, IOException {
    	// Store test data into current store
    	testData.getInstantData().getIssuerDocument();
    	DIDDocument user = testData.getInstantData().getUser1Document();

    	VerifiableCredential vc = user.getCredential("#profile");
    	vc.getMetadata().setAlias("MyProfile");

    	File file = getFile("ids", vc.getId().getDid().getMethodSpecificId(),
    			"credentials", "#" + vc.getId().getFragment(), "credential");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	file = getFile("ids", vc.getId().getDid().getMethodSpecificId(),
    			"credentials", "#" + vc.getId().getFragment(), ".metadata");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	vc = user.getCredential("#email");
      	vc.getMetadata().setAlias("Email");

    	file = getFile("ids", vc.getId().getDid().getMethodSpecificId(),
    			"credentials", "#" + vc.getId().getFragment(), "credential");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	file = getFile("ids", vc.getId().getDid().getMethodSpecificId(),
    			"credentials", "#" + vc.getId().getFragment(), ".metadata");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	vc = testData.getInstantData().getUser1TwitterCredential();
    	vc.getMetadata().setAlias("Twitter");

    	file = getFile("ids", vc.getId().getDid().getMethodSpecificId(),
    			"credentials", "#" + vc.getId().getFragment(), "credential");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	file = getFile("ids", vc.getId().getDid().getMethodSpecificId(),
    			"credentials", "#" + vc.getId().getFragment(), ".metadata");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	vc = testData.getInstantData().getUser1PassportCredential();
    	vc.getMetadata().setAlias("Passport");

    	file = getFile("ids", vc.getId().getDid().getMethodSpecificId(),
    			"credentials", "#" + vc.getId().getFragment(), "credential");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	file = getFile("ids", vc.getId().getDid().getMethodSpecificId(),
    			"credentials", "#" + vc.getId().getFragment(), ".metadata");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	DIDURL id = new DIDURL(user.getSubject(), "#profile");
    	vc = store.loadCredential(id);
    	assertEquals("MyProfile", vc.getMetadata().getAlias());
    	assertEquals(user.getSubject(), vc.getSubject().getId());
    	assertEquals(id, vc.getId());
    	assertTrue(vc.isValid());

    	// try with full id string
    	vc = store.loadCredential(id.toString());
    	assertNotNull(vc);
    	assertEquals("MyProfile", vc.getMetadata().getAlias());
    	assertEquals(user.getSubject(), vc.getSubject().getId());
    	assertEquals(id, vc.getId());
    	assertTrue(vc.isValid());

    	id = new DIDURL(user.getSubject(), "#twitter");
    	vc = store.loadCredential(id.toString());
    	assertNotNull(vc);
    	assertEquals("Twitter", vc.getMetadata().getAlias());
    	assertEquals(user.getSubject(), vc.getSubject().getId());
    	assertEquals(id, vc.getId());
    	assertTrue(vc.isValid());

    	vc = store.loadCredential(new DIDURL(user.getSubject(), "#notExist"));
    	assertNull(vc);

    	id = new DIDURL(user.getSubject(), "#twitter");
		assertTrue(store.containsCredential(id));
		assertTrue(store.containsCredential(id.toString()));
		assertFalse(store.containsCredential(new DIDURL(user.getSubject(), "#notExists")));
	}

	@Test
	public void testListCredentials() throws DIDException, IOException {
    	testData.getRootIdentity();

    	// Store test data into current store
		testData.getInstantData().getIssuerDocument();
		DIDDocument user = testData.getInstantData().getUser1Document();
    	VerifiableCredential vc = user.getCredential("#profile");
    	vc.getMetadata().setAlias("MyProfile");
    	vc = user.getCredential("#email");
    	vc.getMetadata().setAlias("Email");
    	vc = testData.getInstantData().getUser1TwitterCredential();
    	vc.getMetadata().setAlias("Twitter");
    	vc = testData.getInstantData().getUser1PassportCredential();
    	vc.getMetadata().setAlias("Passport");

    	List<DIDURL> vcs = store.listCredentials(user.getSubject());
		assertEquals(4, vcs.size());

		for (DIDURL id : vcs) {
			assertTrue(id.getFragment().equals("profile")
					|| id.getFragment().equals("email")
					|| id.getFragment().equals("twitter")
					|| id.getFragment().equals("passport"));

			assertTrue(id.getMetadata().getAlias().equals("MyProfile")
					|| id.getMetadata().getAlias().equals("Email")
					|| id.getMetadata().getAlias().equals("Twitter")
					|| id.getMetadata().getAlias().equals("Passport"));
		}
	}

	@Test
	public void testDeleteCredential() throws DIDException, IOException {
    	// Store test data into current store
		testData.getInstantData().getIssuerDocument();
		DIDDocument user = testData.getInstantData().getUser1Document();
    	VerifiableCredential vc = user.getCredential("#profile");
    	vc.getMetadata().setAlias("MyProfile");
    	vc = user.getCredential("#email");
    	vc.getMetadata().setAlias("Email");
    	vc = testData.getInstantData().getUser1TwitterCredential();
    	vc.getMetadata().setAlias("Twitter");
    	vc = testData.getInstantData().getUser1PassportCredential();
    	vc.getMetadata().setAlias("Passport");


    	File file = getFile("ids", user.getSubject().getMethodSpecificId(),
    			"credentials", "#twitter", "credential");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	file = getFile("ids", user.getSubject().getMethodSpecificId(),
    			"credentials", "#twitter", ".metadata");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	file = getFile("ids", user.getSubject().getMethodSpecificId(),
    			"credentials", "#passport", "credential");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	file = getFile("ids", user.getSubject().getMethodSpecificId(),
    			"credentials", "#passport", ".metadata");
    	assertTrue(file.exists());
    	assertTrue(file.isFile());

    	boolean deleted = store.deleteCredential(new DIDURL(user.getSubject(), "#twitter"));
		assertTrue(deleted);

		deleted = store.deleteCredential(new DIDURL(user.getSubject(), "#passport").toString());
		assertTrue(deleted);

		deleted = store.deleteCredential(user.getSubject().toString() + "#notExist");
		assertFalse(deleted);

    	file = getFile("ids", user.getSubject().getMethodSpecificId(),
    			"credentials", "#twitter");
    	assertFalse(file.exists());

    	file = getFile("ids", user.getSubject().getMethodSpecificId(),
    			"credentials", "#passport");
    	assertFalse(file.exists());

		assertTrue(store.containsCredential(new DIDURL(user.getSubject(), "#email")));
		assertTrue(store.containsCredential(user.getSubject().toString() + "#profile"));

		assertFalse(store.containsCredential(new DIDURL(user.getSubject(), "#twitter")));
		assertFalse(store.containsCredential(user.getSubject().toString() + "#passport"));
	}

	@Test
	public void testChangePassword() throws DIDException {
    	RootIdentity identity = testData.getRootIdentity();

		for (int i = 0; i < 10; i++) {
    		String alias = "my did " + i;
        	DIDDocument doc = identity.newDid(TestConfig.storePass);
        	doc.getMetadata().setAlias(alias);
        	assertTrue(doc.isValid());

        	DIDDocument resolved = doc.getSubject().resolve();
        	assertNull(resolved);

        	doc.publish(TestConfig.storePass);

        	File file = getFile("ids", doc.getSubject().getMethodSpecificId(), "document");
        	assertTrue(file.exists());
        	assertTrue(file.isFile());

        	file = getFile("ids", doc.getSubject().getMethodSpecificId(), ".metadata");
        	assertTrue(file.exists());
        	assertTrue(file.isFile());

        	file = getFile("ids", doc.getSubject().getMethodSpecificId(), "privatekeys", "#primary");
        	assertTrue(file.exists());
        	assertTrue(file.isFile());

        	resolved = doc.getSubject().resolve();
        	assertNotNull(resolved);
        	store.storeDid(resolved);
        	assertEquals(alias, resolved.getMetadata().getAlias());
        	assertEquals(doc.getSubject(), resolved.getSubject());
        	assertEquals(doc.getProof().getSignature(),
        			resolved.getProof().getSignature());

        	assertTrue(resolved.isValid());
    	}

		List<DID> dids = store.listDids();
		assertEquals(10, dids.size());

		store.changePassword(TestConfig.storePass, "newpasswd");

		dids = store.listDids();
		assertEquals(10, dids.size());

		for (int i = 0; i < 10; i++) {
    		String alias = "my did " + i;
    		DID did = identity.getDid(i);
        	DIDDocument doc = store.loadDid(did);
        	assertNotNull(doc);
        	assertTrue(doc.isValid());

        	File file = getFile("ids", did.getMethodSpecificId(), "document");
        	assertTrue(file.exists());
        	assertTrue(file.isFile());

        	file = getFile("ids", did.getMethodSpecificId(), ".metadata");
        	assertTrue(file.exists());
        	assertTrue(file.isFile());

        	file = getFile("ids", did.getMethodSpecificId(), "privatekeys", "#primary");
        	assertTrue(file.exists());
        	assertTrue(file.isFile());

        	assertEquals(alias, doc.getMetadata().getAlias());
    	}

		DIDDocument doc = identity.newDid("newpasswd");
		assertNotNull(doc);
	}

	@Test
	public void testChangePasswordWithWrongPassword() throws DIDException {
		RootIdentity identity = testData.getRootIdentity();

		for (int i = 0; i < 10; i++) {
    		String alias = "my did " + i;
        	DIDDocument doc = identity.newDid(TestConfig.storePass);
        	doc.getMetadata().setAlias(alias);
        	assertTrue(doc.isValid());
    	}

		List<DID> dids = store.listDids();
		assertEquals(10, dids.size());

		assertThrows(DIDStoreException.class, () -> {
			store.changePassword("wrongpasswd", "newpasswd");
		});
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testCompatibility(int version) throws DIDException, IOException {
    	byte[] data = "Hello World".getBytes();

    	TestData.CompatibleData cd = testData.getCompatibleData(version);
    	cd.loadAll();

		DIDStore store = DIDStore.open(cd.getStoreDir());

       	List<DID> dids = store.listDids();
       	assertEquals(version == 2 ? 10 : 4, dids.size());

       	for (DID did : dids) {
       		String alias = String.valueOf(did.getMetadata().getAlias());

       		if (alias.equals("Issuer")) {
       			List<DIDURL> vcs = store.listCredentials(did);
       			assertEquals(1, vcs.size());

       			for (DIDURL id : vcs)
       				assertNotNull(store.loadCredential(id));
       		} else if (alias.equals("User1")) {
       			List<DIDURL> vcs = store.listCredentials(did);
       			assertEquals(version == 2 ? 5 : 4, vcs.size());

       			for (DIDURL id : vcs)
       				assertNotNull(store.loadCredential(id));
       		} else if (alias.equals("User2")) {
       			List<DIDURL> vcs = store.listCredentials(did);
       			assertEquals(1, vcs.size());

       			for (DIDURL id : vcs)
       				assertNotNull(store.loadCredential(id));
       		} else if (alias.equals("User3")) {
       			List<DIDURL> vcs = store.listCredentials(did);
       			assertEquals(0, vcs.size());
       		}

       		DIDDocument doc = store.loadDid(did);
       		if (!doc.isCustomizedDid() || doc.getControllerCount() <= 1) {
	       		String sig = doc.sign(TestConfig.storePass, data);
	       		assertTrue(doc.verify(sig, data));
       		}
       	}
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testCompatibilityNewDIDWithWrongPass(int version) throws DIDException {
		DIDStore store = DIDStore.open(testData.getCompatibleData(version).getStoreDir());
		RootIdentity idenitty = store.loadRootIdentity();

		assertThrows(WrongPasswordException.class, () -> {
			idenitty.newDid("wrongpass");
		});
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testCompatibilityNewDIDandGetDID(int version) throws DIDException {
		DIDStore store = DIDStore.open(testData.getCompatibleData(version).getStoreDir());
		RootIdentity identity = store.loadRootIdentity();

       	DIDDocument doc = identity.newDid(TestConfig.storePass);
       	assertNotNull(doc);

       	store.deleteDid(doc.getSubject());

       	DID did = identity.getDid(1000);

       	doc = identity.newDid(1000, TestConfig.storePass);
       	assertNotNull(doc);
       	assertEquals(doc.getSubject(), did);

       	store.deleteDid(doc.getSubject());

	}

	private void createDataForPerformanceTest(DIDStore store)
			throws DIDException {
		Map<String, Object> props= new HashMap<String, Object>();
		props.put("name", "John");
		props.put("gender", "Male");
		props.put("nation", "Singapore");
		props.put("language", "English");
		props.put("email", "john@example.com");
		props.put("twitter", "@john");

		RootIdentity identity = store.loadRootIdentity();

		for (int i = 0; i < 10; i++) {
    		String alias = "my did " + i;
        	DIDDocument doc = identity.newDid(TestConfig.storePass);
        	doc.getMetadata().setAlias(alias);
        	Issuer issuer = new Issuer(doc);
        	VerifiableCredential.Builder cb = issuer.issueFor(doc.getSubject());
        	VerifiableCredential vc = cb.id("#cred-1")
        			.type("BasicProfileCredential", "SelfProclaimedCredential")
        			.properties(props)
        			.seal(TestConfig.storePass);

        	store.storeCredential(vc);
		}
	}

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
	public void testStoreCachePerformance(boolean cached) throws DIDException {
		Utils.deleteFile(new File(TestConfig.storeRoot));
		DIDStore store = null;
    	if (cached)
    		store = DIDStore.open(TestConfig.storeRoot);
    	else
    		store = DIDStore.open(TestConfig.storeRoot, 0, 0);

       	String mnemonic =  Mnemonic.getInstance().generate();
    	RootIdentity.create(mnemonic, TestConfig.passphrase,
    			true, store, TestConfig.storePass);

    	createDataForPerformanceTest(store);

    	List<DID> dids = store.listDids();
    	assertEquals(10, dids.size());

    	long start = System.currentTimeMillis();

    	for (int i = 0; i < 1000; i++) {
	    	for (DID did : dids) {
	    		DIDDocument doc = store.loadDid(did);
	    		assertEquals(did, doc.getSubject());

	    		DIDURL id = new DIDURL(did, "#cred-1");
	    		VerifiableCredential vc = store.loadCredential(id);
	    		assertEquals(id, vc.getId());
	    	}
    	}

    	long end = System.currentTimeMillis();

    	log.info("Store loading {} cache took {} milliseconds.",
    			(cached ? "with" : "without"), end - start);
	}

	@Test
	public void testMultipleStore() throws DIDException {
		DIDStore[] stores = new DIDStore[10];
		DIDDocument[] docs = new DIDDocument[10];

		for (int i = 0; i < stores.length; i++) {
			Utils.deleteFile(new File(TestConfig.storeRoot + i));
			stores[i] = DIDStore.open(TestConfig.storeRoot + i);
			assertNotNull(stores[i]);
			String mnemonic = Mnemonic.getInstance().generate();
			RootIdentity.create(mnemonic, "", stores[i], TestConfig.storePass);
		}

		for (int i = 0; i < stores.length; i++) {
			docs[i] = stores[i].loadRootIdentity().newDid(TestConfig.storePass);
			assertNotNull(docs[i]);
		}

		for (int i = 0; i < stores.length; i++) {
			DIDDocument doc = stores[i].loadDid(docs[i].getSubject());
			assertNotNull(doc);
			assertEquals(docs[i].toString(true), doc.toString(true));
		}
	}

	@Test
	public void testOpenStoreOnExistEmptyFolder() throws DIDException {
		File emptyFolder = new File(TestConfig.tempDir + File.separator + "DIDTest-EmptyStore");
		if (emptyFolder.exists())
			Utils.deleteFile(emptyFolder);

		emptyFolder.mkdirs();

		DIDStore store = DIDStore.open(emptyFolder);
		assertNotNull(store);

		store.close();
	}

	@Test
	public void testExportAndImportDid() throws DIDException, IOException {
		File storeDir = new File(TestConfig.storeRoot);

		testData.getInstantData().getIssuerDocument();
		testData.getInstantData().getUser1Document();
		testData.getInstantData().getUser1PassportCredential();
		testData.getInstantData().getUser1TwitterCredential();

		DID did = store.listDids().get(0);

		File tempDir = new File(TestConfig.tempDir);
		tempDir.mkdirs();
		File exportFile = new File(tempDir, "didexport.json");

		store.exportDid(did, exportFile, "password", TestConfig.storePass);

		File restoreDir = new File(tempDir, "restore");
		Utils.deleteFile(restoreDir);
		DIDStore store2 = DIDStore.open(restoreDir.getAbsolutePath());
		store2.importDid(exportFile, "password", TestConfig.storePass);

		String path = "data" + File.separator + "ids" + File.separator + did.getMethodSpecificId();
		File didDir = new File(storeDir, path);
		File reDidDir = new File(restoreDir, path);
		assertTrue(didDir.exists());
		assertTrue(reDidDir.exists());
		assertTrue(Utils.equals(reDidDir, didDir));
	}

	@Test
	public void testExportAndImportRootIdentity() throws DIDException, IOException {
		File storeDir = new File(TestConfig.storeRoot);

		testData.getInstantData().getIssuerDocument();
		testData.getInstantData().getUser1Document();
		testData.getInstantData().getUser1PassportCredential();
		testData.getInstantData().getUser1TwitterCredential();

		String id = store.loadRootIdentity().getId();

		File tempDir = new File(TestConfig.tempDir);
		tempDir.mkdirs();
		File exportFile = new File(tempDir, "idexport.json");

		store.exportRootIdentity(id, exportFile, "password", TestConfig.storePass);

		File restoreDir = new File(tempDir, "restore");
		Utils.deleteFile(restoreDir);
		DIDStore store2 = DIDStore.open(restoreDir.getAbsolutePath());
		store2.importRootIdentity(exportFile, "password", TestConfig.storePass);

		String path = "data" + File.separator + "roots" + File.separator + id;
		File privateDir = new File(storeDir, path);
		File rePrivateDir = new File(restoreDir, path);
		assertTrue(privateDir.exists());
		assertTrue(rePrivateDir.exists());
		assertTrue(Utils.equals(rePrivateDir, privateDir));
	}

	@Test
	public void testExportAndImportStore() throws DIDException, IOException {
    	testData.getRootIdentity();

    	// Store test data into current store
		testData.getInstantData().getIssuerDocument();
		DIDDocument user = testData.getInstantData().getUser1Document();
    	VerifiableCredential vc = user.getCredential("#profile");
    	vc.getMetadata().setAlias("MyProfile");
    	vc = user.getCredential("#email");
    	vc.getMetadata().setAlias("Email");
    	vc = testData.getInstantData().getUser1TwitterCredential();
    	vc.getMetadata().setAlias("Twitter");
    	vc = testData.getInstantData().getUser1PassportCredential();
    	vc.getMetadata().setAlias("Passport");

		File tempDir = new File(TestConfig.tempDir);
		tempDir.mkdirs();
		File exportFile = new File(tempDir, "storeexport.zip");

		store.exportStore(exportFile, "password", TestConfig.storePass);

		File restoreDir = new File(tempDir, "restore");
		Utils.deleteFile(restoreDir);
		DIDStore store2 = DIDStore.open(restoreDir.getAbsolutePath());
		store2.importStore(exportFile, "password", TestConfig.storePass);

		File storeDir = new File(TestConfig.storeRoot);

		assertTrue(storeDir.exists());
		assertTrue(restoreDir.exists());
		assertTrue(Utils.equals(restoreDir, storeDir));
	}
}
