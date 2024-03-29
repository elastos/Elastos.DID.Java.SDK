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

package org.elastos.did.samples;

import java.io.File;
import java.util.List;

import org.elastos.did.DID;
import org.elastos.did.DIDBackend;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.Mnemonic;
import org.elastos.did.RootIdentity;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDStoreException;

/**
 * How to use the root identity object.
 */
public class RootIdentitySample {
	private static final String STORE_PASS = "secret";

	private DIDStore store;
	private RootIdentity identity;
	private String mnemonic; // use to re-create a store

	public DIDStore openStore() throws DIDStoreException {
		if (store == null) {
			// Location to your DIDStore
			String storePath = System.getProperty("java.io.tmpdir")
					+ File.separator + this.getClass().getName() + ".store";

			store = DIDStore.open(storePath);
		}

		return store;
	}

	public void closeStore() {
		if (store != null)
			store.close();
	}

	public RootIdentity createNewRootIdentity() throws DIDException {
		// Create a mnemonic use default language(English).
		Mnemonic mg = Mnemonic.getInstance();
		mnemonic = mg.generate();

		System.out.println("Please write down your mnemonic:\n  " + mnemonic);

		// Initialize the root identity.
		identity = RootIdentity.create(mnemonic, null, store, STORE_PASS);
		return identity;
	}

	public void listRootIdentity() throws DIDException {
		List<RootIdentity> ids = store.listRootIdentities();

		for (RootIdentity id : ids)
			System.out.println("RootIdentity: " + id.getId());
	}

	public void createDid() throws DIDException {
		DIDDocument doc = identity.newDid(STORE_PASS);
		DID did = doc.getSubject();

		System.out.println("Created DID: " + did);

		doc.publish(STORE_PASS);
		System.out.println("Published DID: " + did);
	}

	public void createDidByIndex(int index) throws DIDException {
		DIDDocument doc = identity.newDid(index, STORE_PASS);
		DID did = doc.getSubject();

		System.out.println("Created DID: " + did);

		doc.publish(STORE_PASS);
		System.out.println("Published DID: " + did);
	}

	public void createAnotherStoreAndSyncRootIdentity() throws DIDException {
		String storePath = System.getProperty("java.io.tmpdir")
				+ File.separator + this.getClass().getName() + "_new.store";
		DIDStore newStore = DIDStore.open(storePath);

		// Re-create the root identity with user's mnemonic.
		identity = RootIdentity.create(mnemonic, null, newStore, STORE_PASS);

		// Synchronize the existing(published) DIDs that created by this identity
		identity.synchronize();
		// now the new store has the same contexts with the previous sample store

		newStore.close();
	}

	public static void main(String[] args) {
		// Initializa the DID backend globally.
		Web3Adapter adapter = new Web3Adapter();
		DIDBackend.initialize(adapter);

		RootIdentitySample sample = new RootIdentitySample();

		try {
			sample.openStore();

			sample.createNewRootIdentity();
			// The new created root identities in the store
			sample.listRootIdentity();

			// Create DID using next available index
			sample.createDid();

			// Create DID with specified index
			sample.createDidByIndex(1234);

			sample.closeStore();

			// you can do this on the other device restore same identity and store
			sample.createAnotherStoreAndSyncRootIdentity();
		} catch (DIDException e) {
			e.printStackTrace();
		}

		adapter.shutdown();
	}
}
