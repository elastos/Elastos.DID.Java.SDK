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
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.Mnemonic;
import org.elastos.did.RootIdentity;
import org.elastos.did.exception.DIDException;

/**
 * The common class that represent an entity with DID.
 */
class Entity {
	// Mnemonic passphrase and the store password should set by the end user.
	private final static String passphrase = "";  // Default is an empty string, or any user defined word
	private final static String storepass = "mypassword";

	// The entity name
	private String name;

	private DIDStore store;
	private DID did;

	protected Entity(String name) throws DIDException {
		this.name = name;

		initRootIdentity();
		initDid();
	}

	private void initRootIdentity() throws DIDException {
		final String storePath = System.getProperty("java.io.tmpdir")
				+ File.separator + name + ".store";

		store = DIDStore.open(storePath);

		// Check the store whether contains the root private identity.
		if (store.containsRootIdentities())
			return; // Already exists

		// Create a mnemonic use default language(English).
		Mnemonic mg = Mnemonic.getInstance();
		String mnemonic = mg.generate();

		System.out.println(name + " -- Please write down your mnemonic and passwords:");
		System.out.println("  Mnemonic: " + mnemonic);
		System.out.println("  Mnemonic passphrase: " + passphrase);
		System.out.println("  Store password: " + storepass);

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
			System.out.println(name + " -- Using existing DID: " + did);
			return;
		}

		RootIdentity id = store.loadRootIdentity();
		DIDDocument doc = id.newDid(storepass);
		doc.getMetadata().setAlias("me");
		doc.publish(storepass);
		this.did = doc.getSubject();
		System.out.println(name + " -- Created the new DID : " + doc.getSubject());
	}

	public DID getDid() {
		return did;
	}

	public DIDDocument getDocument() throws DIDException {
		return store.loadDid(did);
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
