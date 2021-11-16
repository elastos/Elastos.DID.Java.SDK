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
		DIDBackend.initialize(new AssistDIDAdapter("testnet"));

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
	}
}
