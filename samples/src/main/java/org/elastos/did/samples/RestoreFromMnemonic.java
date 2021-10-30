package org.elastos.did.samples;

import java.io.File;
import java.util.List;

import org.elastos.did.DID;
import org.elastos.did.DIDBackend;
import org.elastos.did.DIDStore;
import org.elastos.did.RootIdentity;
import org.elastos.did.exception.DIDException;

public class RestoreFromMnemonic {
	private static void deleteFile(File file) {
		if (file.isDirectory()) {
			File[] children = file.listFiles();
			for (File child : children)
				deleteFile(child);
		}

		file.delete();
	}

	public static void main(String[] args) throws DIDException {
		String mnemonic = "advance duty suspect finish space matter squeeze elephant twenty over stick shield";
		String passphrase = "secret";
		String storepass = "passwd";

		// Initializa the DID backend globally.
		DIDBackend.initialize(new AssistDIDAdapter("testnet"));

		final String storePath = System.getProperty("java.io.tmpdir")
				+ File.separator + "recovery.store";
		deleteFile(new File(storePath));

		DIDStore store = DIDStore.open(storePath);

		RootIdentity id = RootIdentity.create(mnemonic, passphrase, store, storepass);
		id.synchronize();

		List<DID> dids = store.listDids();
		if (dids.size() > 0) {
			for (DID did : dids) {
				System.out.println(did);
				System.out.println(store.loadDid(did));
			}

		} else {
			System.out.println("No dids restored.");
		}
	}

}
