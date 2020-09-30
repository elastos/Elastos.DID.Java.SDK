package org.elastos.did.examples;

import java.io.File;
import java.util.List;

import org.elastos.did.DID;
import org.elastos.did.DIDBackend;
import org.elastos.did.DIDStore;
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

		// Get DID resolve cache dir.
		final String cacheDir = System.getProperty("user.home") + File.separator + ".cache"
				+ File.separator + "elastos.did";

		// Initializa the DID backend globally.
		DIDBackend.initialize("http://api.elastos.io:21606", cacheDir);

		final String storePath = System.getProperty("java.io.tmpdir")
				+ File.separator + "recovery.store";
		deleteFile(new File(storePath));

		// Create a fake adapter, just print the tx payload to console.
		DIDStore store = DIDStore.open("filesystem", storePath, (payload, memo) -> {
			System.out.println("Create ID transaction with:");
			System.out.println("  Payload = " + payload);
		});

		store.initPrivateIdentity(null, mnemonic, passphrase, storepass);

		store.synchronize(storepass);

		List<DID> dids = store.listDids(DIDStore.DID_HAS_PRIVATEKEY);
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
