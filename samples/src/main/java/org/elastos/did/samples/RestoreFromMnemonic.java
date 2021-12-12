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
import org.elastos.did.DIDStore;
import org.elastos.did.RootIdentity;
import org.elastos.did.exception.DIDException;

/**
 * How to restore DIDs from the mnemonic backup.
 */
public class RestoreFromMnemonic {
	public static void restore() throws DIDException {
		String mnemonic = "advance duty suspect finish space matter squeeze elephant twenty over stick shield";
		String passphrase = "secret";
		String storepass = "passwd";

		String storePath = System.getProperty("java.io.tmpdir")
				+ File.separator + RestoreFromMnemonic.class.getName() + ".store";
		deleteFile(new File(storePath));

		DIDStore store = DIDStore.open(storePath);

		RootIdentity id = RootIdentity.create(mnemonic, passphrase, store, storepass);
		id.synchronize();

		List<DID> dids = store.listDids();
		System.out.println(dids.size() + " DIDs restored.");
		if (dids.size() > 0) {
			for (DID did : dids) {
				System.out.println(did);
				System.out.println(store.loadDid(did));
			}
		} else {
			System.out.println("No dids restored.");
		}
	}

	private static void deleteFile(File file) {
		if (file.isDirectory()) {
			File[] children = file.listFiles();
			for (File child : children)
				deleteFile(child);
		}

		file.delete();
	}

	public static void main(String[] args) throws DIDException {
		// Initializa the DID backend globally.
		Web3Adapter adapter = new Web3Adapter();
		DIDBackend.initialize(adapter);

		restore();

		adapter.shutdown();
	}
}
