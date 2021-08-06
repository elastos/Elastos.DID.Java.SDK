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

package org.elastos.did.util;

import java.util.concurrent.Callable;

import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.RootIdentity;
import org.elastos.did.exception.DIDException;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "createdid", mixinStandardHelpOptions = true, version = "createdid 2.0",
		description = "Create a DID.")
public class CreateDid extends CommandBase implements Callable<Integer> {
	@Option(names = {"-f", "--force"}, description = "Overwrite the existing.")
	private boolean force = false;

	@Option(names = {"-s", "--store"}, description = "DID Store path, default: ~/.elastos/did/store")
	private String storeDir = null;

	@Option(names = {"-i", "--identity"}, description = "The root identity ID to create the DID")
	private String identity = null;

	@Option(names = {"-n", "--index"}, description = "Create new DID with the index")
	private int index = -1;

	@Option(names = {"-p", "--password"}, required = true, description = "Password for the DID store")
	private String password = null;

	@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
	private boolean verbose = false;

	@Override
	public Integer call() throws Exception {
		try {
			DIDStore store = openDIDStore(storeDir);

			RootIdentity id = null;
			if (identity == null || identity.isEmpty()) {
				id = store.loadRootIdentity();
				if (id == null) {
					System.out.println(Colorize.red("Store not contains the default root identity"));
					return -1;
				}
			} else {
				id = store.loadRootIdentity(identity);
				if (id == null) {
					System.out.format(Colorize.red("Store not contains the root identity: %s\n"), identity);
					return -1;
				}
			}

			DIDDocument doc;
			if (index >= 0)
				doc = id.newDid(index, force, password);
			else
				doc = id.newDid(password);

			System.out.println(Colorize.green("DID " + doc.getSubject() + " created."));
			System.out.println("\nDID document:");
			printJson(System.out, false, doc.serialize(true));
		} catch (DIDException e) {
			if (verbose)
				e.printStackTrace(System.err);
			else
				System.err.println("Error: " + e.getMessage());
		}

		return 0;
	}
}
