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

import org.elastos.did.DID;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.exception.DIDException;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "displaydid", mixinStandardHelpOptions = true, version = "displaydid 2.0",
		description = "Display the DID document and metadata.")
public class DisplayDid extends CommandBase implements Callable<Integer> {
	@Option(names = {"-s", "--store"}, description = "DID Store path, default: ~/.elastos/did/store")
	private String storeDir = null;

	@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
	private boolean verbose = false;

	@Parameters(paramLabel = "DID", index = "0", description = "The DID to be display.")
	private String did;

	@Override
	public Integer call() throws Exception {
		try {
			DIDStore store = openDIDStore(storeDir);

			DID _did = new DID(did);
			DIDDocument doc = store.loadDid(_did);

			if (doc != null) {
				System.out.println("DID document:");
				printJson(System.out, false, doc.serialize(true));

				System.out.println("\nDID Metadata:");
				printJson(System.out, false, doc.getMetadata().serialize());
			} else {
				System.out.format(Colorize.red("DID %s not exists\n"), did);
			}
		} catch (DIDException e) {
			if (verbose)
				e.printStackTrace(System.err);
			else
				System.err.println("Error: " + e.getMessage());
		}

		return 0;
	}
}
