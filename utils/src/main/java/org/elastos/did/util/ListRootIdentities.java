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

import java.util.List;
import java.util.concurrent.Callable;

import org.elastos.did.DIDStore;
import org.elastos.did.RootIdentity;
import org.elastos.did.exception.DIDException;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "listidentity", mixinStandardHelpOptions = true, version = "listidentity 2.0",
		description = "List the RootIdentities.")
public class ListRootIdentities extends CommandBase implements Callable<Integer> {
	@Option(names = {"-s", "--store"}, description = "DID Store path, default: ~/.elastos/did/store")
	private String storeDir = null;

	@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
	private boolean verboseErrors = false;

	@Override
	public Integer call() throws Exception {
		try {
			DIDStore store = openDIDStore(storeDir);

			RootIdentity defaultId = store.loadRootIdentity();
			List<RootIdentity> ids = store.listRootIdentities();

			System.out.format(Colorize.green("Total %d root identities\n"), ids.size());
			for (RootIdentity id : ids) {
				String defaultMarker = "";

				if (defaultId != null && id.getId().equals(defaultId.getId()))
					defaultMarker = " *";

				System.out.println("  " + id.getId() + defaultMarker);
			}
		} catch (DIDException e) {
			if (verboseErrors)
				e.printStackTrace(System.err);
			else
				System.err.println("Error: " + e.getMessage());
		}

		return 0;
	}
}
