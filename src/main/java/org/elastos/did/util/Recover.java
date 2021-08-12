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

import java.io.IOException;
import java.util.concurrent.Callable;

import org.elastos.did.DID;
import org.elastos.did.DIDBackend;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDDocument.Builder;
import org.elastos.did.DIDDocument.PublicKey;
import org.elastos.did.DIDDocument.Service;
import org.elastos.did.DIDStore;
import org.elastos.did.Mnemonic;
import org.elastos.did.RootIdentity;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDResolveException;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "recover", mixinStandardHelpOptions = true, version = "recover 2.0",
		description = "Recover the wrong DIDs.")
public class Recover extends CommandBase implements Callable<Integer> {
	@Option(names = {"-n", "--network"}, description = "Avaliable networks: mainnet testnet")
	private String network = null;

	@Option(names = {"-f", "--force"}, description = "Overwrite the existing.")
	private boolean force = false;

	@Option(names = {"-m", "--merge"}, description = "How to merge the old DID information: none, interactive, all. default: interactive.")
	private String merge = null;

	@Option(names = {"-s", "--store"}, description = "DID Store path, default: ~/.elastos/did/store")
	private String storeDir = null;

	@Option(names = {"-p", "--password"}, required = true, description = "Password for the DID store")
	private String password = null;

	@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
	private boolean verbose = false;

	private static final int NONE = 0;
	private static final int INTERACTIVE = 1;
	private static final int ALL = 2;

	@Override
	public Integer call() throws Exception {
		try {
			this.setupDIDBackend(network, null);
			DIDStore store = openDIDStore(storeDir);

			int mode = INTERACTIVE;
			if (merge != null) {
				switch (merge.toLowerCase()) {
				case "none":
					mode = NONE;
					break;
				case "interactive":
					mode = INTERACTIVE;
					break;
				case "all":
					mode = ALL;
					break;
				default:
					System.err.println("Unknown merge mode: " + merge);
					return -1;
				}
			}

			String mnemonic = null;

			mnemonic = System.console().readLine("Mnemonic: ");
			if (!Mnemonic.checkIsValid(mnemonic)) {
				System.err.println("Mnemonic is invald");
				return -1;
			}

			String passphrase = System.console().readLine("Passphrase(enter for empty): ");

			RootIdentity id = RootIdentity.create(mnemonic, passphrase, force, store, password);
			System.out.println(Colorize.green("Identity " + id.getId() + " created."));

			int index = 0;
			int empty = 0;
			int error = 0;
			while (true) {
				DID did = id.getDid(index);
				System.out.format("Checking DID@%d %s...", index, did.toString());
				try {
					DIDDocument doc = did.resolve(true);
					error = 0;

					if (doc != null) {
						empty = 0;

						if (doc.isExpired())
							System.out.println(Colorize.yellow("EXPIRED"));
						else if (doc.isDeactivated())
							System.out.println(Colorize.yellow("EXPIRED"));
						else
							System.out.println(Colorize.green("GOOD"));
					} else {
						empty++;

						System.out.println(Colorize.green("NONE"));
					}
				} catch (DIDResolveException e) {
					if (e.getMessage().endsWith("signature mismatch.")) {
						empty = 0;
						error = 0;

						System.out.print(Colorize.yellow("WRONG, recovering..."));
						try {
							recoverDid(id, index, mode, password);
							System.out.format("Checking DID@%d %s...", index, did.toString());
							System.out.print(Colorize.yellow("WRONG, recovering..."));
							System.out.println(Colorize.green("RECOVERED"));
						} catch (Exception ex) {
							System.out.println(Colorize.red("FAILED"));
							if (verbose)
								ex.printStackTrace(System.err);
						}
					} else {
						error++;

						System.out.println(Colorize.red("ERROR"));
					}
				}

				if (empty >= 10 || error >= 10)
					break;

				index++;
			}
		} catch (DIDException e) {
			if (verbose)
				e.printStackTrace(System.err);
			else
				System.err.println("Error: " + e.getMessage());
		}

		return 0;
	}

	void recoverDid(RootIdentity id, int index, int mode, String password)
			throws DIDException, IOException {
		DIDDocument doc = id.newDid(index, true, password);

		if (mode != NONE) {
			String answer;
			boolean merge = true;

			DIDDocument oldDoc = DIDBackend.getInstance().resolveUntrustedDid(doc.getSubject(), true);
			Builder db = doc.edit();

			if (oldDoc.getPublicKeyCount() > 1) {
				for (PublicKey pk : oldDoc.getPublicKeys()) {
					if (pk.getId().equals(oldDoc.getDefaultPublicKeyId()))
						continue;

					if (mode == INTERACTIVE) {
						System.out.format("\nPublicKey: {\n  id = '%s',\n  key = '%s'\n}\n",
								pk.getId().toString(), pk.getPublicKeyBase58());
						answer = System.console().readLine("Add this public key(Yes or No)? ");
						merge = (answer.equalsIgnoreCase("Y") || answer.equalsIgnoreCase("YES"));
					}

					if (merge) {
						db.addPublicKey(pk.getId(), pk.getController(), pk.getPublicKeyBase58());
						if (mode == INTERACTIVE)
							System.out.println(Colorize.green("Added the public key to the new DID document."));

						if (oldDoc.isAuthenticationKey(pk.getId())) {
							if (mode == INTERACTIVE) {
								answer = System.console().readLine("Add this public key as authentication key(Yes or No)? ");
								merge = (answer.equalsIgnoreCase("Y") || answer.equalsIgnoreCase("YES"));
							}

							if (merge) {
								db.addAuthenticationKey(pk.getId());
								if (mode == INTERACTIVE)
									System.out.println(Colorize.green("Added the public key as authentication key."));
							}
						} else if (oldDoc.isAuthorizationKey(pk.getId())) {
							if (mode == INTERACTIVE) {
								answer = System.console().readLine("Add this public key as authorization key(Yes or No)? ");
								merge = (answer.equalsIgnoreCase("Y") || answer.equalsIgnoreCase("YES"));
							}

							if (merge) {
								db.addAuthorizationKey(pk.getId());
								if (mode == INTERACTIVE)
									System.out.println(Colorize.green("Added the public key as authorization key."));
							}
						}
					}
				}
			}

			if (oldDoc.getCredentialCount() > 0) {
				for (VerifiableCredential vc : oldDoc.getCredentials()) {
					if (!vc.isSelfProclaimed())
						continue;

					if (mode == INTERACTIVE) {
						System.out.print("\nVerifiableCredential: ");
						printJson(System.out, false, vc.toString(true));
						answer = System.console().readLine("Add this credential(Yes or No)? ");
						merge = (answer.equalsIgnoreCase("Y") || answer.equalsIgnoreCase("YES"));
					}

					if (merge) {
						db.addCredential(vc.getId(), vc.getType().toArray(new String[] {}),
								vc.getSubject().getProperties(), password);
						if (mode == INTERACTIVE)
							System.out.println(Colorize.green("Added the credential to the new DID document."));
					}
				}
			}

			if (oldDoc.getServiceCount() > 0) {
				for (Service svc : oldDoc.getServices()) {
					if (mode == INTERACTIVE) {
						System.out.format("\nService: {\n  id = '%s',\n  type = '%s',\n  endpoint = '%s'\n}\n",
								svc.getId().toString(), svc.getType(), svc.getServiceEndpoint());
						answer = System.console().readLine("Add this service(Yes or No)? ");
						merge = (answer.equalsIgnoreCase("Y") || answer.equalsIgnoreCase("YES"));
					}

					if (merge) {
						db.addService(svc.getId(), svc.getType(),
								svc.getServiceEndpoint(), svc.getProperties());
						if (mode == INTERACTIVE)
							System.out.println(Colorize.green("Added the service to the new DID document."));
					}
				}
			}

			doc = db.seal(password);
		}

		doc.publishUntrusted(null, password, null);
		// TODO: try to resolve the new published doc
	}
}
