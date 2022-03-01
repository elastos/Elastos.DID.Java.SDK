/*
 * Copyright (c) 2022 Elastos Foundation
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
import java.io.PrintStream;
import java.util.List;
import java.util.concurrent.Callable;

import org.elastos.did.DID;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.DIDURL;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.backend.CredentialBiography;
import org.elastos.did.backend.CredentialTransaction;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDResolveException;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "credential", mixinStandardHelpOptions = true, version = "2.0",
description = "Credential management commands.", subcommands = {
		Credentials.Resolve.class,
		Credentials.ListLocal.class,
		Credentials.ListDeclared.class,
		Credentials.Verify.class
})
public class Credentials {
	@Command(name = "resolve", mixinStandardHelpOptions = true, version = "2.0",
			description = "Resolve credential from the ID side chain.", sortOptions = false)
	public static class Resolve extends CommandBase implements Callable<Integer> {
		@Option(names = {"-f", "--force"}, description = "Resolve froced from ID sidechain, default false.")
		private boolean force = false;

		@Option(names = {"-b", "--biography"}, description = "Resolve credential biography from ID sidechain.")
		private boolean biography = false;

		@Option(names = {"-l", "--local"}, description = "Local DID resolve directory, default current directory.")
		private String localDir = null;

		@Option(names = {"-c", "--compact"}, description = "Output JSON in compact format, default false.")
		private boolean compact = false;

		@Option(names = {"-o", "--out"}, description = "Output file, default is STDOUT.")
		private String outputFile;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "ID", index = "0", description = "The credential ID(DIDURL) to be resolve.")
		private String vcId;

		private DIDURL id;

		@Override
		public Integer call() {
			try {
				if (localDir != null)
					setLocalResolveHandle(toFile(localDir));

				id = toDidUrl(vcId);

				if (biography)
					resolveVcBiography();
				else
					resolveVc();

				return 0;
			} catch(Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			} finally {
				if (localDir != null)
					clearLocalResolveHandle();
			}
		}

		private void resolveVc() throws DIDException, IOException {
			System.out.format("Resolving credential %s...", id);
			VerifiableCredential vc = VerifiableCredential.resolve(id, force);
			if (vc == null) {
				System.out.println(Colorize.red("NOT exists"));
			} else {
				System.out.println(Colorize.green("OK"));

				System.out.print("Verifing the credential...");
				boolean valid = vc.isValid();
				if (valid) {
					System.out.println(Colorize.green("Valid"));
				} else {
					System.out.println(Colorize.red("Invalid"));
					vc.isValid(getVerificationEventListener());
				}

				System.out.println("\nVerifiable credential:");
				PrintStream out = System.out;
				if (outputFile != null)
					out = new PrintStream(toFile(outputFile));

				printJson(out, compact, vc.serialize(true));

				if (outputFile != null)
					out.close();
			}
		}

		private void resolveVcBiography() throws DIDException, IOException {
			System.out.format("Resolving credential biography %s...", id);
			CredentialBiography bio = VerifiableCredential.resolveBiography(id);
			if (bio == null) {
				System.out.println(Colorize.red("NOT exists"));
			} else {
				System.out.println(Colorize.green("OK"));

				PrintStream out = System.out;
				if (outputFile != null)
					out = new PrintStream(toFile(outputFile));

				out.format("DID status: %s\n\n", bio.getStatus().toString());
				for (CredentialTransaction tx : bio.getAllTransactions()) {
					printJson(out, compact, tx.serialize(true));
					out.println();
				}

				if (outputFile != null)
					out.close();
			}
		}
	}

	@Command(name = "rlist", mixinStandardHelpOptions = true, version = "2.0",
			description = "List the credentials from the ID side chain.", sortOptions = false)
	public static class ListDeclared extends CommandBase implements Callable<Integer> {
		@Option(names = {"-v", "--verify"}, description = "Verify the credentials, default false.")
		private boolean verify = false;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DID", index = "0", defaultValue = "", description = "The owner DID to be list, default is self.")
		private String didstr;

		@Override
		public Integer call() {
			try {
				DID did;
				if (didstr.isEmpty()) {
					if (getActiveIdentity() == null) {
						System.out.println(Colorize.red("No active identity"));
						return -1;
					}

					did = getActiveDid();
				} else {
					did = toDid(didstr);
				}

				listCredentials(did);

				return 0;
			} catch(Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}

		private void listCredentials(DID did) throws DIDException {
			System.out.format("Resolving DID %s...", did);
			DIDDocument doc = did.resolve();
			if (doc == null) {
				System.out.format(Colorize.red("\rResolving DID %s...NOT exists.\n"), did);
			} else {
				System.out.format(Colorize.green("\rResolving DID %s...OK.\n"), did);
				System.out.println("Verifing the document...");
				boolean valid = doc.isValid();
				if (valid) {
					System.out.println(Colorize.green("Valid"));
				} else {
					System.out.println(Colorize.red("Invalid"));
					doc.isValid(getVerificationEventListener());
				}
			}

			System.out.println("\nDeclared credentials:");
			int total = 0;
			int limit = 64;
			while (true) {
				List<DIDURL> ids = VerifiableCredential.list(did, total, limit);
				if (ids == null)
					break;

				for (DIDURL id : ids) {
					System.out.print("  " + id);

					if (verify) {
						System.out.print("......");
						try {
							VerifiableCredential vc = VerifiableCredential.resolve(id);

							if (vc.isValid()) {
								System.out.println(Colorize.green("Valid"));
							} else {
								String error = null;
								if (!vc.isGenuine())
									error = "NOT Genuine";
								else if (!vc.isExpired())
									error = "Expired";
								else if (vc.isRevoked())
									error = "Revoked";

								System.out.println(Colorize.red(error));
							}
						} catch (DIDResolveException e) {
							System.out.println(Colorize.red("resolve error"));
						}
					} else {
						System.out.println();
					}
				}

				total += ids.size();
			}

			System.out.println("Total " + total + " credentials");
		}
	}

	@Command(name = "list", mixinStandardHelpOptions = true, version = "2.0",
			description = "List the local credentials.", sortOptions = false)
	public static class ListLocal extends CommandBase implements Callable<Integer> {
		@Option(names = {"-v", "--verify"}, description = "Verify the credentials, default false.")
		private boolean verify = false;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				DIDStore store = getActiveStore();
				List<DIDURL> ids = store.listCredentials(getActiveDid());

				System.out.format(Colorize.green("Total %d credentials\n"), ids.size());
				for (DIDURL id : ids) {
					System.out.print("  " + id);

					if (verify) {
						System.out.print("......");
						try {
							VerifiableCredential vc = VerifiableCredential.resolve(id);
							if (vc != null)
								System.out.print("Declared, ");

							vc = store.loadCredential(id);
							if (vc.isValid()) {
								System.out.println(Colorize.green("OK"));
							} else {
								String error = null;
								if (!vc.isGenuine())
									error = "NOT Genuine";
								else if (vc.isExpired())
									error = "Expired";
								else if (vc.isRevoked())
									error = "Revoked";

								System.out.println(Colorize.red(error));
							}
						} catch (DIDResolveException e) {
							System.out.println(Colorize.red("resolve error"));
						}
					} else {
						System.out.println();
					}
				}

				return 0;
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "verify", mixinStandardHelpOptions = true, version = "2.0",
			description = "Verify the verifiable credential.", sortOptions = false)
	public static class Verify extends CommandBase implements Callable<Integer> {
		@Option(names = {"-l", "--local"}, description = "Local DID resolve directory, default current directory.")
		private String localDir = null;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "VC", index = "0", description = "The credential filename.")
		private String credentialFile;

		@Override
		public Integer call() {
			try {
				if (localDir != null)
					setLocalResolveHandle(toFile(localDir));

				VerifiableCredential vc = VerifiableCredential.parse(toFile(credentialFile));
				System.out.println("Verifing the credenitial...");
				boolean valid = vc.isValid();
				if (valid) {
					System.out.println(Colorize.green("Valid"));
				} else {
					System.out.println(Colorize.red("Invalid"));
					vc.isValid(getVerificationEventListener());
				}

				return 0;
			} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			} finally {
				if (localDir != null)
					clearLocalResolveHandle();
			}
		}
	}
}
