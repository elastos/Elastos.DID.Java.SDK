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

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import org.elastos.did.DID;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.DIDURL;
import org.elastos.did.Issuer;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.backend.CredentialBiography;
import org.elastos.did.backend.CredentialTransaction;
import org.elastos.did.crypto.Base58;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDResolveException;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "vc", mixinStandardHelpOptions = true, version = Version.VERSION,
description = "Credential management commands.", subcommands = {
		Credentials.Resolve.class,
		Credentials.Show.class,
		Credentials.Issue.class,
		Credentials.ListLocal.class,
		Credentials.ListDeclared.class,
		Credentials.Delete.class,
		Credentials.Declare.class,
		Credentials.Revoke.class,
		Credentials.Verify.class
})
public class Credentials {
	@Command(name = "resolve", mixinStandardHelpOptions = true, version = Version.VERSION,
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

	@Command(name = "show", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Show the credential and metadata.", sortOptions = false)
	public static class Show extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DIDURL", index = "0", description = "The id of the credential to be show.")
		private String idString;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				DIDURL id = toDidUrl(idString);

				DIDStore store = getActiveStore();
				VerifiableCredential vc = store.loadCredential(id);
				if (vc != null) {
					System.out.println("Verifiable credential:");
					printJson(System.out, false, vc.serialize(true));

					System.out.println("\nMetadata:");
					printJson(System.out, false, vc.getMetadata().serialize());
				} else {
					System.out.format(Colorize.red("Credential %s not exists\n"), id);
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

	@Command(name = "issue", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Issue a credential.", sortOptions = false)
	public static class Issue extends CommandBase implements Callable<Integer> {
		@Option(names = {"-c", "--compact"}, description = "Output JSON in compact format, default false.")
		private boolean compact = false;

		@Option(names = {"-o", "--out"}, description = "Output file, default is STDOUT.")
		private String outputFile;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DID", index = "0", defaultValue = "", description = "The DID who the credential issue to, default is self.")
		private String didString;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				DID did = didString.isEmpty() ? getActiveDid() : toDid(didString);
				byte[] binId = new byte[16];
				new SecureRandom().nextBytes(binId);
				DIDURL id = new DIDURL(did, "#" + Base58.encode(binId));

				DIDStore store = getActiveStore();
				DIDDocument issuerDoc = store.loadDid(getActiveDid());
				boolean selfProclaimed = (did.equals(getActiveDid()));

				boolean saveToStore = selfProclaimed;
				if (!selfProclaimed) {
					List<DID> myDids = store.listDids();
					saveToStore = myDids.contains(did);
				}

				VerifiableCredential.Builder vb = new Issuer(issuerDoc).issueFor(did);
				vb.id(id);

				if (selfProclaimed)
					vb.type("https://ns.elastos.org/credentials/v1#SelfProclaimedCredential");

				String type = System.console().readLine("Types(comma separated URI list): ").trim();
				if (!type.isEmpty()) {
					String[] types = type.split("\\s*,\\s*");
					vb.types(types);
				}

				Map<String, Object> subject = readJson("Subject(JSON format): ");
				if (subject != null && !subject.isEmpty())
					vb.properties(subject);

				Date expiration = readExpirationDate();
				if (expiration != null)
					vb.expirationDate(expiration);

				VerifiableCredential vc = vb.seal(CommandContext.getPassword());
				System.out.print("Credential " + vc.getId() + " created.");

				if (saveToStore) {
					store.storeCredential(vc);
					System.out.println(" Saved to the store.");
				} else {
					System.out.println();
				}

				PrintStream out = System.out;
				if (outputFile != null) {
					File output = toFile(outputFile);
					out = new PrintStream(output);
				} else {
					System.out.println("\nCredential:");
				}

				printJson(out, compact, vc.serialize(true));

				if (outputFile != null)
					out.close();

				return 0;
			} catch(Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "rlist", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "List the credentials from the ID side chain.", sortOptions = false)
	public static class ListDeclared extends CommandBase implements Callable<Integer> {
		@Option(names = {"-v", "--verify"}, description = "Verify the credentials, default false.")
		private boolean verify = false;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DID", index = "0", defaultValue = "", description = "The owner DID to be list, default is self.")
		private String didString;

		@Override
		public Integer call() {
			try {
				DID did;
				if (didString.isEmpty()) {
					if (getActiveIdentity() == null) {
						System.out.println(Colorize.red("No active identity"));
						return -1;
					}

					did = getActiveDid();
				} else {
					did = toDid(didString);
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

	@Command(name = "list", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "List the local credentials.", sortOptions = false)
	public static class ListLocal extends CommandBase implements Callable<Integer> {
		@Option(names = {"-v", "--verify"}, description = "Verify the credentials, default false.")
		private boolean verify = false;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DID", index = "0", defaultValue = "", description = "The owner DID to be list, default is self.")
		private String didString;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				DID did = didString.isEmpty() ? getActiveDid() : toDid(didString);

				DIDStore store = getActiveStore();
				List<DIDURL> ids = store.listCredentials(did);

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

	@Command(name = "delete", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Delete the credential.", sortOptions = false)
	public static class Delete extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DIDURL", index = "0", description = "The id of the credential to be show.")
		private String idString;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				DIDURL id = toDidUrl(idString);

				DIDStore store = getActiveStore();
				boolean deleted = store.deleteCredential(id);
				if (deleted)
					System.out.format("Credential %s deleted\n", id);
				else
					System.out.format(Colorize.red("Credential %s not exists\n"), id);

				return 0;
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "declare", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Declare the credential.", sortOptions = false)
	public static class Declare extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DIDURL", index = "0", description = "The id of the credential to be show.")
		private String idString;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				DIDURL id = toDidUrl(idString);
				if (VerifiableCredential.resolve(id) != null) {
					System.out.println(Colorize.yellow("Credential " + id + " already declared"));
					return -1;
				}

				DIDStore store = getActiveStore();
				VerifiableCredential vc = store.loadCredential(id);
				if (vc != null) {
					String password = CommandContext.getPassword();

					System.out.format("Declaring credential %s...", id);
					vc.declare(password);
					System.out.println(Colorize.green("Success"));
				} else {
					System.out.format(Colorize.red("Credential %s not exists\n"), id);
				}
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}

			return 0;
		}
	}

	@Command(name = "revoke", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Revoke the credential.", sortOptions = false)
	public static class Revoke extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DIDURL", index = "0", description = "The id of the credential to be show.")
		private String idString;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				DIDURL id = toDidUrl(idString);

				DIDStore store = getActiveStore();
				DID did = getActiveDid();
				DIDDocument signer = store.loadDid(did);

				VerifiableCredential vc = VerifiableCredential.resolve(id);
				if (vc == null)
					vc = store.loadCredential(id);

				if (vc != null) {
					if (vc.isRevoked()) {
						System.out.println(Colorize.yellow("Credential " + id + " already revoked."));
						return -1;
					}

					if (!vc.getIssuer().equals(did) && !vc.getSubject().getId().equals(did)) {
						System.out.println(Colorize.red("No rights to revoke credential " + id));
						return -1;
					}
				}

				String password = CommandContext.getPassword();

				System.out.format("Revoking credential %s...", id);
				if (vc != null)
					vc.revoke(signer, (DIDURL)null, password);
				else
					VerifiableCredential.revoke(id, signer, password);

				System.out.println(Colorize.green("Success"));

				return 0;
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "verify", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Verify the credential.", sortOptions = false)
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
