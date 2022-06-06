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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.concurrent.Callable;

import org.elastos.did.Constants;
import org.elastos.did.DID;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.DIDURL;
import org.elastos.did.RootIdentity;
import org.elastos.did.TransferTicket;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.backend.DIDBiography;
import org.elastos.did.backend.DIDTransaction;
import org.elastos.did.crypto.Base58;
import org.elastos.did.crypto.HDKey;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.WrongPasswordException;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "did", mixinStandardHelpOptions = true, version = Version.VERSION,
description = "DID management commands.", subcommands = {
		DIDs.Switch.class,
		DIDs.Resolve.class,
		DIDs.Show.class,
		DIDs.Create.class,
		DIDs.CreateAppDid.class,
		DIDs.Edit.class,
		DIDs.CreateCustomizedDid.class,
		DIDs.AcquireCustomizedDid.class,
		DIDs.TransferCustomizedDid.class,
		DIDs.List.class,
		DIDs.Delete.class,
		DIDs.Publish.class,
		DIDs.Renew.class,
		DIDs.Export.class,
		DIDs.Synchronize.class,
		DIDs.Deactivate.class,
		DIDs.Verify.class
})
public class DIDs extends CommandBase implements Callable<Integer> {
    @Override
    public Integer call() {
    	try {
    		DID did = getActiveDid();
    		if (did != null)
    			System.out.println("Active DID: " + Colorize.green(did.toString()));
    		else
    			System.out.println("No active DID.");

    			return 0;
		} catch (Exception e) {
			System.err.println(Colorize.red("Error: " + e.getMessage()));
			return -1;
		}
    }

	@Command(name = "switch", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Switch the active DID.", sortOptions = false)
	public static class Switch extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DID", index = "0", description = "The DID to be active.")
		private String didString;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				DID did = toDid(didString);
				if (did.equals(getActiveDid())) {
					System.out.println(did + " is already active DID.");
					return 0;
				}

				if (!getActiveStore().containsDid(did)) {
					System.out.println(Colorize.red("DID " + did + " not exists."));
					return -1;
				}

				getActiveRootIdentity().setDefaultDid(did);
				System.out.println("Switched to the DID: " + Colorize.green(did.toString()));

				return 0;
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "resolve", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Resolve DID from the ID side chain.", sortOptions = false)
	public static class Resolve extends CommandBase implements Callable<Integer> {
		@Option(names = {"-f", "--force"}, description = "Resolve froced from ID sidechain, default false.")
		private boolean force = false;

		@Option(names = {"-b", "--biography"}, description = "Resolve DID biography from ID sidechain.")
		private boolean biography = false;

		@Option(names = {"-l", "--local"}, description = "Local DID resolve directory, default current directory.")
		private String localDir = null;

		@Option(names = {"-c", "--compact"}, description = "Output JSON in compact format, default false.")
		private boolean compact = false;

		@Option(names = {"-o", "--out"}, description = "Output file, default is STDOUT.")
		private String outputFile;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DID", index = "0", description = "The DID to be resolve.")
		private String didString;

		private DID did;

		@Override
		public Integer call() {
			try {
				if (localDir != null)
					setLocalResolveHandle(toFile(localDir));

				did = toDid(didString);

				if (biography)
					resolveBiography();
				else
					resolveDid();

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

		private void resolveDid() throws DIDException, IOException {
			System.out.format("Resolving DID %s...", did);
			DIDDocument doc = did.resolve(force);
			if (doc == null) {
				System.out.println(Colorize.red("NOT exists"));
			} else {
				System.out.println(Colorize.green("OK"));

				System.out.print("Verifing the document...");
				boolean valid = doc.isValid();
				if (valid) {
					System.out.println(Colorize.green("Valid"));
				} else {
					System.out.println(Colorize.red("Invalid"));
					doc.isValid(getVerificationEventListener());
				}

				PrintStream out = System.out;
				if (outputFile != null) {
					File output = toFile(outputFile);
					out = new PrintStream(output);
				} else {
					System.out.println("\nDID document:");
				}

				printJson(out, compact, doc.serialize(true));

				if (outputFile != null)
					out.close();
			}
		}

		private void resolveBiography() throws DIDException, IOException {
			System.out.format("Resolving DID biography %s...", did);
			DIDBiography bio = did.resolveBiography();
			if (bio == null) {
				System.out.println(Colorize.red("NOT exists"));
			} else {
				System.out.println(Colorize.green("OK"));

				PrintStream out = System.out;
				if (outputFile != null)
					out = new PrintStream(toFile(outputFile));

				out.format("DID status: %s\n\n", bio.getStatus().toString());
				for (DIDTransaction tx : bio.getAllTransactions()) {
					printJson(out, compact, tx.serialize(true));
					out.println();
				}

				if (outputFile != null)
					out.close();
			}
		}
	}

	@Command(name = "create", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Create a new DID.", sortOptions = false)
	public static class Create extends CommandBase implements Callable<Integer> {
		@Option(names = {"-i", "--index"}, description = "Create new DID with the index, default next available index.")
		private int index = -1;

		@Option(names = {"-f", "--force"}, description = "Overwrite the existing.")
		private boolean force = false;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				RootIdentity id = getActiveStore().loadRootIdentity();
				if (id == null) {
					System.out.println(Colorize.red("Store not contains the default root identity"));
					return -1;
				}

				DIDDocument doc;
				String password = CommandContext.getPassword();
				if (index >= 0)
					doc = id.newDid(index, force, password);
				else
					doc = id.newDid(force, password);

				System.out.println("DID " + doc.getSubject() + " created.\n");
				System.out.println("DID document:");
				printJson(System.out, false, doc.serialize(true));

				return 0;
			} catch (Exception e) {
				if (e instanceof WrongPasswordException)
					CommandContext.clearPassword();

				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "createappdid", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Create a new application DID.", sortOptions = false)
	public static class CreateAppDid extends CommandBase implements Callable<Integer> {
		@Option(names = {"-f", "--force"}, description = "Overwrite the existing.")
		private boolean force = false;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "APPID", index = "0", description = "The app' identity.")
		private String appId;

		@Parameters(paramLabel = "CODE", index = "1", description = "The security code for the DID.")
		private int appCode;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				RootIdentity id = getActiveStore().loadRootIdentity();
				if (id == null) {
					System.out.println(Colorize.red("Store not contains the default root identity"));
					return -1;
				}

				DIDDocument doc;
				String password = CommandContext.getPassword();
				doc = id.newDid(appId, appCode, force, password);

				System.out.println("DID " + doc.getSubject() + " created.\n");
				System.out.println("DID document:");
				printJson(System.out, false, doc.serialize(true));

				return 0;
			} catch (Exception e) {
				if (e instanceof WrongPasswordException)
					CommandContext.clearPassword();

				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "edit", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Modify the DID document.", subcommands = {
					Edit.PublicKeys.class,
					Edit.Services.class,
					Edit.Credentials.class
			})
	public static class Edit extends CommandBase {
		@Command(name = "pk", mixinStandardHelpOptions = true, version = Version.VERSION,
				description = "Update public keys.", subcommands = {
						PublicKeys.Add.class,
						PublicKeys.Remove.class
				})
		public static class PublicKeys extends CommandBase {
			@Command(name = "add", mixinStandardHelpOptions = true, version = Version.VERSION,
					description = "Add a new public key.", sortOptions = false)
			public static class Add extends CommandBase implements Callable<Integer> {
				@Option(names = {"-i", "--id"}, description = "Public key id, default use random.")
				private String id = null;

				@Option(names = {"-t", "--type"}, description = "Public key type, default is ECDSAsecp256r1.")
				private String type = Constants.DEFAULT_PUBLICKEY_TYPE;

				@Option(names = {"-c", "--controller"}, description = "Public key contoller, default is self.")
				private String controller = null;

				@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
				private boolean verboseErrors = false;

				@Parameters(paramLabel = "PK", index = "0", defaultValue = "", description = "The public key base58 string.")
				private String pk;

				@Override
				public Integer call() {
					try {
						if (getActiveIdentity() == null) {
							System.out.println(Colorize.red("No active identity"));
							return -1;
						}

						DID did = getActiveDid();

						if (id == null) {
							byte[] binId = new byte[16];
							new SecureRandom().nextBytes(binId);
							id = "#" + Base58.encode(binId);
						}

						DIDURL pkId = toDidUrl(did, id);
						DID pkController = controller != null ? toDid(controller) : did;

						DIDStore store = getActiveStore();
						DIDDocument doc = store.loadDid(did);

						String password = CommandContext.getPassword();

						byte[] sk = null;
						if (pk.isEmpty()) {
							HDKey key = HDKey.deserializeBase58(doc.derive(id, 0, password));
							pk = key.getPublicKeyBase58();
							sk = key.serialize();
						}

						DIDDocument.Builder db = doc.edit();

						db.addPublicKey(pkId, type, pkController, pk);
						if (pkController.equals(did))
							db.addAuthenticationKey(pkId);
						else
							db.addAuthorizationKey(pkId);

						doc = db.seal(password);

						store.storePrivateKey(pkId, sk, password);
						store.storeDid(doc);

						return 0;
					} catch (Exception e) {
						if (e instanceof WrongPasswordException)
							CommandContext.clearPassword();

						System.err.println(Colorize.red("Error: " + e.getMessage()));
						if (verboseErrors)
							e.printStackTrace(System.err);

						return -1;
					}
				}
			}

			@Command(name = "remove", mixinStandardHelpOptions = true, version = Version.VERSION,
					description = "Remove a public key.", sortOptions = false)
			public static class Remove extends CommandBase implements Callable<Integer> {
				@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
				private boolean verboseErrors = false;

				@Parameters(paramLabel = "ID", index = "0", description = "The public key id.")
				private String id;

				@Override
				public Integer call() {
					try {
						if (getActiveIdentity() == null) {
							System.out.println(Colorize.red("No active identity"));
							return -1;
						}

						DID did = getActiveDid();
						DIDURL pkId = toDidUrl(did, id);

						DIDStore store = getActiveStore();
						DIDDocument doc = store.loadDid(did);

						DIDDocument.Builder db = doc.edit();
						db.removePublicKey(pkId, true);

						String password = CommandContext.getPassword();
						doc = db.seal(password);

						store.storeDid(doc);

						return 0;
					} catch (Exception e) {
						if (e instanceof WrongPasswordException)
							CommandContext.clearPassword();

						System.err.println(Colorize.red("Error: " + e.getMessage()));
						if (verboseErrors)
							e.printStackTrace(System.err);

						return -1;
					}
				}
			}
		}

		@Command(name = "svc", mixinStandardHelpOptions = true, version = Version.VERSION,
				description = "Update services.", subcommands = {
						Services.Add.class,
						Services.Remove.class
				})
		public static class Services extends CommandBase {
			@Command(name = "add", mixinStandardHelpOptions = true, version = Version.VERSION,
					description = "Add a new service.", sortOptions = false)
			public static class Add extends CommandBase implements Callable<Integer> {
				@Option(names = {"-i", "--id"}, description = "Service id, default use random.")
				private String id = null;

				@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
				private boolean verboseErrors = false;

				@Parameters(paramLabel = "TYPE", index = "0", description = "The service type.")
				private String type;

				@Parameters(paramLabel = "ENDPOINT", index = "1", description = "The service endpoint.")
				private String endpoint;

				@Override
				public Integer call() {
					try {
						if (getActiveIdentity() == null) {
							System.out.println(Colorize.red("No active identity"));
							return -1;
						}

						DID did = getActiveDid();

						if (id == null) {
							byte[] binId = new byte[16];
							new SecureRandom().nextBytes(binId);
							id = "#" + Base58.encode(binId);
						}

						DIDURL svcId = toDidUrl(did, id);

						DIDStore store = getActiveStore();
						DIDDocument doc = store.loadDid(did);

						DIDDocument.Builder db = doc.edit();
						db.addService(svcId, type, endpoint);

						String password = CommandContext.getPassword();
						doc = db.seal(password);

						store.storeDid(doc);

						return 0;
					} catch (Exception e) {
						if (e instanceof WrongPasswordException)
							CommandContext.clearPassword();

						System.err.println(Colorize.red("Error: " + e.getMessage()));
						if (verboseErrors)
							e.printStackTrace(System.err);

						return -1;
					}
				}
			}

			@Command(name = "remove", mixinStandardHelpOptions = true, version = Version.VERSION,
					description = "Remove a service.", sortOptions = false)
			public static class Remove extends CommandBase implements Callable<Integer> {
				@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
				private boolean verboseErrors = false;

				@Parameters(paramLabel = "ID", index = "0", description = "The service id.")
				private String id;

				@Override
				public Integer call() {
					try {
						if (getActiveIdentity() == null) {
							System.out.println(Colorize.red("No active identity"));
							return -1;
						}

						DID did = getActiveDid();
						DIDURL svcId = toDidUrl(did, id);

						DIDStore store = getActiveStore();
						DIDDocument doc = store.loadDid(did);

						DIDDocument.Builder db = doc.edit();
						db.removeService(svcId);

						String password = CommandContext.getPassword();
						doc = db.seal(password);

						store.storeDid(doc);

						return 0;
					} catch (Exception e) {
						if (e instanceof WrongPasswordException)
							CommandContext.clearPassword();

						System.err.println(Colorize.red("Error: " + e.getMessage()));
						if (verboseErrors)
							e.printStackTrace(System.err);

						return -1;
					}
				}
			}
		}

		@Command(name = "vc", mixinStandardHelpOptions = true, version = Version.VERSION,
				description = "Update credentials.", subcommands = {
						Credentials.Add.class,
						Credentials.Remove.class
				})
		public static class Credentials extends CommandBase {
			@Command(name = "add", mixinStandardHelpOptions = true, version = Version.VERSION,
					description = "Add a new embedded credential.", sortOptions = false)
			public static class Add extends CommandBase implements Callable<Integer> {
				@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
				private boolean verboseErrors = false;

				@Parameters(paramLabel = "ID", index = "0", description = "The existing credential id.")
				private String id;

				@Override
				public Integer call() {
					try {
						if (getActiveIdentity() == null) {
							System.out.println(Colorize.red("No active identity"));
							return -1;
						}

						DID did = getActiveDid();

						DIDURL vcId = toDidUrl(did, id);

						DIDStore store = getActiveStore();

						VerifiableCredential vc = store.loadCredential(vcId);
						if (vc == null) {
							System.out.println(Colorize.red("Credenital " + vcId + " not exists."));
							return -1;
						}

						DIDDocument doc = store.loadDid(did);

						DIDDocument.Builder db = doc.edit();
						db.addCredential(vc);

						String password = CommandContext.getPassword();
						doc = db.seal(password);

						store.storeDid(doc);

						return 0;
					} catch (Exception e) {
						if (e instanceof WrongPasswordException)
							CommandContext.clearPassword();

						System.err.println(Colorize.red("Error: " + e.getMessage()));
						if (verboseErrors)
							e.printStackTrace(System.err);

						return -1;
					}
				}
			}

			@Command(name = "remove", mixinStandardHelpOptions = true, version = Version.VERSION,
					description = "Remove an embedded credential.", sortOptions = false)
			public static class Remove extends CommandBase implements Callable<Integer> {
				@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
				private boolean verboseErrors = false;

				@Parameters(paramLabel = "ID", index = "0", description = "The credential id.")
				private String id;

				@Override
				public Integer call() {
					try {
						if (getActiveIdentity() == null) {
							System.out.println(Colorize.red("No active identity"));
							return -1;
						}

						DID did = getActiveDid();
						DIDURL vcId = toDidUrl(did, id);

						DIDStore store = getActiveStore();
						DIDDocument doc = store.loadDid(did);

						DIDDocument.Builder db = doc.edit();
						db.removeCredential(vcId);

						String password = CommandContext.getPassword();
						doc = db.seal(password);

						store.storeDid(doc);

						return 0;
					} catch (Exception e) {
						if (e instanceof WrongPasswordException)
							CommandContext.clearPassword();

						System.err.println(Colorize.red("Error: " + e.getMessage()));
						if (verboseErrors)
							e.printStackTrace(System.err);

						return -1;
					}
				}
			}
		}
	}


	@Command(name = "createcid", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Create a new customized DID.", sortOptions = false)
	public static class CreateCustomizedDid extends CommandBase implements Callable<Integer> {
		@Option(names = {"-f", "--force"}, description = "Overwrite the existing.")
		private boolean force = false;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DID", index = "0", description = "The DID to be show.")
		private String didString;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				DID cid = toDid(didString);

				DIDStore store = getActiveStore();
				RootIdentity id = store.loadRootIdentity();
				if (id == null) {
					System.out.println(Colorize.red("Store not contains the default root identity"));
					return -1;
				}

				DIDDocument doc = store.loadDid(id.getDefaultDid());
				if (doc.isCustomizedDid()) {
					System.out.println(Colorize.red("Current active DID " + doc.getSubject() + " is a customized DID, should be primitive DID."));
					return -1;
				}

				String password = CommandContext.getPassword();
				DIDDocument newDoc = doc.newCustomizedDid(cid, force, password);

				System.out.println("DID " + newDoc.getSubject() + " created.");
				System.out.println("\nDID document:");
				printJson(System.out, false, newDoc.serialize(true));

				return 0;
			} catch (Exception e) {
				if (e instanceof WrongPasswordException)
					CommandContext.clearPassword();

				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "acquirecid", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Acquire a customized DID.", sortOptions = false)
	public static class AcquireCustomizedDid extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DID", index = "0", description = "The DID to be acquire.")
		private String didString;

		@Parameters(paramLabel = "TICKET", index = "1", description = "The transfer ticke file.")
		private String ticketFile;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				DID cid = toDid(didString);

				TransferTicket ticket = TransferTicket.parse(toFile(ticketFile));
				if (!ticket.getSubject().equals(cid)) {
					System.out.println(Colorize.red("The transfer ticket not matched with DID " + cid));
					return -1;
				}

				DIDStore store = getActiveStore();
				RootIdentity id = store.loadRootIdentity();
				if (id == null) {
					System.out.println(Colorize.red("Store not contains the default root identity"));
					return -1;
				}

				DIDDocument doc = store.loadDid(id.getDefaultDid());
				if (doc.isCustomizedDid()) {
					System.out.println(Colorize.red("Current active DID " + doc.getSubject() + " is a customized DID, should be primitive DID."));
					return -1;
				}

				String password = CommandContext.getPassword();
				DIDDocument newDoc = doc.newCustomizedDid(cid, true, password);
				newDoc.publish(ticket, password);

				System.out.println("DID " + newDoc.getSubject() + " created and acquire.");
				System.out.println("\nDID document:");
				printJson(System.out, false, newDoc.serialize(true));

				return 0;
			} catch (Exception e) {
				if (e instanceof WrongPasswordException)
					CommandContext.clearPassword();

				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "transfercid", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Transfer the customized DID.", sortOptions = false)
	public static class TransferCustomizedDid extends CommandBase implements Callable<Integer> {
		@Option(names = {"-o", "--out"}, description = "Output file, default is STDOUT.")
		private String outputFile;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DID", index = "0", description = "The DID to be transfer.")
		private String didString;

		@Parameters(paramLabel = "RECIPIENT", index = "1", description = "The recipient DID.")
		private String recipient;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				DID customizedDid = toDid(didString);
				DID recipientDid = toDid(recipient);

				DIDStore store = getActiveStore();
				RootIdentity id = getActiveRootIdentity();
				if (id == null) {
					System.out.println(Colorize.red("Store not contains the default root identity"));
					return -1;
				}

				DIDDocument doc = store.loadDid(id.getDefaultDid());
				if (doc.isCustomizedDid()) {
					System.out.println(Colorize.red("Current active DID " + doc.getSubject() + " is a customized DID, should be primitive DID."));
					return -1;
				}

				DIDDocument customizedDoc = customizedDid.resolve();
				if (customizedDoc == null) {
					System.out.println(Colorize.red("DID " + customizedDid + " is not published."));
					return -1;
				}

				if (!customizedDoc.isCustomizedDid()) {
					System.out.println(Colorize.red("DID " + customizedDid + " is not a customized DID."));
					return -1;
				}

				if (!customizedDoc.hasController(doc.getSubject())) {
					System.out.println(Colorize.red("Active DID " + doc.getSubject() + " is not the owner of DID " + customizedDid));
					return -1;
				}

				DIDDocument recipientDoc = recipientDid.resolve();
				if (recipientDoc != null && recipientDoc.isCustomizedDid()) {
					System.out.println(Colorize.red("The recipient DID " + recipientDid + " should be a primitive DID."));
					return -1;
				}

				store.storeDid(customizedDoc);
				customizedDoc.setEffectiveController(doc.getSubject());

				String password = CommandContext.getPassword();
				TransferTicket ticket = customizedDoc.createTransferTicket(recipientDid, password);

				System.out.println(Colorize.green("Transfer ticket created."));

				PrintStream out = System.out;
				if (outputFile != null) {
					File output = toFile(outputFile);
					out = new PrintStream(output);
				} else {
					System.out.println("\nTransfer ticket:");
				}

				printJson(out, true, ticket.serialize(true));

				if (outputFile != null)
					out.close();

				return 0;
			} catch (Exception e) {
				if (e instanceof WrongPasswordException)
					CommandContext.clearPassword();

				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "show", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Show the DID document and metadata.", sortOptions = false)
	public static class Show extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DID", index = "0", defaultValue = "", description = "The DID to be show.")
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
				DIDDocument doc = store.loadDid(did);
				if (doc != null) {
					System.out.println("DID document:");
					printJson(System.out, false, doc.serialize(true));

					System.out.println("\nDID Metadata:");
					printJson(System.out, false, doc.getMetadata().serialize());
				} else {
					System.out.format(Colorize.red("DID %s not exists\n"), did);
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

	@Command(name = "list", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "List the DIDs.", sortOptions = false)
	public static class List extends CommandBase implements Callable<Integer> {
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
				java.util.List<DID> dids = store.listDids();

				DID activeDid = getActiveDid();

				System.out.format("Total %d DIDs\n", dids.size());
				for (DID did : dids) {
					System.out.print(" " + (did.equals(activeDid) ? Colorize.green("*") : " ") + did);

					if (verify) {
						System.out.print("......");
						try {
							DIDDocument doc = did.resolve();
							if (doc != null)
								System.out.print("Published, ");

							doc = store.loadDid(did);
							if (doc.isValid()) {
								System.out.println(Colorize.green("Valid"));
							} else {
								String error = null;
								if (!doc.isGenuine())
									error = "NOT Genuine";
								else if (doc.isExpired())
									error = "Expired";
								else if (doc.isDeactivated())
									error = "Deactivated";

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
			description = "Delete the DID.", sortOptions = false)
	public static class Delete extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DID", index = "0", description = "The DID to be delete.")
		private String didString;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				DID did = toDid(didString);
				if (did.equals(getActiveDid())) {
					System.out.println(Colorize.red("Can not delete the current active DID"));
					return -1;
				}

				DIDStore store = getActiveStore();
				boolean deleted = store.deleteDid(did);
				if (deleted)
					System.out.format("DID %s deleted\n", did);
				else
					System.out.format(Colorize.red("DID %s not exists\n"), did);

				return 0;
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "publish", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Publish the DID.", sortOptions = false)
	public static class Publish extends CommandBase implements Callable<Integer> {
		@Option(names = {"-f", "--force"}, description = "Publish in force mode.")
		private boolean force = false;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DID", index = "0", defaultValue = "", description = "The DID to be publish, default is active DID.")
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
				DIDDocument doc = store.loadDid(did);
				if (doc != null) {
					String password = CommandContext.getPassword();

					System.out.format("Publishing DID %s...", did);
					doc.publish(doc.getDefaultPublicKeyId(), force, password);
					System.out.println(Colorize.green("Success"));
				} else {
					System.out.format(Colorize.red("DID %s not exists\n"), did);
				}
			} catch (Exception e) {
				if (e instanceof WrongPasswordException)
					CommandContext.clearPassword();

				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}

			return 0;
		}
	}

	@Command(name = "renew", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Renew the DID.", sortOptions = false)
	public static class Renew extends CommandBase implements Callable<Integer> {
		private static final String DATETIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss";

		@Option(names = {"-p", "--expiration"}, description = "expiration date time(yyyy-MM-ddTHH:mm:ss).")
		private String expiration = null;

		@Option(names = {"-f", "--force"}, description = "Publish in force mode.")
		private boolean force = false;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DID", index = "0", defaultValue = "", description = "The DID to be show.")
		private String didString;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				Date exp = null;
				if (expiration != null) {
					SimpleDateFormat dateFormat = new SimpleDateFormat(DATETIME_FORMAT);
					dateFormat.setTimeZone(Constants.UTC);
					try {
						exp = dateFormat.parse(expiration);
					} catch (ParseException e) {
						System.out.println(Colorize.red("Invalid expiration datetime, the format should be: " + DATETIME_FORMAT));
						return -1;
					}
				}

				DID did = didString.isEmpty() ? getActiveDid() : toDid(didString);

				DIDStore store = getActiveStore();
				DIDDocument doc = store.loadDid(did);
				if (doc != null) {
					String password = CommandContext.getPassword();

					DIDDocument.Builder db = doc.edit();
					if (exp == null)
						exp = readDate("Expiration date");

					if (exp == null)
						db.setDefaultExpires();
					else
						db.setExpires(exp);

					doc = db.seal(password);

					store.storeDid(doc);

					System.out.format("Renew DID %s...", did);
					doc.publish(doc.getDefaultPublicKeyId(), force, password);
					System.out.println(Colorize.green("Success"));
				} else {
					System.out.format(Colorize.red("DID %s not exists\n"), did);
				}
			} catch (Exception e) {
				if (e instanceof WrongPasswordException)
					CommandContext.clearPassword();

				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}

			return 0;
		}
	}

	@Command(name = "deactivate", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Deactivate the DID.", sortOptions = false)
	public static class Deactivate extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DID", index = "0", defaultValue = "", description = "The DID to be show.")
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
				DIDDocument doc = store.loadDid(did);
				if (doc != null) {
					String password = CommandContext.getPassword();

					System.out.format("Deactivate DID %s...", did);
					doc.deactivate(password);
					System.out.println(Colorize.green("Success"));
				} else {
					System.out.format(Colorize.red("DID %s not exists\n"), did);
				}
			} catch (Exception e) {
				if (e instanceof WrongPasswordException)
					CommandContext.clearPassword();

				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}

			return 0;
		}
	}

	@Command(name = "export", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Export the DID.", sortOptions = false)
	public static class Export extends CommandBase implements Callable<Integer> {
		@Option(names = {"-o", "--out"}, description = "Output file, default is STDOUT.")
		private String outputFile;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DID", index = "0", defaultValue = "", description = "The DID to be show.")
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
				if (!store.containsDid(did)) {
					System.out.format(Colorize.red("DID %s not exists\n"), did);
					return -1;
				}

				String exportPassword;
				while (true) {
					exportPassword = new String(System.console().readPassword("Export password: "));
					if (exportPassword.isEmpty())
						System.out.println(Colorize.yellow("Password can not be empty."));
					else
						break;
				}
				String exportPassword2 = new String(System.console().readPassword("Confirm export password: "));
				if (!exportPassword2.equalsIgnoreCase(exportPassword)) {
					System.out.println(Colorize.red("Password mismatch."));
					return -1;
				}

				String password = CommandContext.getPassword();

				PrintStream out = System.out;
				if (outputFile != null) {
					File output = toFile(outputFile);
					out = new PrintStream(output);
				} else {
					System.out.println("\nExported JSON:");
				}

				store.exportDid(did, out, exportPassword, password);

				if (outputFile != null)
					out.close();
				else
					System.out.println();

				return 0;
			} catch (Exception e) {
				if (e instanceof WrongPasswordException)
					CommandContext.clearPassword();

				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "sync", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Synchronize DID.", sortOptions = false)
	public static class Synchronize extends CommandBase implements Callable<Integer> {
		@Option(names = {"-m", "--merge"}, defaultValue = "interactive", description = "How to merge the conflict: chain, local, interactive. default: interactive.")
		private String merge = null;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DID", index = "0", defaultValue = "", description = "The DID to be show.")
		private String didString;

		private static final int INTERACTIVE = 0;
		private static final int CHAIN = 1;
		private static final int LOCAL = 2;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				int mode = INTERACTIVE;
				if (merge != null) {
					switch (merge.toLowerCase()) {
					case "chain":
						mode = CHAIN;
						break;
					case "local":
						mode = LOCAL;
						break;
					case "interactive":
						mode = INTERACTIVE;
						break;
					default:
						System.out.println(Colorize.red("Unknown merge mode: " + merge));
						return -1;
					}
				}

				DID did = didString.isEmpty() ? getActiveDid() : toDid(didString);
				DIDStore store = getActiveStore();

				System.out.println("Synchronizing......");
				final int mergeMode = mode;
				store.synchronize(did, (chainCopy, localCopy) -> {
					DIDDocument keep = null;

					switch (mergeMode) {
					case CHAIN:
						keep = chainCopy;
						break;
					case LOCAL:
						keep = localCopy;
						break;
					default:
						SimpleDateFormat df = new SimpleDateFormat(Constants.DATE_FORMAT);
						System.out.format("DID %s conflict. Chain copy: %s, local copy: %s\n",
								chainCopy.getSubject(), df.format(chainCopy.getLastModified()),
								df.format(localCopy.getLastModified()));
						while (true) {
							String answer = System.console().readLine("Which copy do you want keep, (C)hain copy or (L)ocal copy? ");

							if (answer.equalsIgnoreCase("c") || answer.equalsIgnoreCase("chain")) {
								keep = chainCopy;
								break;
							} else if (answer.equalsIgnoreCase("l") || answer.equalsIgnoreCase("local")) {
								keep = localCopy;
								break;
							} else {
								System.out.println("Invalid selection.");
							}
						}
					}

					return keep;
				});

				System.out.println("Finish synchronize.\n");
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
			description = "Verify the DID document.", sortOptions = false)
	public static class Verify extends CommandBase implements Callable<Integer> {
		@Option(names = {"-f", "--force"}, description = "Resolve froced from ID sidechain, default false.")
		private boolean force = false;

		@Option(names = {"-l", "--local"}, description = "Local DID resolve directory, default current directory.")
		private String localDir = null;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "DOCUMENT", index = "0", description = "The DID document filename.")
		private String documentFile;

		@Override
		public Integer call() {
			try {
				if (localDir != null)
					setLocalResolveHandle(toFile(localDir));

				DIDDocument doc = DIDDocument.parse(toFile(documentFile));
				System.out.print("Verifing the document...");
				boolean valid = doc.isValid();
				if (valid) {
					System.out.println(Colorize.green("Valid"));
				} else {
					System.out.println(Colorize.red("Invalid"));
					doc.isValid(getVerificationEventListener());
				}

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
	}

	@Command(name = "registernames", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Register resolved names.", sortOptions = false)
	public static class RegisterNames extends CommandBase implements Callable<Integer> {
		@Option(names = {"-p", "--password"}, required = true, description = "Password for the DID store")
		private String password = null;

		@Option(names = {"-l", "--name-list"}, required = true, description = "Name list file")
		private String nameListFile = null;

		@Option(names = {"-f", "--name-suffix"}, description = "Name suffix for testing, default is current time, 0 to turn off the suffix")
		private String nameSuffix = String.valueOf(System.currentTimeMillis());

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		private static int MAX_RESOLVE_RETRY = 24;

		private DIDDocument ownerDoc;

		@Override
		public Integer call() {
			if (getActiveIdentity() == null) {
				System.out.println(Colorize.red("No active identity"));
				return -1;
			}

			// fix the naming
			if (nameSuffix.equals("0"))
				nameSuffix = null;

			try {
				// Load the name list
				ArrayList<String> names = loadNames(toFile(nameListFile));
				if (names.isEmpty()) {
					System.out.println(Colorize.yellow("The name list file is empty."));
					return 0;
				}

				DIDStore store = getActiveStore();

				DID ownerDid = getActiveDid();
				ownerDoc = store.loadDid(ownerDid);

				Web3Adapter adapter = getActiveDidAdapter();
				adapter.setBatchMode(true);

				// Create DIDs
				for (String name : names)
					createCustomizedDid(name);

				adapter.commit();

				// check the last DID
				System.out.println("\nChecking for the regitered DIDs...\n");

				// Check and show the status
				for (String name : names)
					checkCustomizedDid(name);

				return 0;
			} catch (DIDException | IOException e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}

		private ArrayList<String> loadNames(File file) throws IOException {
			ArrayList<String> names = new ArrayList<>(2048);

			try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
				String name;
				while ((name = reader.readLine()) != null) {
					if (name.trim().isEmpty())
						continue;

					if (names.contains(name))
						continue;

					// Add time suffix padding for the names when run in testing mode
					if (nameSuffix != null)
						name = name + nameSuffix;

					names.add(name);
				}
			}

			return names;
		}

		private void createCustomizedDid(String name) {
			DID did = new DID("did:elastos:" + name);

			try {
				/*
				System.out.print("Checking DID " + did + "...");
				DIDDocument resolved = did.resolve();
				if (resolved != null) {
					if (resolved.getControllerCount() == 1 && resolved.hasController(ownerDoc.getSubject()))
						System.out.println(Colorize.green("exists"));
					else
						System.out.println(Colorize.yellow("exists(not owned)"));

					return;
				} else {
					System.out.println("to be create");
				}
				*/

				System.out.print("Creating DID " + did + "...");

				DIDDocument doc = ownerDoc.newCustomizedDid(did, true, password);

				// Update the expires: now + 3 month
				/*
				Calendar cal = Calendar.getInstance(Constants.UTC);
				cal.add(Calendar.MONTH, 3);
				Date expires = cal.getTime();

				DIDDocument.Builder db = doc.edit();
				db.setExpires(expires);
				doc = db.seal(password);
				store.storeDid(doc);
				*/

				doc.publish(password);

				System.out.println(Colorize.green("OK"));
			} catch (Exception e) {
				System.out.println(Colorize.red("ERROR: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);
			}
		}

		private void checkCustomizedDid(String name) {
			DID did = new DID("did:elastos:" + name);
			System.out.print("Checking DID " + did + "...");

			int maxRetry = MAX_RESOLVE_RETRY;

			while (maxRetry-- > 0) {
				try {
					DIDDocument resolved = did.resolve();
					if (resolved != null) {
						if (resolved.getControllerCount() == 1 && resolved.hasController(ownerDoc.getSubject()))
							System.out.println(Colorize.green("exists"));
						else
							System.out.println(Colorize.yellow("exists(not owned)"));

						return;
					} else {
						System.out.print(".");
					}
				} catch (DIDResolveException ignore) {
					System.out.print(Colorize.red("x"));
				}

				try {
					Thread.sleep(5000);
				} catch (InterruptedException ignore) {
				}
			}

			System.out.println(Colorize.yellow("timeout"));
		}
	}
}
