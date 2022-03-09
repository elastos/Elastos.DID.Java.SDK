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
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.attribute.BasicFileAttributes;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.Callable;

import org.elastos.did.Constants;
import org.elastos.did.DID;
import org.elastos.did.DIDBackend;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDDocument.Builder;
import org.elastos.did.DIDDocument.PublicKey;
import org.elastos.did.DIDDocument.Service;
import org.elastos.did.DIDStore;
import org.elastos.did.DefaultDIDAdapter;
import org.elastos.did.Mnemonic;
import org.elastos.did.RootIdentity;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDResolveException;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "id", mixinStandardHelpOptions = true, version = "2.0",
		description = "Identity management commands.", subcommands = {
				Identities.Switch.class,
				Identities.List.class,
				Identities.Create.class,
				Identities.Delete.class,
				Identities.Export.class,
				Identities.Synchronize.class,
				Identities.Recover.class
})
public class Identities extends CommandBase implements Callable<Integer> {
	public static boolean exists(String identity) {
		File dir = getIdentityHome(identity);
		return dir.exists();
	}

	protected static File getIdentityHome(String identity) {
		File dir = new File(DIDUtils.getHome(), identity);
		 if (dir.exists()) {
			 if (!dir.isDirectory())
				throw new IllegalStateException("Identity folder " + dir.getAbsolutePath() + " exists, but not a directory");
		 }

		 return dir;
	}

	private static void prepareDidStore(String identity, String network) throws IOException {
		File dir = getIdentityHome(identity);
		File storeDir = new File(dir, network);

		if (!storeDir.exists()) {
			File originStore = new File(dir, ".origin");
			copyFile(originStore, storeDir);
		}
	}

	protected static DIDStore openStore(String identity, String network) throws IOException, DIDException {
		// Open the did store at: $APPHOME/identity/network
		File home = getIdentityHome(identity);
		File storeFile = new File(home, network);
		if (storeFile.exists()) {
			if (!storeFile.isDirectory())
				throw new IllegalStateException("Store folder " + storeFile.getAbsolutePath() + " exists, but not a directory");
		} else {
			prepareDidStore(identity, network);
		}

		return DIDStore.open(storeFile);
	}

    @Override
    public Integer call() {
		String identity = getActiveIdentity();
		if (identity != null)
			System.out.println("Active identity: " + Colorize.green(identity));
		else
			System.out.println("No active identity.");

		return 0;
    }

	@Command(name = "switch", mixinStandardHelpOptions = true, version = "2.0",
			description = "Switch the active identity.", sortOptions = false)
	public static class Switch extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "IDENTITY", index = "0", description = "The identity name.")
		private String name;

		@Override
		public Integer call() {
			try {
				if (name.equals(getActiveIdentity())) {
					System.out.println(name + " is already active identity.");
					return 0;
				}

				if (!exists(name)) {
					System.out.println(Colorize.red("Identity " + name + " not exists."));
					return -1;
				}

				getContext().switchIdentity(name);
				System.out.println("Switched to the identity: " + Colorize.green(name));

				return 0;
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "create", mixinStandardHelpOptions = true, version = "2.0",
			description = "Create user identity.", sortOptions = false)
	public static class Create extends CommandBase implements Callable<Integer> {
		@Option(names = {"-i", "--import"}, description = "Import from existing mnemonic and optional passphrase.")
		private boolean importMode = false;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "IDENTITY", index = "0", description = "The name of the identity.")
		private String name;

		@Override
		public Integer call() {
			File identityDir = null;

			try {
				identityDir = getIdentityHome(name);
				if (identityDir.exists()) {
					System.out.println(Colorize.red("Identity " + name + " already exists."));
					return -1;
				}

				String mnemonic = null;
				if (importMode) {
					mnemonic = System.console().readLine("Mnemonic: ");
					if (!Mnemonic.checkIsValid(mnemonic)) {
						System.err.println(Colorize.red("Mnemonic is invald"));
						return -1;
					}
				} else {
					mnemonic = Mnemonic.getInstance().generate();
					System.out.println("Mnemonic: " + Colorize.green(mnemonic));
					System.out.println("Please write down your mnemonics safely!!!");
				}

				String passphrase = System.console().readLine("Passphrase(enter for empty): ");

				String password;
				while (true) {
					password = new String(System.console().readPassword("Password: "));
					if (password.isEmpty())
						System.out.println(Colorize.yellow("Password can not be empty."));
					else
						break;
				}
				String password2 = new String(System.console().readPassword("Confirm password: "));
				if (!password2.equalsIgnoreCase(password)) {
					System.out.println(Colorize.red("Password mismatch."));
					return -1;
				}

				String address = Wallets.create(identityDir, mnemonic, passphrase, password);
				System.out.println(Colorize.green("Wallet " + address + " created."));

				// Initialize DIDBackend for DID creation.
				if (!DIDBackend.isInitialized())
					DIDBackend.initialize(new DefaultDIDAdapter(getActiveNetwork().getRpcEndpint()));

				DIDStore store = DIDStore.open(new File(identityDir, ".origin"));
				RootIdentity id = RootIdentity.create(mnemonic, passphrase, true, store, password);
				id.setAlias(name);
				id.setAsDefault();
				System.out.println("Identity " + name + ":" + id.getId() + " created.");

				if (importMode) {
					id.synchronize();
					System.out.println("Identity " + name + ":" + id.getId() + " synchronized.");
				}

				if (!importMode || store.listDids().isEmpty()) {
					DIDDocument doc = id.newDid(password);
					id.setDefaultDid(doc.getSubject());
					System.out.println("DID " + doc.getSubject() + " created.");
				} else {
					id.setDefaultDid(id.getDid(0));
				}

				store.close();

				prepareDidStore(name, getActiveNetwork().getName());
				getContext().switchIdentity(name);
				System.out.println("Switched to the identity: " + Colorize.green(name));

				return 0;
			} catch (Exception e) {
				if (identityDir != null)
					deleteFile(identityDir);

				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "list", mixinStandardHelpOptions = true, version = "2.0",
			description = "List user identities.", sortOptions = false)
	public static class List extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Override
		public Integer call() {
			try {
				File dir = DIDUtils.getHome();

				FilenameFilter filter = (d, n) -> {
					File f = new File(d, n);
					return f.isDirectory();
				};

				DateTimeFormatter df = DateTimeFormatter.ofPattern("MM/dd/yyyy HH:mm:ss");
				ZoneId tz = ZoneId.systemDefault();

				System.out.println("last access           last modified         name");
				System.out.println("--------------------  --------------------  ----------------");
				for (File d : dir.listFiles(filter)) {
					String identity = d.getName();
					BasicFileAttributes attr = Files.readAttributes(d.toPath(), BasicFileAttributes.class);

					ZonedDateTime aTime = Instant.ofEpochMilli(attr.lastAccessTime().toMillis()).atZone(tz);
					ZonedDateTime mTime = Instant.ofEpochMilli(attr.lastModifiedTime().toMillis()).atZone(tz);

					boolean isActive = d.getName().equals(getActiveIdentity());

					System.out.format("%-20s  %-20s  %s%s\n", df.format(aTime), df.format(mTime),
							isActive ? Colorize.green("*") : " ", identity);
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

	@Command(name = "delete", mixinStandardHelpOptions = true, version = "2.0",
			description = "Delete user identity.", sortOptions = false)
	public static class Delete extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "IDENTITY", index = "0", description = "The identity name to be delete.")
		private String name;

		@Override
		public Integer call() {
			try {
				if (name.equals(getActiveIdentity())) {
					System.out.println(Colorize.yellow("Can not delete the active identity."));
					return -1;
				}

				File dir = getIdentityHome(name);
				if (!dir.exists()) {
					System.out.println(Colorize.red("Identity " + name + " not exists."));
					return -1;
				}
				deleteFile(dir);
				System.out.println("Identity " + name + " deleted.");

				return 0;
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "export", mixinStandardHelpOptions = true, version = "2.0",
			description = "Export the identity.", subcommands = {
					Export.Mnemonic.class,
					Export.Store.class
			})
	public static class Export extends CommandBase {
		@Command(name = "mnemonic", mixinStandardHelpOptions = true, version = "2.0",
				description = "Export the identity's mnemonic.", sortOptions = false)
		public static class Mnemonic extends CommandBase implements Callable<Integer> {
			@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
			private boolean verboseErrors = false;

			@Override
			public Integer call() {
				try {
					if (getActiveIdentity() == null) {
						System.out.println(Colorize.red("No active identity"));
						return -1;
					}

					RootIdentity id = getActiveRootIdentity();
					String mnemonic = id.exportMnemonic(CommandContext.getPassword());
					System.out.println("Mnemonic: " + Colorize.green(mnemonic));

					return 0;
				} catch (Exception e) {
					System.err.println(Colorize.red("Error: " + e.getMessage()));
					if (verboseErrors)
						e.printStackTrace(System.err);

					return -1;
				}
			}
		}

		@Command(name = "store", mixinStandardHelpOptions = true, version = "2.0",
				description = "Export the DID store.", sortOptions = false)
		public static class Store extends CommandBase implements Callable<Integer> {
			@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
			private boolean verboseErrors = false;

			@Parameters(paramLabel = "FILE", index = "0", description = "The export file name.")
			private String file;

			@Override
			public Integer call() {
				try {
					if (getActiveIdentity() == null) {
						System.out.println(Colorize.red("No active identity"));
						return -1;
					}

					File exportFile = toFile(file);
					DIDStore store = getActiveStore();
					String password = CommandContext.getPassword();

					store.exportStore(exportFile, password, password);

					return 0;
				} catch (Exception e) {
					System.err.println(Colorize.red("Error: " + e.getMessage()));
					if (verboseErrors)
						e.printStackTrace(System.err);

					return -1;
				}
			}
		}
	}

	@Command(name = "sync", mixinStandardHelpOptions = true, version = "2.0",
			description = "Synchronize all DIDs that belong to the identity.", sortOptions = false)
	public static class Synchronize extends CommandBase implements Callable<Integer> {
		@Option(names = {"-m", "--merge"}, defaultValue = "interactive", description = "How to merge the conflict: chain, local, interactive. default: interactive.")
		private String merge = null;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		private static final int INTERACTIVE = 0;
		private static final int CHAIN = 1;
		private static final int LOCAL = 2;

		@Override
		public Integer call() throws Exception {
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

				RootIdentity id = getActiveRootIdentity();
				if (id == null) {
					System.out.println(Colorize.red("Store not contains the default root identity"));
					return -1;
				}

				System.out.println("Synchronizing......");
				final int mergeMode = mode;
				id.synchronize((chainCopy, localCopy) -> {
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
								System.out.println(Colorize.yellow("Invalid selection."));
							}
						}
					}

					return keep;
				});

				System.out.println("Finish synchronize.");
				return 0;
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "recover", mixinStandardHelpOptions = true, version = "2.0",
			description = "Recover the wrong DIDs.", sortOptions = false)
	public static class Recover extends CommandBase implements Callable<Integer> {
		@Option(names = {"-m", "--merge"}, description = "How to merge the old DID information: none, interactive, all. default: interactive.")
		private String merge = null;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		private static final int NONE = 0;
		private static final int INTERACTIVE = 1;
		private static final int ALL = 2;

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
						System.out.println(Colorize.red("Unknown merge mode: " + merge));
						return -1;
					}
				}

				RootIdentity id = getActiveRootIdentity();

				String password = null;
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
							if (password == null)
								password = CommandContext.getPassword();

							try {
								recoverDid(id, index, mode, password);
								System.out.format("Checking DID@%d %s...", index, did.toString());
								System.out.print(Colorize.yellow("WRONG, recovering..."));
								System.out.println(Colorize.green("RECOVERED"));
							} catch (Exception ex) {
								System.out.println(Colorize.red("FAILED"));
								if (verboseErrors)
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

				return 0;
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
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
}
