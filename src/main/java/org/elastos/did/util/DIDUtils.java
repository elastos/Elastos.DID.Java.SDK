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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.Callable;

import org.elastos.did.DID;
import org.elastos.did.DIDBackend;
import org.elastos.did.DIDBackend.LocalResolveHandle;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.DefaultDIDAdapter;
import org.elastos.did.Mnemonic;
import org.elastos.did.RootIdentity;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.VerifiablePresentation;
import org.elastos.did.VerificationEventListener;
import org.elastos.did.backend.SimulatedIDChain;
import org.elastos.did.crypto.Base64;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDTransactionException;
import org.elastos.did.jwt.JwtParser;
import org.elastos.did.jwt.JwtParserBuilder;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

public class DIDUtils {
	private static Scanner in;
	private static DIDStore store;

	public static class MyResolveHandle implements LocalResolveHandle {
		private File didDir;
		private Map<DID, DIDDocument> dids;

		public MyResolveHandle(String dir) throws IOException {
			if (dir == null || dir.isEmpty())
				didDir = new File(".");
			else
				didDir = new File(dir);

			didDir = didDir.getCanonicalFile();
			dids = new HashMap<DID, DIDDocument>();
			System.out.println("Local resolve directory: " + didDir.toString());
		}

		@Override
		public DIDDocument resolve(DID did) {
			if (dids.containsKey(did))
				return dids.get(did);

			try {
				File didFile = new File(didDir, did.getMethodSpecificId());
				if (!didFile.exists() || !didFile.isFile())
					didFile = new File(didDir, did.getMethodSpecificId() + ".json");

				if (didFile.exists() && didFile.isFile()) {
					InputStream in = new FileInputStream(didFile);
					DIDDocument doc = DIDDocument.parse(in);
					in.close();
					System.out.println("Load did " + did + " from " + didFile.getAbsolutePath());
					dids.put(did, doc);
					return doc;
				}
			} catch (Exception e) {
				System.out.print("Load did  " + did + " error!");
				e.printStackTrace(System.err);
			}

			return null;
		}
	}

	public static class ConsoleVerificationEventListener extends VerificationEventListener {
		@Override
		public void done(Object context, boolean succeeded, String message) {
			String color = succeeded ? GREEN : RED;

			System.out.println("  " + colorize(message, color));
		}

	}

	private static final String RESET = "\033[0m";
	// private static final String BLACK = "\033[0;30m";
	private static final String RED = "\033[0;31m";
	private static final String GREEN = "\033[0;32m";
	private static final String YELLOW = "\033[0;33m";
	//private static final String BLUE = "\033[0;34m";

	private static String colorize(String text, String color) {
		return color + text + RESET;
	}

	private static void setupDIDBackend(String network, String localResolveFolder)
			throws IOException, DIDResolveException {
		if (DIDBackend.isInitialized()) {
			if (network != null && !network.isEmpty()) {
				System.out.println(colorize("DID backend already initialized.", YELLOW));
				System.out.println(colorize("The following network and local resolve directory will be ignored.", YELLOW));
			}

			return;
		}

		if (network == null || network.isEmpty())
			network = "mainnet";

		DIDBackend.initialize(new DefaultDIDAdapter(network) {
			@Override
			public void createIdTransaction(String payload, String memo)
					throws DIDTransactionException {
				System.out.println("ID transaction payload:");
				try {
					printJson(System.out, false, payload);
				} catch (IOException e) {
					throw new DIDTransactionException(e);
				}
			}
		});

		DIDBackend.getInstance().setResolveHandle(new MyResolveHandle(localResolveFolder));
	}

	private static void openDIDStore(String storeDir) throws DIDStoreException {
		if (store != null) {
			if (storeDir != null && !storeDir.isEmpty()) {
				System.out.println(colorize("DID store already opened.", YELLOW));
				System.out.println(colorize("The following commands will use the opened store.", YELLOW));
			}

			return;
		}

		File storeFile = null;

		if (storeDir == null || storeDir.isEmpty())
			storeFile = getUserDirectory(".elastos/did/store");
		else
			storeFile = new File(storeDir);

		store = DIDStore.open(storeFile);
		System.out.println("Opened DID store: " + storeFile.getAbsolutePath());
	}

	private static void printJson(PrintStream out, boolean compact, String json) throws IOException {
		if (!compact) {
			JsonFactory jsonFactory = new JsonFactory();
			jsonFactory.configure(JsonGenerator.Feature.AUTO_CLOSE_TARGET, false);
			jsonFactory.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, false);

			ObjectMapper mapper = new ObjectMapper(jsonFactory);
			JsonNode node = mapper.readTree(json);
			mapper.writerWithDefaultPrettyPrinter().writeValue(out, node);
			out.println();
		} else {
			out.println(json);
		}
	}

	private static File getUserDirectory(String dir) {
		String home = System.getProperty("user.home");
		String path = home + File.separator + dir;
		return new File(path);
	}

	@Command(name = "resolvedid", mixinStandardHelpOptions = true, version = "2.0",
			description = "Resolve DID from the ID side chain.")
	public static class ResolveDid implements Callable<Integer> {
		@Option(names = {"-n", "--network"}, description = "Avaliable networks: mainnet testnet")
		private String network = null;

		@Option(names = {"-f", "--force"}, description = "Resolve froced from ID sidechain, default false.")
		private boolean force = false;

		@Option(names = {"-l", "--local"}, description = "Local DID resolve directory, default current directory.")
		private String local = null;

		@Option(names = {"-c", "--compact"}, description = "Output JSON in compact format, default false.")
		private boolean compact = false;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
		private boolean verbose = false;

		@Option(names = {"-o", "--out"}, description = "Output file, default is STDOUT.")
		private String outputFile;

		@Parameters(paramLabel = "DID", index = "0", description = "The target DID.")
		private String didstr;

		@Override
		public Integer call() throws Exception {
			try {
				setupDIDBackend(network, local);

				DID did = new DID(didstr);

				System.out.format("Resolving DID %s...", did);
				DIDDocument doc = did.resolve(force);
				if (doc == null) {
					System.out.format(colorize("\rResolving DID %s...NOT exists.\n", RED), did);
				} else {
					System.out.format(colorize("\rResolving DID %s...OK.\n", GREEN), did);
					System.out.println("Verifing the document...");
					boolean valid = doc.isValid(new ConsoleVerificationEventListener());
					if (valid)
						System.out.println(colorize("Verifing the document...OK", GREEN));
					else
						System.out.println(colorize("Verifing the document...FAILED", RED));

					System.out.println("\nDID document:");
					PrintStream out = System.out;
					if (outputFile != null)
						out = new PrintStream(outputFile);

					printJson(out, compact, doc.serialize(true));

					if (outputFile != null)
						out.close();
				}
			} catch(DIDException e) {
				if (verbose)
					e.printStackTrace(System.err);
				else
					System.err.println("Error: " + e.getMessage());
			}

			return 0;
		}

	}

	@Command(name = "verifydoc", mixinStandardHelpOptions = true, version = "2.0",
			description = "Verify the DID document.")
	public static class VerifyDocument implements Callable<Integer> {
		@Option(names = {"-n", "--network"}, description = "Avaliable networks: mainnet testnet")
		private String network = null;

		@Option(names = {"-f", "--force"}, description = "Resolve froced from ID sidechain, default false.")
		private boolean force = false;

		@Option(names = {"-l", "--local"}, description = "Local DID resolve directory, default current directory.")
		private String local = null;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
		private boolean verbose = false;

		@Parameters(paramLabel = "DOCUMENT", index = "0", description = "The DID document filename.")
		private String documentFile;

		@Override
		public Integer call() throws Exception {
			try {
				setupDIDBackend(network, local);

				DIDDocument doc = DIDDocument.parse(new File(documentFile));
				System.out.println("Verifing the document...");
				boolean valid = doc.isValid(new ConsoleVerificationEventListener());
				if (valid)
					System.out.println(colorize("Verifing the document...OK", GREEN));
				else
					System.out.println(colorize("Verifing the document...FAILED", RED));
			} catch(DIDException e) {
				if (verbose)
					e.printStackTrace(System.err);
				else
					System.err.println("Error: " + e.getMessage());
			}

			return 0;
		}
	}

	@Command(name = "verifyvc", mixinStandardHelpOptions = true, version = "2.0",
			description = "Verify the verifiable credential.")
	public static class VerifyCredential implements Callable<Integer> {
		@Option(names = {"-n", "--network"}, description = "Avaliable networks: mainnet testnet")
		private String network = null;

		@Option(names = {"-f", "--force"}, description = "Resolve froced from ID sidechain, default false.")
		private boolean force = false;

		@Option(names = {"-l", "--local"}, description = "Local DID resolve directory, default current directory.")
		private String local = null;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
		private boolean verbose = false;

		@Parameters(paramLabel = "VC", index = "0", description = "The credential filename.")
		private String credentialFile;

		@Override
		public Integer call() throws Exception {
			try {
				setupDIDBackend(network, local);

				VerifiableCredential vc = VerifiableCredential.parse(new File(credentialFile));
				System.out.println("Verifing the credenitial...");
				boolean valid = vc.isValid(new ConsoleVerificationEventListener());
				if (valid)
					System.out.println(colorize("Verifing the credenitial...OK", GREEN));
				else
					System.out.println(colorize("Verifing the credenitial...FAILED", RED));
			} catch(DIDException e) {
				if (verbose)
					e.printStackTrace(System.err);
				else
					System.err.println("Error: " + e.getMessage());
			}

			return 0;
		}
	}

	@Command(name = "verifyvp", mixinStandardHelpOptions = true, version = "2.0",
			description = "Verify the verifiable presentation.")
	public static class VerifyPresentation implements Callable<Integer> {
		@Option(names = {"-n", "--network"}, description = "Avaliable networks: mainnet testnet")
		private String network = null;

		@Option(names = {"-f", "--force"}, description = "Resolve froced from ID sidechain, default false.")
		private boolean force = false;

		@Option(names = {"-l", "--local"}, description = "Local DID resolve directory, default current directory.")
		private String local = null;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
		private boolean verbose = false;

		@Parameters(paramLabel = "VP", index = "0", description = "The presentation filename.")
		private String presentationFile;

		@Override
		public Integer call() throws Exception {
			try {
				setupDIDBackend(network, local);

				VerifiablePresentation vp = VerifiablePresentation.parse(new File(presentationFile));
				System.out.println("Verifing the presentation...");
				boolean valid = vp.isValid(new ConsoleVerificationEventListener());
				if (valid)
					System.out.println(colorize("Verifing the presentation...OK", GREEN));
				else
					System.out.println(colorize("Verifing the presentation...FAILED", RED));
			} catch(DIDException e) {
				if (verbose)
					e.printStackTrace(System.err);
				else
					System.err.println("Error: " + e.getMessage());
			}

			return 0;
		}
	}

	@Command(name = "verifyjwt", mixinStandardHelpOptions = true, version = "2.0",
			description = "Verify the JTW/JWS token.")
	public static class VerifyJwt implements Callable<Integer> {
		private static final int BASE64_OPT = Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP;

		@Option(names = {"-n", "--network"}, description = "Avaliable networks: mainnet testnet")
		private String network = null;

		@Option(names = {"-f", "--force"}, description = "Resolve froced from ID sidechain, default false.")
		private boolean force = false;

		@Option(names = {"-l", "--local"}, description = "Local DID resolve directory, default current directory.")
		private String local = null;

		@Option(names = {"-c", "--compact"}, description = "Output JSON in compact format, default false.")
		private boolean compact = false;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
		private boolean verbose = false;

		@Parameters(paramLabel = "JWT", index = "0", description = "The JWT token filename.")
		private String jwtFile;

		@Override
		public Integer call() throws Exception {
			try {
				setupDIDBackend(network, local);

				BufferedReader in = new BufferedReader(new FileReader(jwtFile));
				String token = in.readLine();
				in.close();

				JwtParser jp = new JwtParserBuilder().build();
				jp.parseClaimsJws(token);

				String[] parts = token.split("\\.", 3);
				System.out.println("======== HEADER ========");
				printJson(System.out, compact, new String(Base64.decode(parts[0].getBytes(), BASE64_OPT)));
				System.out.println("======== PAYLOAD ========");
				printJson(System.out, compact, new String(Base64.decode(parts[1].getBytes(), BASE64_OPT)));
				if (parts.length == 3) {
					System.out.println("======== SIGNATURE ========");
					System.out.println(parts[2]);
				}
			} catch(DIDException e) {
				if (verbose)
					e.printStackTrace(System.err);
				else
					System.err.println("Error: " + e.getMessage());
			}

			return 0;
		}
	}

	@Command(name = "createidentity", mixinStandardHelpOptions = true, version = "createidentity 2.0",
			description = "Create a RootIdentity.")
	public static class CreateRootIdentity implements Callable<Integer> {
		@Option(names = {"-f", "--force"}, description = "Overwrite the existing.")
		private boolean force = false;

		@Option(names = {"-s", "--store"}, description = "DID Store path, default: ~/.elastos/did/store")
		private String storeDir = null;

		@Option(names = {"-p", "--password"}, required = true, description = "Password for the DID store")
		private String password = null;

		@Option(names = {"-n", "--new"}, description = "Create new from mnemonic")
		private Boolean create = false;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
		private boolean verbose = false;

		@Override
		public Integer call() throws Exception {
			try {
				openDIDStore(storeDir);

				String mnemonic = null;

				Scanner in = new Scanner(System.in);

				if (create) {
					mnemonic = Mnemonic.getInstance().generate();
					System.out.println("Mnemonic: " + mnemonic);
				} else {
					System.out.print("Mnemonic: ");
					mnemonic = in.nextLine();
					if (!Mnemonic.checkIsValid(mnemonic)) {
						System.err.println("Mnemonic is invald");
						in.close();
						return -1;
					}
				}

				System.out.print("Passphrase(enter for empty): ");
				String passphrase = in.nextLine();
				in.close();

				RootIdentity id = RootIdentity.create(mnemonic, passphrase, force, store, password);
				System.out.println(colorize("Identity " + id.getId() + " created.", GREEN));
			} catch (DIDException e) {
				if (verbose)
					e.printStackTrace(System.err);
				else
					System.err.println("Error: " + e.getMessage());
			}

			return 0;
		}
	}

	@Command(name = "listidentity", mixinStandardHelpOptions = true, version = "listidentity 2.0",
			description = "List the RootIdentities.")
	public static class ListRootIdentities implements Callable<Integer> {
		@Option(names = {"-s", "--store"}, description = "DID Store path, default: ~/.elastos/did/store")
		private String storeDir = null;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
		private boolean verbose = false;

		@Override
		public Integer call() throws Exception {
			try {
				openDIDStore(storeDir);

				RootIdentity defaultId = store.loadRootIdentity();
				List<RootIdentity> ids = store.listRootIdentities();

				System.out.format(colorize("Total %d root identities\n", GREEN), ids.size());
				for (RootIdentity id : ids) {
					String defaultMarker = "";

					if (defaultId != null && id.getId().equals(defaultId.getId()))
						defaultMarker = " *";

					System.out.println("  " + id.getId() + defaultMarker);
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

	@Command(name = "deleteidentity", mixinStandardHelpOptions = true, version = "deleteidentity 2.0",
			description = "Delete the root identity.")
	public static class DeleteRootIdentity implements Callable<Integer> {
		@Option(names = {"-s", "--store"}, description = "DID Store path, default: ~/.elastos/did/store")
		private String storeDir = null;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
		private boolean verbose = false;

		@Parameters(paramLabel = "ID", index = "0", description = "The root identity to be delete from the store.")
		private String id;

		@Override
		public Integer call() throws Exception {
			try {
				openDIDStore(storeDir);

				boolean deleted = store.deleteRootIdentity(id);

				if (deleted)
					System.out.format(colorize("RootIdentity %s deleted\n", GREEN), id);
				else
					System.out.format(colorize("RootIdentity %s not exists\n", RED), id);
			} catch (DIDException e) {
				if (verbose)
					e.printStackTrace(System.err);
				else
					System.err.println("Error: " + e.getMessage());
			}

			return 0;
		}
	}

	@Command(name = "createdid", mixinStandardHelpOptions = true, version = "createdid 2.0",
			description = "Create a DID.")
	public static class CreateDid implements Callable<Integer> {
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
				openDIDStore(storeDir);

				RootIdentity id = null;
				if (identity == null || identity.isEmpty()) {
					id = store.loadRootIdentity();
					if (id == null) {
						System.out.println(colorize("Store not contains the default root identity", RED));
						return -1;
					}
				} else {
					id = store.loadRootIdentity(identity);
					if (id == null) {
						System.out.format(colorize("Store not contains the root identity: %s\n", RED), identity);
						return -1;
					}
				}

				DIDDocument doc;
				if (index >= 0)
					doc = id.newDid(index, force, password);
				else
					doc = id.newDid(password);

				System.out.println(colorize("DID " + doc.getSubject() + " created.", GREEN));
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

	@Command(name = "listdid", mixinStandardHelpOptions = true, version = "listdid 2.0",
			description = "List the DIDs.")
	public static class ListDids implements Callable<Integer> {
		@Option(names = {"-s", "--store"}, description = "DID Store path, default: ~/.elastos/did/store")
		private String storeDir = null;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
		private boolean verbose = false;

		@Override
		public Integer call() throws Exception {
			try {
				openDIDStore(storeDir);

				List<DID> dids = store.listDids();

				System.out.format(colorize("Total %d DIDs\n", GREEN), dids.size());
				for (DID did : dids)
					System.out.println("  " + did);
			} catch (DIDException e) {
				if (verbose)
					e.printStackTrace(System.err);
				else
					System.err.println("Error: " + e.getMessage());
			}

			return 0;
		}
	}

	@Command(name = "deletedid", mixinStandardHelpOptions = true, version = "deletedid 2.0",
			description = "Delete the DID.")
	public static class DeleteDid implements Callable<Integer> {
		@Option(names = {"-s", "--store"}, description = "DID Store path, default: ~/.elastos/did/store")
		private String storeDir = null;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
		private boolean verbose = false;

		@Parameters(paramLabel = "DID", index = "0", description = "The DID to be delete from the store.")
		private String did;

		@Override
		public Integer call() throws Exception {
			try {
				openDIDStore(storeDir);

				DID _did = new DID(did);
				boolean deleted = store.deleteDid(_did);

				if (deleted)
					System.out.format(colorize("DID %s deleted\n", GREEN), did);
				else
					System.out.format(colorize("DID %s not exists\n", RED), did);
			} catch (DIDException e) {
				if (verbose)
					e.printStackTrace(System.err);
				else
					System.err.println("Error: " + e.getMessage());
			}

			return 0;
		}
	}

	@Command(name = "displaydid", mixinStandardHelpOptions = true, version = "displaydid 2.0",
			description = "Display the DID document and metadata.")
	public static class DisplayDid implements Callable<Integer> {
		@Option(names = {"-s", "--store"}, description = "DID Store path, default: ~/.elastos/did/store")
		private String storeDir = null;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
		private boolean verbose = false;

		@Parameters(paramLabel = "DID", index = "0", description = "The DID to be display.")
		private String did;

		@Override
		public Integer call() throws Exception {
			try {
				openDIDStore(storeDir);

				DID _did = new DID(did);
				DIDDocument doc = store.loadDid(_did);

				if (doc != null) {
					System.out.println("DID document:");
					printJson(System.out, false, doc.serialize(true));

					System.out.println("\nDID Metadata:");
					printJson(System.out, false, doc.getMetadata().serialize());
				} else {
					System.out.format(colorize("DID %s not exists\n", RED), did);
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

	@Command(name = "publishdid", mixinStandardHelpOptions = true, version = "publishdid 2.0",
			description = "Publish DID to ID transaction payload.")
	public static class PublishDid implements Callable<Integer> {
		@Option(names = {"-s", "--store"}, description = "DID Store path, default: ~/.elastos/did/store")
		private String storeDir = null;

		@Option(names = {"-p", "--password"}, required = true, description = "Password for the DID store")
		private String password = null;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
		private boolean verbose = false;

		@Parameters(paramLabel = "DID", index = "0", description = "The DID to be publish.")
		private String did;

		@Override
		public Integer call() throws Exception {
			try {
				openDIDStore(storeDir);

				DID _did = new DID(did);
				if (store.containsDid(_did)) {
					store.synchronize(_did);

					System.out.format("Publishing DID %s...\n", did);
					DIDDocument doc = store.loadDid(_did);
					doc.publish(password);
				} else {
					System.out.format(colorize("DID %s not exists\n", RED), did);
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

	@Command(name = "simchain", mixinStandardHelpOptions = true, version = "2.0",
			description = "Simulated ID Chain for testing.")
	public static class SimChain implements Callable<Integer> {
		@Option(names = {"-i", "--interface"}, description = "Server interface, default: localhost")
		private String host = "localhost";

		@Option(names = {"-p", "--port"}, description = "Server port, default 9123.")
		private int port = 9123;

		@Option(names = {"-e", "--verbose"}, description = "Verbose error output, default false.")
		private boolean verbose = false;

		@Option(names = {"-l", "--loglevel"}, description = "Log level, default is info(trace, debug, info, warn, error).")
		private String level = "info";

		@Override
		public Integer call() throws Exception {
			Level logLevel = Level.valueOf(level);

			// We use logback as the default logging backend
			Logger root = (Logger)LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
			root.setLevel(logLevel);

			try {
				SimulatedIDChain simChain = new SimulatedIDChain(host, port);
				DIDBackend.initialize(simChain.getAdapter(), 0, 0, 0);
				Runtime.getRuntime().addShutdownHook(new Thread(()-> {
					simChain.stop();
				}));

				simChain.run();
			} catch(Exception e) {
				if (verbose)
					e.printStackTrace(System.err);
				else
					System.err.println("Error: " + e.getMessage());
			}

			return 0;
		}
	}

	@Command(name = "shell", mixinStandardHelpOptions = true, version = "shell 2.0",
			description = "Interactive shell.")
	public static class Shell implements Callable<Integer> {
		@Option(names = {"-n", "--network"}, description = "Avaliable networks: mainnet testnet")
		private String network = null;

		@Option(names = {"-l", "--local"}, description = "Local DID resolve directory, default current directory.")
		private String local = null;

		@Override
		public Integer call() throws Exception {
			int exitCode = 0;

			setupDIDBackend(network, local);

			while (true) {
				System.out.print("didshell $ ");
				String cmd = in.nextLine().trim();
				if (cmd.isEmpty())
					continue;

				if (cmd.equals("exit") || cmd.equals("quit")) {
					exitCode = 0;
					break;
				}

				if (cmd.equals("help") || cmd.equals("?")) {
					new CommandLine(new DIDCommand()).execute(new String[] {"--help"});
					continue;
				}

				String[] args = cmd.split("\\s+");
				exitCode = new CommandLine(new DIDCommand()).execute(args);
			}

			return exitCode;
		}
	}

	@Command(name = "org.elastos.did.util.DIDUtils", mixinStandardHelpOptions = true, version = "didutils 2.0",
			description = "Elastos DID command line tool.",
		subcommands = {
			ResolveDid.class,
			VerifyDocument.class,
			VerifyCredential.class,
			VerifyPresentation.class,
			VerifyJwt.class,
			CreateRootIdentity.class,
			ListRootIdentities.class,
			DeleteRootIdentity.class,
			CreateDid.class,
			ListDids.class,
			DeleteDid.class,
			DisplayDid.class,
			PublishDid.class,
			SimChain.class,
			Shell.class
		})
	public static class DIDCommand {
	}

	public static void main(String[] args) {
		// We use logback as the logging backend
		Logger root = (Logger)LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
		root.setLevel(Level.WARN);

		in = new Scanner(System.in);

		int exitCode = new CommandLine(new DIDCommand()).execute(args);

		in.close();

		System.exit(exitCode);
	}

}
