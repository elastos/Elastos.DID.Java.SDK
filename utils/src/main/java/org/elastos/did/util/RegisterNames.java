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
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.concurrent.Callable;

import org.elastos.did.Constants;
import org.elastos.did.DID;
import org.elastos.did.DIDBackend;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.Mnemonic;
import org.elastos.did.RootIdentity;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDResolveException;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "registernames", mixinStandardHelpOptions = true, version = "registernames 2.0",
		description = "Register resolved names.")
public class RegisterNames extends CommandBase implements Callable<Integer> {
	@Option(names = {"-s", "--store"}, description = "DID Store path, default: ~/.elastos/did/store")
	private String storeDir = null;

	@Option(names = {"-p", "--password"}, required = true, description = "Password for the DID store")
	private String password = null;

	@Option(names = {"-n", "--network"}, description = "Avaliable networks: mainnet testnet or a RPC endpoint for private net")
	private String network = "testnet";

	@Option(names = {"-w", "--wallet"}, description = "Wallet file name, default: ~/.elastos/did/wallet/eid-wallet.json")
	private String walletFile = null;

	@Option(names = {"-t", "--walletPassword"}, required = true, description = "The wallet password")
	private String walletPassword = null;

	@Option(names = {"-l", "--name-list"}, required = true, description = "Name list file")
	private String nameListFile = null;

	@Option(names = {"-f", "--name-suffix"}, description = "Name suffix for testing, default is current time, 0 to turn off the suffix")
	private String nameSuffix = String.valueOf(System.currentTimeMillis());

	@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
	private boolean verboseErrors = false;

	private DIDStore store;
	private DIDDocument ownerDoc;

	private static int MAX_RESOLVE_RETRY = 24;

	@Override
	public Integer call() throws Exception {
		// fix the naming
		if (nameSuffix.equals("0"))
			nameSuffix = null;

		try {
			// Load the name list
			ArrayList<String> names = loadNames(nameListFile);
			if (names.isEmpty()) {
				System.out.println(Colorize.yellow("The name list file is empty."));
				return 0;
			}

			if (walletFile == null)
				walletFile = getUserFile(".elastos/did/wallet/eid-wallet.json").getAbsolutePath();

			Web3Adapter adapter = new Web3Adapter(network, walletFile, walletPassword);
			DIDBackend.initialize(adapter);
			store = openDIDStore(storeDir);

			// Initialize the owner's did
			initilizeOwner();
			if (ownerDoc.getSubject().resolve() == null)
				return -1;

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

			adapter.shutdown();
		} catch (DIDException | IOException e) {
			if (verboseErrors)
				e.printStackTrace(System.err);
			else
				System.err.println("Error: " + e.getMessage());
		}

		return 0;
	}

	private ArrayList<String> loadNames(String file) throws IOException {
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

	private boolean waitForDidAvailable(DID did) {
		int maxRetry = MAX_RESOLVE_RETRY;

		while (maxRetry-- > 0) {
			try {
				if (did.resolve() != null)
					return true;
			} catch (DIDResolveException ignore) {
			}

			try {
				Thread.sleep(5000);
			} catch (InterruptedException ignore) {
			}
		}

		return false;
	}

	private void initilizeOwner() throws DIDException {
		RootIdentity ownerId = store.loadRootIdentity();
		if (ownerId == null) {
			System.out.println("Store not contains the default root identity, will create a new one");
			System.out.println("Createing the root identity...");
			String mnemonic = Mnemonic.getInstance().generate();;
			System.out.println("Mnemonic: " + Colorize.red(mnemonic));
			ownerId = RootIdentity.create(mnemonic, "", true, store, password);
			System.out.println("Createing the root identity " + ownerId.getId() + "..." + Colorize.green("OK"));
		} else {
			System.out.println("Use the existing root identity " +  ownerId.getId());
			/*
			System.out.print("Synchronize the identity...");
			ownerId.synchronize();
			System.out.println(Colorize.green("OK"));
			*/
		}

		DID ownerDid = ownerId.getDid(0);
		System.out.print("Checking the default owner's DID " + ownerDid + "...");
		if (ownerDid.resolve() != null) {
			System.out.println(Colorize.green("exists"));
			ownerDoc = store.loadDid(ownerDid);
		} else {
			System.out.println("to be create");
			ownerDoc = ownerId.newDid(0, true, password);
			System.out.print("Creating DID " + ownerDoc.getSubject() + "...");
			ownerDoc.publish(password);
			if (waitForDidAvailable(ownerDoc.getSubject())) {
				System.out.println(Colorize.green("OK"));
			} else {
				System.out.println(Colorize.red("ERROR"));
			}
		}
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
			Calendar cal = Calendar.getInstance(Constants.UTC);
			cal.add(Calendar.MONTH, 3);
			Date expires = cal.getTime();

			DIDDocument.Builder db = doc.edit();
			db.setExpires(expires);
			doc = db.seal(password);
			store.storeDid(doc);

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

	public static void main(String... args) {
		// We use logback as the logging backend
		Logger root = (Logger)LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
		root.setLevel(Level.WARN);

		int exitCode = new CommandLine(new RegisterNames()).execute(args);
        System.exit(exitCode);
    }
}
