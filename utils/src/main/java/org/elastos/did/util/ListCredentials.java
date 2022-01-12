package org.elastos.did.util;

import java.util.List;
import java.util.concurrent.Callable;

import org.elastos.did.DID;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDURL;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDResolveException;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "listcredentials", mixinStandardHelpOptions = true, version = "2.0",
description = "List the credentials from the ID side chain.")
public class ListCredentials extends CommandBase implements Callable<Integer> {
	@Option(names = {"-n", "--network"}, description = "Avaliable networks: mainnet testnet")
	private String network = null;

	@Option(names = {"-l", "--local"}, description = "Local DID resolve directory, default current directory.")
	private String local = null;

	@Option(names = {"-v", "--verifiy"}, description = "verify each credential, default false.")
	private boolean verify = false;

	@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
	private boolean verboseErrors = false;

	@Parameters(paramLabel = "DID", index = "0", description = "The target DID.")
	private String didstr;

	@Override
	public Integer call() throws Exception {
		try {
			setupDIDBackend(network, local);

			listCredentials(new DID(didstr), verify);
		} catch(DIDException e) {
			if (verboseErrors)
				e.printStackTrace(System.err);
			else
				System.err.println("Error: " + e.getMessage());
		}

		return 0;
	}

	private void listCredentials(DID did, boolean verify) throws DIDException {
		System.out.format("Resolving DID %s...", did);
		DIDDocument doc = did.resolve();
		if (doc == null) {
			System.out.format(Colorize.red("\rResolving DID %s...NOT exists.\n"), did);
		} else {
			System.out.format(Colorize.green("\rResolving DID %s...OK.\n"), did);
			System.out.println("Verifing the document...");
			boolean valid = doc.isValid(new ConsoleVerificationEventListener());
			if (valid)
				System.out.println(Colorize.green("Verifing the document...OK"));
			else
				System.out.println(Colorize.red("Verifing the document...FAILED"));
		}

		System.out.println("Declared credentials:\n");
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
							System.out.println(Colorize.green("OK"));
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
