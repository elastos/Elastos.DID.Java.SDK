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
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.concurrent.Callable;

import org.elastos.did.DID;
import org.elastos.did.DIDStore;
import org.elastos.did.DIDURL;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.VerifiablePresentation;
import org.elastos.did.crypto.Base58;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "vp", mixinStandardHelpOptions = true, version = "2.0",
description = "Presentation management commands.", subcommands = {
		Presentations.Create.class,
		Presentations.Verify.class
})
public class Presentations extends CommandBase {
	@Command(name = "create", mixinStandardHelpOptions = true, version = "2.0",
			description = "Create a presentation.", sortOptions = false)
	public static class Create extends CommandBase implements Callable<Integer> {
		@Option(names = {"-r", "--realm"}, description = "Realm for the presentation.")
		private String realm = null;

		@Option(names = {"-n", "--nonce"}, description = "Nonce for the presentation.")
		private String nonce = null;

		@Option(names = {"-c", "--compact"}, description = "Output JSON in compact format, default false.")
		private boolean compact = false;

		@Option(names = {"-o", "--out"}, description = "Output file, default is STDOUT.")
		private String outputFile;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Override
		public Integer call() {
			try {
				if (getActiveIdentity() == null) {
					System.out.println(Colorize.red("No active identity"));
					return -1;
				}

				DID did = getActiveDid();

				byte[] binId = new byte[16];
				new SecureRandom().nextBytes(binId);
				DIDURL id = new DIDURL(did, "#" + Base58.encode(binId));

				DIDStore store = getActiveStore();

				VerifiablePresentation.Builder pb = VerifiablePresentation.createFor(did, store);

				while (true) {
					String idstr = System.console().readLine("Add credential(ID): ");
					if (idstr == null || idstr.isEmpty())
						break;

					DIDURL vcId = null;
					try {
						vcId = toDidUrl(did, idstr);
					} catch (Exception e) {
						System.out.println(Colorize.red("Invalid DIDURL."));
						continue;
					}

					VerifiableCredential vc = store.loadCredential(vcId);
					if (vc == null) {
						System.out.println(Colorize.red("Credential " + vcId + " not exists."));
						continue;
					}

					try {
						pb.credentials(vc);
					} catch (Exception e) {
						System.out.println(Colorize.red(e.getClass().getName() + ": " + e.getMessage()));
					}
				}

				pb.id(id);
				pb.realm(realm).nonce(nonce);

				VerifiablePresentation vp = pb.seal(CommandContext.getPassword());

				PrintStream out = System.out;
				if (outputFile != null) {
					File output = toFile(outputFile);
					out = new PrintStream(output);
				} else {
					System.out.println("\nPresentation:");
				}

				printJson(out, compact, vp.serialize(true));

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

	@Command(name = "verify", mixinStandardHelpOptions = true, version = "verifyvp 2.0",
			description = "Verify the verifiable presentation.")
	public static class Verify extends CommandBase implements Callable<Integer> {
		@Option(names = {"-l", "--local"}, description = "Local DID resolve directory, default current directory.")
		private String localDir = null;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "VP", index = "0", description = "The presentation filename.")
		private String presentationFile;

		@Override
		public Integer call() {
			try {
				if (localDir != null)
					setLocalResolveHandle(toFile(localDir));

				VerifiablePresentation vp = VerifiablePresentation.parse(toFile(presentationFile));
				System.out.println("Verifing the presentation...");
				boolean valid = vp.isValid();
				if (valid) {
					System.out.println(Colorize.green("Valid"));
				} else {
					System.out.println(Colorize.red("Invalid"));
					vp.isValid(getVerificationEventListener());
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
