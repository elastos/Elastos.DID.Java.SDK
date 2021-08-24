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

import java.io.File;
import java.util.concurrent.Callable;

import org.elastos.did.VerifiableCredential;
import org.elastos.did.exception.DIDException;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;


@Command(name = "verifyvc", mixinStandardHelpOptions = true, version = "2.0",
		description = "Verify the verifiable credential.")
public class VerifyCredential extends CommandBase implements Callable<Integer> {
	@Option(names = {"-n", "--network"}, description = "Avaliable networks: mainnet testnet")
	private String network = null;

	@Option(names = {"-f", "--force"}, description = "Resolve froced from ID sidechain, default false.")
	private boolean force = false;

	@Option(names = {"-l", "--local"}, description = "Local DID resolve directory, default current directory.")
	private String local = null;

	@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
	private boolean verboseErrors = false;

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
				System.out.println(Colorize.green("Verifing the credenitial...OK"));
			else
				System.out.println(Colorize.red("Verifing the credenitial...FAILED"));
		} catch(DIDException e) {
			if (verboseErrors)
				e.printStackTrace(System.err);
			else
				System.err.println("Error: " + e.getMessage());
		}

		return 0;
	}
}
