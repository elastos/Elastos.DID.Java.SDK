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

import java.util.concurrent.Callable;

import org.elastos.did.VerifiablePresentation;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "presentation", mixinStandardHelpOptions = true, version = "2.0",
description = "Presentation management commands.", subcommands = {
		Presentations.Verify.class
})
public class Presentations extends CommandBase {
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
