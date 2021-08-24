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

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(name = "didutils", mixinStandardHelpOptions = true, version = "didutils 2.0",
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
			Recover.class,
			SimChain.class,
			Shell.class
		})
public class DIDUtils {
	public static void main(String[] args) {
		// We use logback as the logging backend
		Logger root = (Logger)LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
		root.setLevel(Level.WARN);

		int exitCode = new CommandLine(new DIDUtils()).execute(args);

		System.exit(exitCode);
	}
}
