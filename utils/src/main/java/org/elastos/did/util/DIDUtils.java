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
import java.util.concurrent.Callable;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(name = "didutils", mixinStandardHelpOptions = true, version = Version.VERSION,
		description = "Elastos DID command line tool.",
		subcommands = {
			Networks.class,
			Wallets.class,
			Identities.class,
			DIDs.class,
			Credentials.class,
			Presentations.class,
			IDRequests.class,
			JWTs.class,
			Jsonld.class,
			Shell.class,
			SimChain.class,
			DIDUtils.Ver.class
		})
public class DIDUtils implements Runnable {
	private static final String APP_HOME = ".elastos/didutils";

	public static File getHome() {
		String userHome = System.getProperty("user.home");
		File home = new File(userHome + File.separator + APP_HOME);
		if (!home.exists()) {
			home.mkdirs();
		} else {
			if (!home.isDirectory())
				throw new IllegalStateException("DIDUtils home folder " + home.getAbsolutePath() + " exists, but not a directory");
		}

		return home;
	}

	@Override
	public void run() {
		System.out.println(new CommandLine(this).getUsageMessage());
	}

	@Command(name = "ver", mixinStandardHelpOptions = false, version = Version.VERSION,
			description = "Version info.")
	public static class Ver implements Callable<Integer> {
		@Override
		public Integer call() throws Exception {
			System.out.println(Version.VERSION);
			return 0;
		}
	}

	public static void main(String[] args) {
		// We use logback as the logging backend
		Logger root = (Logger)LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
		root.setLevel(Level.WARN);

		int exitCode = new CommandLine(new DIDUtils()).execute(args);
		System.exit(exitCode);
	}
}
