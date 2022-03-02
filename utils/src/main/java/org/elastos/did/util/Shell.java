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

import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(name = "sh", mixinStandardHelpOptions = true, version = "shell 2.0",
		description = "Interactive shell.")
public class Shell extends CommandBase implements Callable<Integer> {
	@Override
	public Integer call() throws Exception {
		int exitCode = 0;

		System.out.println("Network: " + Colorize.green(getActiveNetwork().toString()));
		if (getActiveIdentity() != null) {
			System.out.print("Identity: " + Colorize.green(getActiveIdentity()));
			System.out.println(", DID: " + Colorize.green(String.valueOf(getActiveDid())));
		} else {
			System.out.println("Identity: " + Colorize.yellow("N/A"));
		}

		while (true) {
			String cmd = System.console().readLine("didshell $ ");
			if (cmd.isEmpty())
				continue;

			if (cmd.equals("exit") || cmd.equals("quit")) {
				exitCode = 0;
				break;
			}

			String[] args = cmd.split("\\s+");
			if (cmd.equals("help") || cmd.equals("?"))
				args = new String[] {"--help"};

			exitCode = new CommandLine(new DIDUtils()).execute(args);
		}

		return exitCode;
	}
}
