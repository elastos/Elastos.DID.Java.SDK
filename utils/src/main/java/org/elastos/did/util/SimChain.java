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

import java.util.concurrent.Callable;

import org.elastos.did.DIDBackend;
import org.elastos.did.backend.SimulatedIDChain;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "simchain", mixinStandardHelpOptions = true, version = "2.0",
		description = "Simulated ID Chain for testing.")
public class SimChain implements Callable<Integer> {
	@Option(names = {"-i", "--interface"}, description = "Server interface, default: localhost")
	private String host = "localhost";

	@Option(names = {"-p", "--port"}, description = "Server port, default 9123.")
	private int port = 9123;

	@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
	private boolean verboseErrors = false;

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
			if (verboseErrors)
				e.printStackTrace(System.err);
			else
				System.err.println("Error: " + e.getMessage());
		}

		return 0;
	}
}
