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

import java.util.Map;
import java.util.concurrent.Callable;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
@Command(name = "network", mixinStandardHelpOptions = true, version = "2.0",
description = "Networks management commands.", subcommands = {
		Networks.Switch.class,
		Networks.List.class,
		Networks.Add.class,
		Networks.Delete.class,
})
public class Networks extends CommandBase implements Callable<Integer> {
	@Override
	public Integer call() {
		Network network = getContext().getActiveNetwork();
		System.out.println("Active network: " + Colorize.green(network.toString()));

		return 0;
	}

	@Command(name = "switch", mixinStandardHelpOptions = true, version = "2.0",
			description = "Switch the active network.", sortOptions = false)
	public static class Switch extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "NETWORK", index = "0", description = "The network name.")
		private String name;

		@Override
		public Integer call() {
			try {
				if (name.equals(getActiveNetwork().getName())) {
					System.out.println(name + " is already active network.");
					return 0;
				}

				if (getContext().getNetwork(name) == null) {
					System.out.println(Colorize.red("Network " + name + " not exists."));
					return -1;
				}

				getContext().switchNetwork(name);
				System.out.println("Switched to the network: " + Colorize.green(name));

				return 0;
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "add", mixinStandardHelpOptions = true, version = "2.0",
			description = "Add a new private network.", sortOptions = false)
	public static class Add extends CommandBase implements Callable<Integer> {
		@Option(names = {"-c", "--chain-id"}, description = "Verbose error output, default false.")
		private Long chainId = null;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "NAME", index = "0", description = "The network name.")
		private String name;

		@Parameters(paramLabel = "RPC-ENDPOINT", index = "1", description = "The RPC endpoint for the network.")
		private String rpcEndpoint;

		@Override
		public Integer call() {
			try {
				if (getContext().getNetwork(name) != null) {
					System.out.println(Colorize.red("Network " + name + " already exists."));
					return -1;
				}

				Network network = new Network(name, rpcEndpoint, chainId);
				getContext().addNetwork(network);
				System.out.println("Network " + name + " added.");
				getContext().switchNetwork(name);
				System.out.println("Switched to the network: " + Colorize.green(name));

				return 0;
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "list", mixinStandardHelpOptions = true, version = "2.0",
			description = "List the available private networks.", sortOptions = false)
	public static class List extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Override
		public Integer call() {
			try {
				Map<String, Network> networks = getContext().getNetworks();
				if (networks.isEmpty()) {
					System.out.println("No private networks.");
					return 0;
				}

				System.out.println("name					  RPC Endpoint");
				System.out.println("------------------------  --------------------------------");
				for (Network network : networks.values())
					System.out.format("%-24s  %s\n", network.getName(), network.getRpcEndpint());

				return 0;
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "delete", mixinStandardHelpOptions = true, version = "2.0",
			description = "Delete the private network.", sortOptions = false)
	public static class Delete extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "NETWORK", index = "0", description = "The network name that to be delete.")
		private String name;

		@Override
		public Integer call() {
			try {
				if (!getContext().getNetworks().containsKey(name)) {
					System.out.println(Colorize.red("Network " + name + " not exists."));
					return -1;
				}

				if (name.equals(getActiveNetwork().getName())) {
					System.out.println(Colorize.yellow("Can not delete the active network."));
					return -1;
				}

				getContext().deleteNetwork(name);
				System.out.println("Network " + name + " deleted.");

				return 0;
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}
}
