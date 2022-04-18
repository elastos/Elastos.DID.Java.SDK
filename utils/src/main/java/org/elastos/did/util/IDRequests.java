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

import org.elastos.did.backend.CredentialRequest;
import org.elastos.did.backend.DIDRequest;
import org.elastos.did.backend.IDChainRequest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "idrequest", mixinStandardHelpOptions = true, version = Version.VERSION,
description = "DID request commands.", subcommands = {
		IDRequests.Verify.class
})
public class IDRequests extends CommandBase {
	@Command(name = "verify", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Verify the DID request.", sortOptions = false)
	public static class Verify extends CommandBase implements Callable<Integer> {
		@Option(names = {"-f", "--force"}, description = "Resolve froced from ID sidechain, default false.")
		private boolean force = false;

		@Option(names = {"-l", "--local"}, description = "Local DID resolve directory, default current directory.")
		private String localDir = null;

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "REQUEST", index = "0", description = "The DID request filename.")
		private String requestFile;

		@Override
		public Integer call() {
			try {
				if (localDir != null)
					setLocalResolveHandle(toFile(localDir));

				ObjectMapper mapper = new ObjectMapper();
				JsonNode requestJson = mapper.readTree(toFile(requestFile));
				JsonNode header = requestJson.get("header");
				if (header == null) {
					System.out.println(Colorize.red("Invalid IDChain request, missing header"));
					return -1;
				}

				JsonNode spec = header.get("specification");
				if (spec == null) {
					System.out.println(Colorize.red("Invalid IDChain request, missing specification"));
					return -1;
				}

				IDChainRequest<?> request;
				switch (spec.asText()) {
				case IDChainRequest.DID_SPECIFICATION:
					request = DIDRequest.parse(toFile(requestFile), DIDRequest.class);
					break;

				case IDChainRequest.CREDENTIAL_SPECIFICATION:
					request = CredentialRequest.parse(toFile(requestFile), CredentialRequest.class);
					break;

				default:
					System.out.println(Colorize.red("Invalid IDChain request, unknown specification: " + spec));
					return -1;
				}

				boolean valid = request.isValid();
				System.out.println("Request spec: " + request.getOperation().getSpecification());
				System.out.println("Request op: " + request.getOperation().name());
				System.out.println("Request is " + (valid ? Colorize.green("valid") : Colorize.red("invalid")));
				return 0;
			} catch(Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
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
