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

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.concurrent.Callable;

import org.elastos.did.crypto.Base64;
import org.elastos.did.exception.DIDException;
import org.elastos.did.jwt.JwtParser;
import org.elastos.did.jwt.JwtParserBuilder;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "verifyjwt", mixinStandardHelpOptions = true, version = "2.0",
		description = "Verify the JTW/JWS token.")
public class VerifyJwt extends CommandBase implements Callable<Integer> {
	private static final int BASE64_OPT = Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP;

	@Option(names = {"-n", "--network"}, description = "Avaliable networks: mainnet testnet")
	private String network = null;

	@Option(names = {"-f", "--force"}, description = "Resolve froced from ID sidechain, default false.")
	private boolean force = false;

	@Option(names = {"-l", "--local"}, description = "Local DID resolve directory, default current directory.")
	private String local = null;

	@Option(names = {"-c", "--compact"}, description = "Output JSON in compact format, default false.")
	private boolean compact = false;

	@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
	private boolean verboseErrors = false;

	@Parameters(paramLabel = "JWT", index = "0", description = "The JWT token filename.")
	private String jwtFile;

	@Override
	public Integer call() throws Exception {
		try {
			setupDIDBackend(network, local);

			BufferedReader in = new BufferedReader(new FileReader(jwtFile));
			String token = in.readLine();
			in.close();

			JwtParser jp = new JwtParserBuilder().build();
			jp.parseClaimsJws(token);

			String[] parts = token.split("\\.", 3);
			System.out.println("HEADER:");
			printJson(System.out, compact, new String(Base64.decode(parts[0].getBytes(), BASE64_OPT)));
			System.out.println("PAYLOAD:");
			printJson(System.out, compact, new String(Base64.decode(parts[1].getBytes(), BASE64_OPT)));
			if (parts.length == 3) {
				System.out.println("SIGNATURE:");
				System.out.println(parts[2]);
			}
		} catch(DIDException e) {
			if (verboseErrors)
				e.printStackTrace(System.err);
			else
				System.err.println("Error: " + e.getMessage());
		}

		return 0;
	}
}
