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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;

import org.elastos.did.DID;
import org.elastos.did.DIDBackend;
import org.elastos.did.DIDBackend.LocalResolveHandle;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.VerificationEventListener;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public abstract class CommandBase {
	private static DIDStore store;

	public final static class Colorize {
		public static final String RESET = "\033[0m";
		public static final String BLACK = "\033[0;30m";
		public static final String RED = "\033[0;31m";
		public static final String GREEN = "\033[0;32m";
		public static final String YELLOW = "\033[0;33m";
		public static final String BLUE = "\033[0;34m";

		public static String colorize(String text, String color) {
			return color + text + RESET;
		}

		public static String red(String text) {
			return colorize(text, RED);
		}

		public static String green(String text) {
			return colorize(text, GREEN);
		}

		public static String yellow(String text) {
			return colorize(text, YELLOW);
		}

		public static String blue(String text) {
			return colorize(text, BLUE);
		}
	}

	private static class MyResolveHandle implements LocalResolveHandle {
		private File didDir;
		private Map<DID, DIDDocument> dids;

		public MyResolveHandle(String dir) throws IOException {
			if (dir == null || dir.isEmpty())
				didDir = new File(".");
			else
				didDir = new File(dir);

			didDir = didDir.getCanonicalFile();
			dids = new HashMap<DID, DIDDocument>();
			System.out.println("Local resolve directory: " + didDir.toString());
		}

		@Override
		public DIDDocument resolve(DID did) {
			if (dids.containsKey(did))
				return dids.get(did);

			try {
				File didFile = new File(didDir, did.getMethodSpecificId());
				if (!didFile.exists() || !didFile.isFile())
					didFile = new File(didDir, did.getMethodSpecificId() + ".json");

				if (didFile.exists() && didFile.isFile()) {
					InputStream in = new FileInputStream(didFile);
					DIDDocument doc = DIDDocument.parse(in);
					in.close();
					System.out.println("Load did " + did + " from " + didFile.getAbsolutePath());
					dids.put(did, doc);
					return doc;
				}
			} catch (Exception e) {
				System.out.print("Load did  " + did + " error!");
				e.printStackTrace(System.err);
			}

			return null;
		}
	}

	public static class ConsoleVerificationEventListener extends VerificationEventListener {
		@Override
		public void done(Object context, boolean succeeded, String message) {
			String color = succeeded ? Colorize.GREEN : Colorize.RED;

			System.out.println("  " + Colorize.colorize(message, color));
		}

	}


	protected void setupDIDBackend(String network, String localResolveFolder)
			throws IOException, DIDResolveException {
		if (DIDBackend.isInitialized()) {
			if (network != null && !network.isEmpty()) {
				System.out.println(Colorize.yellow("DID backend already initialized."));
				System.out.println(Colorize.yellow("The following network and local resolve directory will be ignored."));
			}

			return;
		}

		if (network == null || network.isEmpty())
			network = "mainnet";

		DIDBackend.initialize(new AssistDIDAdapter(network));
		DIDBackend.getInstance().setResolveHandle(new MyResolveHandle(localResolveFolder));
	}

	protected DIDStore openDIDStore(String storeDir) throws DIDStoreException {
		if (CommandBase.store != null) {
			if (storeDir != null && !storeDir.isEmpty()) {
				System.out.println(Colorize.yellow("DID store already opened."));
				System.out.println(Colorize.yellow("The following commands will use the opened store."));
			}

			return CommandBase.store;
		}

		File storeFile = null;

		if (storeDir == null || storeDir.isEmpty())
			storeFile = getUserFile(".elastos/did/store");
		else
			storeFile = new File(storeDir);

		CommandBase.store = DIDStore.open(storeFile);
		System.out.println("Opened DID store: " + storeFile.getAbsolutePath());

		return store;
	}

	protected static void printJson(PrintStream out, boolean compact, String json) throws IOException {
		if (!compact) {
			JsonFactory jsonFactory = new JsonFactory();
			jsonFactory.configure(JsonGenerator.Feature.AUTO_CLOSE_TARGET, false);
			jsonFactory.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, false);

			ObjectMapper mapper = new ObjectMapper(jsonFactory);
			JsonNode node = mapper.readTree(json);
			mapper.writerWithDefaultPrettyPrinter().writeValue(out, node);
			out.println();
		} else {
			out.println(json);
		}
	}

	protected File getUserFile(String file) {
		String home = System.getProperty("user.home");
		String path = home + File.separator + file;
		return new File(path);
	}
}
