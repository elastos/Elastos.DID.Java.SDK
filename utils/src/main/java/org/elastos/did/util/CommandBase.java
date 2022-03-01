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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

import org.elastos.did.DID;
import org.elastos.did.DIDBackend;
import org.elastos.did.DIDBackend.LocalResolveHandle;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.DIDURL;
import org.elastos.did.RootIdentity;
import org.elastos.did.VerificationEventListener;
import org.elastos.did.exception.DIDException;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public abstract class CommandBase {
	protected CommandBase() {
		CommandContext.initialize();
	}

	protected static CommandContext getContext() {
		return CommandContext.getInstance();
	}

	protected static Network getActiveNetwork() {
		return getContext().getActiveNetwork();
	}

	protected static String getActiveIdentity() {
		return getContext().getActiveIdentity();
	}

	protected static DIDStore getActiveStore() throws IOException, DIDException {
		return getContext().getActiveStore();
	}

	protected static RootIdentity getActiveRootIdentity() throws IOException, DIDException {
		return getContext().getActiveRootIdentity();
	}

	protected static DID getActiveDid() throws IOException, DIDException {
		return getContext().getActivateDid();
	}

	protected static File getActiveWallet() {
		return getContext().getActiveWallet();
	}

	protected static Web3Adapter getActiveDidAdapter() {
		return getContext().getActiveDidAdapter();
	}

	protected static DID toDid(String did) {
		try {
			return new DID(did);
		} catch (Exception e) {
			System.out.println(Colorize.red("Invalid DID string: " + did));
			throw e;
		}
	}

	protected static DIDURL toDidUrl(String id) {
		try {
			return new DIDURL(id);
		} catch (Exception e) {
			System.out.println(Colorize.red("Invalid DIDURL string: " + id));
			throw e;
		}
	}

	protected static File toFile(String file) {
		if (file == null || file.isEmpty())
			return null;

		if (file.startsWith("~"))
			return new File(System.getProperty("user.home") + file.substring(1));
		else
			return new File(file);
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

	protected static void deleteFile(File file) {
		if (file.isDirectory()) {
			File[] children = file.listFiles();
			for (File child : children)
				deleteFile(child);
		}

		file.delete();
	}

	protected static void copyFile(File source, File dest) throws IOException {
	    if (source.isDirectory()) {
	    	if (!dest.exists())
	    		dest.mkdirs();

	    	for (File f : source.listFiles())
	    		copyFile(f, new File(dest, f.getName()));
	    } else {
	    	Files.copy(source.toPath(), dest.toPath());
	    }
	}

	protected static VerificationEventListener getVerificationEventListener() {
		return new VerificationEventListener() {
			@Override
			public void done(Object context, boolean succeeded, String message) {
				String color = succeeded ? Colorize.GREEN : Colorize.RED;

				System.out.println("  " + Colorize.colorize(message, color));
			}
		};
	}

	protected static void setLocalResolveHandle(File dir) throws IOException {
		DIDBackend.getInstance().setResolveHandle(new MyResolveHandle(dir));
	}

	protected static void clearLocalResolveHandle() {
		DIDBackend.getInstance().setResolveHandle(null);
	}

	private static class MyResolveHandle implements LocalResolveHandle {
		private File localDir;
		private Map<DID, DIDDocument> dids;

		public MyResolveHandle(File dir) throws IOException {
			localDir = dir.getAbsoluteFile();
			dids = new HashMap<DID, DIDDocument>();
		}

		@Override
		public DIDDocument resolve(DID did) {
			if (dids.containsKey(did))
				return dids.get(did);

			try {
				File didFile = new File(localDir, did.getMethodSpecificId());
				if (!didFile.exists() || !didFile.isFile())
					didFile = new File(localDir, did.getMethodSpecificId() + ".json");

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
}
