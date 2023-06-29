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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.JsonLdOptions;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.apicatalog.jsonld.loader.SchemeRouter;
import com.apicatalog.jsonld.uri.UriUtils;

import jakarta.json.Json;
import jakarta.json.JsonValue;
import jakarta.json.JsonWriterFactory;
import jakarta.json.stream.JsonGenerator;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "jsonld", mixinStandardHelpOptions = true, version = Version.VERSION,
		description = "JSON-LD tools.", subcommands = {
				Jsonld.Expand.class,
				Jsonld.Compact.class,
				Jsonld.Verify.class
})
public class Jsonld {
	private static URI baseURI;

	static class MyDocumentLoader implements DocumentLoader {
		private String localURIPrefix;
		private File localContextsDir;

		public MyDocumentLoader(String localURIPrefix, File localContextsDir) {
			super();
			this.localURIPrefix = localURIPrefix;
			this.localContextsDir = localContextsDir;
		}

		private InputStream getLocalContext(URI uri) {
			String uristr = uri.toString();
			if (!uristr.startsWith(localURIPrefix))
				return null;

			String path = uristr.substring(localURIPrefix.length()).replace('/', File.separatorChar);
			if (path.startsWith(File.separator))
				path = path.substring(1);

			File contextFile = new File(localContextsDir, path);
			try {
				return (contextFile.exists() && contextFile.isFile()) ?
						new FileInputStream(contextFile) : null;
			} catch (FileNotFoundException e) {
				return null;
			}
		}

		@Override
		public Document loadDocument(URI uri, DocumentLoaderOptions options) throws JsonLdError {
			InputStream context = getLocalContext(uri);

			// local contexts
			if (context != null) {
				JsonDocument document = JsonDocument.of(context);
				document.setContextUrl(null);
				document.setDocumentUrl(uri);
				return document;
			} else {
				// external contexts
				return SchemeRouter.defaultInstance().loadDocument(uri, options);
			}
		}
	}

	private static JsonLdOptions getJsonLdOptions(String localURIPrefix, File localContextsDir) {
		if (baseURI == null) {
			try {
				baseURI = new URI("https://trinity-tech.io/ns/v1#");
			} catch (URISyntaxException e) {
				throw new RuntimeException("Error create base URI", e);
			}
		}

		if (localContextsDir != null) {
			localContextsDir = localContextsDir.getAbsoluteFile();
			if (!localContextsDir.exists() || !localContextsDir.isDirectory())
				System.out.println(Colorize.yellow("Invalid local context directory: " + localContextsDir));
		}

		JsonLdOptions opts = new JsonLdOptions(new MyDocumentLoader(localURIPrefix, localContextsDir));
		opts.setBase(baseURI);

		return opts;
	}

	private static URI toUri(String name) {
		if (name.indexOf("://") > 0)
			return UriUtils.create(name);

		File file = CommandBase.toFile(name);
		return file.getAbsoluteFile().toPath().toUri();
	}

	@Command(name = "expand", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Expand JSON-LD document.", sortOptions = false)
	public static class Expand extends CommandBase implements Callable<Integer> {
		@Option(names = {"-p", "--prefix"}, description = "Local contexts URI prefix")
		private String localURIPrefix = null;

		@Option(names = {"-x", "--context"}, description = "Local contexts directory")
		private String localContextsDir = null;

		@Option(names = {"-o", "--output"}, description = "Output filename, default output to console.")
		private String outputFile = null;

		@Parameters(paramLabel = "JSON-LD-DOC", index = "0", description = "The JSON-LD document.")
		private String document;

		@Override
		public Integer call() throws Exception {
			JsonValue result = JsonLd.expand(toUri(document))
					.options(getJsonLdOptions(localURIPrefix, toFile(localContextsDir)))
					.get();

			Map<String,Boolean> config = new HashMap<>();
			config.put(JsonGenerator.PRETTY_PRINTING, true);

			JsonWriterFactory writerFactory = Json.createWriterFactory(config);

			PrintStream output = System.out;
			if (outputFile != null && !outputFile.isEmpty())
				output = new PrintStream(new FileOutputStream(toFile(outputFile)));

			writerFactory.createWriter(output).write(result);

			if (output != System.out)
				output.close();

			return 0;
		}
	}

	@Command(name = "compact", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Compact JSON-LD document.")
	public static class Compact extends CommandBase implements Callable<Integer> {
		@Option(names = {"-p", "--prefix"}, description = "Local contexts URI prefix")
		private String localURIPrefix = null;

		@Option(names = {"-x", "--context"}, description = "Local contexts directory")
		private String localContextsDir = null;

		@Option(names = {"-o", "--output"}, description = "Output filename, default output to console.")
		private String outputFile = null;

		@Parameters(paramLabel = "JSON-LD-DOC", index = "0", description = "The JSON-LD document.")
		private String document;

		@Parameters(paramLabel = "JSON-LD-CONTEXT", index = "1", description = "The JSON-LD context.")
		private String context;

		@Override
		public Integer call() throws Exception {
			JsonValue result = JsonLd.compact(toUri(document), toUri(context))
					.options(getJsonLdOptions(localURIPrefix, toFile(localContextsDir)))
					.base(baseURI)
					.compactToRelative(false)
					.get();

			Map<String,Boolean> config = new HashMap<>();
			config.put(JsonGenerator.PRETTY_PRINTING, true);

			JsonWriterFactory writerFactory = Json.createWriterFactory(config);

			PrintStream output = System.out;
			if (outputFile != null && !outputFile.isEmpty())
				output = new PrintStream(new FileOutputStream(toFile(outputFile)));

			writerFactory.createWriter(output).write(result);

			if (output != System.out)
				output.close();

			return 0;
		}
	}

	@Command(name = "verify", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Verify JSON-LD document.")
	public static class Verify extends CommandBase implements Callable<Integer> {
		@Option(names = {"-p", "--prefix"}, description = "Local contexts URI prefix")
		private String localURIPrefix = null;

		@Option(names = {"-x", "--context"}, description = "Local contexts directory")
		private String localContextsDir = null;

		@Option(names = {"-e", "--expandedOutput"}, description = "Expanded output filename, default output to console.")
		private String expandedOutput = null;

		@Option(names = {"-c", "--compactedOutput"}, description = "Compacted output filename, default output to console.")
		private String compactedOutput = null;

		@Parameters(paramLabel = "JSON-LD-DOC", index = "0", description = "The JSON-LD document.")
		private String document;

		@Parameters(paramLabel = "JSON-LD-CONTEXT", index = "1", description = "The JSON-LD context.")
		private String context;

		@Override
		public Integer call() throws Exception {
			JsonLdOptions options = getJsonLdOptions(localURIPrefix, toFile(localContextsDir));

			JsonValue result = JsonLd.expand(toUri(document))
					.options(options)
					.get();

			Map<String,Boolean> config = new HashMap<>();
			config.put(JsonGenerator.PRETTY_PRINTING, true);

			JsonWriterFactory writerFactory = Json.createWriterFactory(config);

			PrintStream output = System.out;
			File tempOutput = null;
			if (expandedOutput != null && !expandedOutput.isEmpty())
				output = new PrintStream(new FileOutputStream(toFile(expandedOutput)));
			else {
				System.out.println("======== Expanded JSON-LD ========");
				tempOutput = File.createTempFile("temp-", ".jsonld");
			}

			writerFactory.createWriter(output).write(result);
			if (tempOutput != null) {
				OutputStream temp = new FileOutputStream(tempOutput);
				writerFactory.createWriter(temp).write(result);
				temp.close();
				expandedOutput = tempOutput.getAbsolutePath();
			}

			if (output != System.out)
				output.close();

			result = JsonLd.compact(toUri(expandedOutput), toUri(context))
					.options(options)
					.base(baseURI)
					.compactToRelative(false)
					.get();

			output = System.out;
			if (compactedOutput != null && !compactedOutput.isEmpty())
				output = new PrintStream(new FileOutputStream(toFile(compactedOutput)));
			else
				System.out.println("\n======== Compacted JSON-LD ========");

			writerFactory.createWriter(output).write(result);

			if (output != System.out)
				output.close();

			return 0;
		}
	}
}
