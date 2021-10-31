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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

import org.elastos.did.Contexts;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.JsonLdErrorCode;
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

@Command(name = "jsonld", mixinStandardHelpOptions = true, version = "jsonld 1.1",
		description = "JSON-LD tools.", subcommands = {
				Jsonld.Expand.class,
				Jsonld.Compact.class,
				Jsonld.Verify.class
})
public class Jsonld {
	private static URI baseURI;
	private static Set<String> builtinContexts;

	static class MyDocumentLoader implements DocumentLoader {

		@Override
		public Document loadDocument(URI uri, DocumentLoaderOptions options) throws JsonLdError {
			if (builtinContexts == null) {
				try {
					builtinContexts = Contexts.getBuiltinContexts();
				} catch (IOException ignore) {
					builtinContexts = Collections.emptySet();
				}
			}

			if (builtinContexts.contains(uri.toString())) {
				try {
					JsonDocument document = JsonDocument.of(Contexts.loadContext(uri));
					document.setContextUrl(null);
					document.setDocumentUrl(uri);
					return document;
				} catch (IOException e) {
					throw new JsonLdError(JsonLdErrorCode.LOADING_REMOTE_CONTEXT_FAILED, e);
				}
			}

			return SchemeRouter.defaultInstance().loadDocument(uri, options);
		}
	}

	private static JsonLdOptions getJsonLdOptions() {
		if (baseURI == null) {
			try {
				baseURI = new URI("https://trinity-tech.io/ns/v1#");
			} catch (URISyntaxException e) {
				throw new RuntimeException("Error create base URI", e);
			}
		}
		JsonLdOptions opts = new JsonLdOptions(new MyDocumentLoader());
		opts.setBase(baseURI);

		return opts;
	}

	private static URI toUri(String name) {
		if (name.indexOf("://") > 0)
			return UriUtils.create(name);

		File file = new File(name);
		return file.getAbsoluteFile().toPath().toUri();
	}

	@Command(name = "expand", mixinStandardHelpOptions = true, version = "jsonld expand 1.1",
			description = "Expand JSON-LD document.")
	public static class Expand extends CommandBase implements Callable<Integer> {
		@Option(names = {"-o", "--output"}, description = "Output filename, default output to console.")
		private String outputFile = null;

		@Parameters(paramLabel = "JSON-LD-DOC", index = "0", description = "The JSON-LD document.")
		private String document;

		@Override
		public Integer call() throws Exception {
			JsonValue result = JsonLd.expand(toUri(document))
					.options(getJsonLdOptions())
					.get();

			Map<String,Boolean> config = new HashMap<>();
			config.put(JsonGenerator.PRETTY_PRINTING, true);

			JsonWriterFactory writerFactory = Json.createWriterFactory(config);

			PrintStream output = System.out;
			if (outputFile != null && !outputFile.isEmpty())
				output = new PrintStream(new FileOutputStream(outputFile));

			writerFactory.createWriter(output).write(result);

			if (output != System.out)
				output.close();

			return 0;
		}
	}

	@Command(name = "compact", mixinStandardHelpOptions = true, version = "jsonld expand 1.1",
			description = "Compact JSON-LD document.")
	public static class Compact extends CommandBase implements Callable<Integer> {
		@Option(names = {"-o", "--output"}, description = "Output filename, default output to console.")
		private String outputFile = null;

		@Parameters(paramLabel = "JSON-LD-DOC", index = "0", description = "The JSON-LD document.")
		private String document;

		@Parameters(paramLabel = "JSON-LD-CONTEXT", index = "1", description = "The JSON-LD context.")
		private String context;

		@Override
		public Integer call() throws Exception {
			JsonValue result = JsonLd.compact(toUri(document), toUri(context))
					.options(getJsonLdOptions())
					.base(baseURI)
					.compactToRelative(false)
					.get();

			Map<String,Boolean> config = new HashMap<>();
			config.put(JsonGenerator.PRETTY_PRINTING, true);

			JsonWriterFactory writerFactory = Json.createWriterFactory(config);

			PrintStream output = System.out;
			if (outputFile != null && !outputFile.isEmpty())
				output = new PrintStream(new FileOutputStream(outputFile));

			writerFactory.createWriter(output).write(result);

			if (output != System.out)
				output.close();

			return 0;
		}
	}

	@Command(name = "verify", mixinStandardHelpOptions = true, version = "jsonld verify 1.1",
			description = "Verify JSON-LD document.")
	public static class Verify extends CommandBase implements Callable<Integer> {
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
			JsonValue result = JsonLd.expand(toUri(document))
					.options(getJsonLdOptions())
					.get();

			Map<String,Boolean> config = new HashMap<>();
			config.put(JsonGenerator.PRETTY_PRINTING, true);

			JsonWriterFactory writerFactory = Json.createWriterFactory(config);

			PrintStream output = System.out;
			File tempOutput = null;
			if (expandedOutput != null && !expandedOutput.isEmpty())
				output = new PrintStream(new FileOutputStream(expandedOutput));
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
					.options(getJsonLdOptions())
					.base(baseURI)
					.compactToRelative(false)
					.get();

			output = System.out;
			if (compactedOutput != null && !compactedOutput.isEmpty())
				output = new PrintStream(new FileOutputStream(compactedOutput));
			else
				System.out.println("\n======== Compacted JSON-LD ========");

			writerFactory.createWriter(output).write(result);

			if (output != System.out)
				output.close();

			return 0;
		}
	}
}
