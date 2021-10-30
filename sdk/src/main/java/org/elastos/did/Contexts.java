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

package org.elastos.did;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Contexts {
	private static final String BUILTIN_CONTEXTS = "contexts/contexts.json";

	private static Map<String, String> builtinContexts;

	private static synchronized void loadBuiltinContexts() throws IOException {
		if (builtinContexts != null)
			return;

		try (InputStream in = Contexts.class.getResourceAsStream(BUILTIN_CONTEXTS)) {
			ObjectMapper om = new ObjectMapper();
			builtinContexts = om.readValue(in, new TypeReference<Map<String,String>>(){});
		} catch (IOException e) {
			throw new IOException("Can not load the built-in contexts", e);
		}
	}

	public static Set<String> getBuiltinContexts() throws IOException {
		loadBuiltinContexts();

		return Collections.unmodifiableSet(builtinContexts.keySet());
	}

	private static InputStream loadBuiltinContext(String uri) {
		String name = "contexts/" + builtinContexts.get(uri);

		return Contexts.class.getResourceAsStream(name);
	}

	private static InputStream loadPublicContext(String uri) throws IOException {
		// TODO:
		return null;
	}

	public static InputStream loadContext(URI uri) throws IOException {
		return loadContext(uri.toString());
	}

	public static InputStream loadContext(String uri) throws IOException {
		loadBuiltinContexts();

		InputStream contextStream;

		if (builtinContexts.containsKey(uri))
			contextStream = loadBuiltinContext(uri);
		else
			contextStream = loadPublicContext(uri);

		return contextStream;
	}
}
