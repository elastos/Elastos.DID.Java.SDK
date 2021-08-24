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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.stream.Stream;

import org.elastos.did.exception.MalformedDIDException;
import org.elastos.did.exception.MalformedDIDURLException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

public class DIDURLTest {
	private static final String TEST_DID = "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN";
	private static final String TEST_PATH = "/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource";
	private static final String TEST_QUERY = "?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A";
	private static final String TEST_FRAGMENT = "#testfragment";

	private static final int WITH_DID = 0x01;
	private static final int WITH_PATH = 0x02;
	private static final int WITH_QUERY = 0x04;
	private static final int WITH_FRAGMENT = 0x08;

	private static Stream<Arguments> provideDIDURLs() {
		return Stream.of(
				Arguments.of(TEST_DID, WITH_DID),
				Arguments.of(TEST_DID + TEST_PATH, WITH_DID | WITH_PATH),
				Arguments.of(TEST_DID + TEST_QUERY, WITH_DID | WITH_QUERY),
				Arguments.of(TEST_DID + TEST_FRAGMENT, WITH_DID | WITH_FRAGMENT),
				Arguments.of(TEST_DID + TEST_PATH + TEST_FRAGMENT, WITH_DID | WITH_PATH | WITH_FRAGMENT),
				Arguments.of(TEST_DID + TEST_QUERY + TEST_FRAGMENT, WITH_DID | WITH_QUERY | WITH_FRAGMENT),
				Arguments.of(TEST_DID + TEST_PATH + TEST_QUERY, WITH_DID | WITH_PATH | WITH_QUERY),
				Arguments.of(TEST_DID + TEST_PATH + TEST_QUERY + TEST_FRAGMENT, WITH_DID | WITH_PATH | WITH_QUERY | WITH_FRAGMENT),

				Arguments.of(TEST_PATH, WITH_PATH),
				Arguments.of(TEST_QUERY, WITH_QUERY),
				Arguments.of(TEST_FRAGMENT, WITH_FRAGMENT),
				Arguments.of(TEST_PATH + TEST_FRAGMENT, WITH_PATH | WITH_FRAGMENT),
				Arguments.of(TEST_QUERY + TEST_FRAGMENT, WITH_QUERY | WITH_FRAGMENT),
				Arguments.of(TEST_PATH + TEST_QUERY, WITH_PATH | WITH_QUERY),
				Arguments.of(TEST_PATH + TEST_QUERY + TEST_FRAGMENT, WITH_PATH | WITH_QUERY | WITH_FRAGMENT),

				Arguments.of("  \n \t " + TEST_DID + "\t	\n", WITH_DID),
				Arguments.of("\t   \n" + TEST_DID + TEST_PATH + "  \n \t", WITH_DID | WITH_PATH),
				Arguments.of("   " + TEST_DID + TEST_QUERY + "\n", WITH_DID | WITH_QUERY),
				Arguments.of("\n" + TEST_DID + TEST_FRAGMENT + "	  ", WITH_DID | WITH_FRAGMENT),
				Arguments.of("\t" + TEST_DID + TEST_PATH + TEST_FRAGMENT + "  \n", WITH_DID | WITH_PATH | WITH_FRAGMENT),
				Arguments.of(" " + TEST_DID + TEST_QUERY + TEST_FRAGMENT + "\t", WITH_DID | WITH_QUERY | WITH_FRAGMENT),
				Arguments.of("   " + TEST_DID + TEST_PATH + TEST_QUERY, WITH_DID | WITH_PATH | WITH_QUERY),
				Arguments.of(TEST_DID + TEST_PATH + TEST_QUERY + TEST_FRAGMENT + "	  ", WITH_DID | WITH_PATH | WITH_QUERY | WITH_FRAGMENT),

				Arguments.of("  \t" + TEST_PATH + "	", WITH_PATH),
				Arguments.of(" \n \t " + TEST_QUERY + "   \n", WITH_QUERY),
				Arguments.of("   " + TEST_FRAGMENT + "\t", WITH_FRAGMENT),
				Arguments.of(" " + TEST_PATH + TEST_FRAGMENT + "	", WITH_PATH | WITH_FRAGMENT),
				Arguments.of("   " + TEST_QUERY + TEST_FRAGMENT, WITH_QUERY | WITH_FRAGMENT),
				Arguments.of(TEST_PATH + TEST_QUERY + "  \n \t  ", WITH_PATH | WITH_QUERY),
				Arguments.of("   " + TEST_PATH + TEST_QUERY + TEST_FRAGMENT + " \n\t\t\n  ", WITH_PATH | WITH_QUERY | WITH_FRAGMENT)
		);
	}

	@SuppressWarnings("unlikely-arg-type")
	@ParameterizedTest
	@MethodSource("provideDIDURLs")
	public void testDIDURL(String spec, int parts)
			throws MalformedDIDURLException, UnsupportedEncodingException {
		DIDURL url = new DIDURL(spec);
		StringBuilder urlBuilder = new StringBuilder();

		// getDid()
		if ((parts & WITH_DID) == WITH_DID) {
			assertEquals(new DID(TEST_DID), url.getDid());
			assertEquals(TEST_DID, url.getDid().toString());

			urlBuilder.append(TEST_DID);
		} else {
			assertNull(url.getDid());
		}

		// getPath()
		if ((parts & WITH_PATH) == WITH_PATH) {
			assertEquals(TEST_PATH, url.getPath());

			urlBuilder.append(TEST_PATH);
		} else {
			assertNull(url.getPath());
		}

		// getQuery(), getQueryString(), getQueryParameter(), hasQueryParameter()
		if ((parts & WITH_QUERY) == WITH_QUERY) {
			assertEquals(TEST_QUERY.substring(1), url.getQueryString());

			assertEquals(5, url.getQuery().size());

			assertEquals("qvalue", url.getQueryParameter("qkey"));
			assertEquals("true", url.getQueryParameter("test"));
			assertEquals("你好", URLDecoder.decode(url.getQueryParameter("hello"), "UTF-8"));
			assertEquals("啊", URLDecoder.decode(url.getQueryParameter("a"), "UTF-8"));
			assertNull(url.getQueryParameter("qkeyonly"));

			assertTrue(url.hasQueryParameter("qkeyonly"));
			assertTrue(url.hasQueryParameter("qkey"));
			assertTrue(url.hasQueryParameter("test"));
			assertTrue(url.hasQueryParameter("hello"));
			assertTrue(url.hasQueryParameter("a"));

			assertFalse(url.hasQueryParameter("notexist"));

			urlBuilder.append(TEST_QUERY);
		} else {
			assertNull(url.getQueryString());
			assertEquals(0, url.getQuery().size());

			assertNull(url.getQueryParameter("qkey"));
			assertFalse(url.hasQueryParameter("qkey"));
		}

		// getFragment()
		if ((parts & WITH_FRAGMENT) == WITH_FRAGMENT) {
			assertEquals(TEST_FRAGMENT.substring(1), url.getFragment());
			urlBuilder.append(TEST_FRAGMENT);
		} else {
			assertNull(url.getFragment());
		}

		String refURLString = urlBuilder.toString();
		DIDURL refURL = new DIDURL(refURLString);

		// toString()
		assertEquals(refURLString, url.toString());

		// toString(DID)
		int pos = (parts & WITH_DID) == WITH_DID ? TEST_DID.length() : 0;
		assertEquals(refURLString.substring(pos), url.toString(DID.valueOf(TEST_DID)));
		assertEquals(refURLString, url.toString(DID.valueOf("did:elastos:abc")));

		// equals()
		assertTrue(url.equals(refURL));
		assertTrue(url.equals(refURLString));

		String difURLString = refURLString + "_abc";
		DIDURL difURL = new DIDURL(difURLString);
		assertFalse(url.equals(difURL));
		assertFalse(url.equals(difURLString));

		// hashCode()
		assertEquals(refURL.hashCode(), url.hashCode());
		assertNotEquals(difURL.hashCode(), url.hashCode());
	}

	@SuppressWarnings("unlikely-arg-type")
	@ParameterizedTest
	@MethodSource("provideDIDURLs")
	public void testDIDURLWithContext(String spec, int parts)
			throws MalformedDIDURLException, UnsupportedEncodingException {
		DID context = new DID("did:elastos:foobar");

		DIDURL url = new DIDURL(context, spec);
		StringBuilder urlBuilder = new StringBuilder();

		// getDid()
		if ((parts & WITH_DID) == WITH_DID) {
			assertEquals(new DID(TEST_DID), url.getDid());
			assertEquals(TEST_DID, url.getDid().toString());

			urlBuilder.append(TEST_DID);
		} else {
			assertEquals(context, url.getDid());
			assertEquals(context.toString(), url.getDid().toString());

			urlBuilder.append(context.toString());
		}

		// getPath()
		if ((parts & WITH_PATH) == WITH_PATH) {
			assertEquals(TEST_PATH, url.getPath());

			urlBuilder.append(TEST_PATH);
		} else {
			assertNull(url.getPath());
		}

		// getQuery(), getQueryString(), getQueryParameter(), hasQueryParameter()
		if ((parts & WITH_QUERY) == WITH_QUERY) {
			assertEquals(TEST_QUERY.substring(1), url.getQueryString());

			assertEquals(5, url.getQuery().size());

			assertEquals("qvalue", url.getQueryParameter("qkey"));
			assertEquals("true", url.getQueryParameter("test"));
			assertEquals("你好", URLDecoder.decode(url.getQueryParameter("hello"), "UTF-8"));
			assertEquals("啊", URLDecoder.decode(url.getQueryParameter("a"), "UTF-8"));
			assertNull(url.getQueryParameter("qkeyonly"));

			assertTrue(url.hasQueryParameter("qkeyonly"));
			assertTrue(url.hasQueryParameter("qkey"));
			assertTrue(url.hasQueryParameter("test"));
			assertTrue(url.hasQueryParameter("hello"));
			assertTrue(url.hasQueryParameter("a"));

			assertFalse(url.hasQueryParameter("notexist"));

			urlBuilder.append(TEST_QUERY);
		} else {
			assertNull(url.getQueryString());
			assertEquals(0, url.getQuery().size());

			assertNull(url.getQueryParameter("qkey"));
			assertFalse(url.hasQueryParameter("qkey"));
		}

		// getFragment()
		if ((parts & WITH_FRAGMENT) == WITH_FRAGMENT) {
			assertEquals(TEST_FRAGMENT.substring(1), url.getFragment());
			urlBuilder.append(TEST_FRAGMENT);
		} else {
			assertNull(url.getFragment());
		}

		String refURLString = urlBuilder.toString();
		DIDURL refURL = new DIDURL(refURLString);

		// toString()
		assertEquals(refURLString, url.toString());

		// toString(DID)
		if ((parts & WITH_DID) == WITH_DID) {
			assertEquals(refURLString.substring(TEST_DID.length()),
					url.toString(DID.valueOf(TEST_DID)));
			assertEquals(refURLString, url.toString(context));
		} else {
			assertEquals(refURLString.substring(context.toString().length()),
					url.toString(context));
			assertEquals(refURLString, url.toString(DID.valueOf(TEST_DID)));
		}

		// equals()
		assertTrue(url.equals(refURL));
		assertTrue(url.equals(refURLString));

		String difURLString = refURLString + "_abc";
		DIDURL difURL = new DIDURL(difURLString);
		assertFalse(url.equals(difURL));
		assertFalse(url.equals(difURLString));

		// hashCode()
		assertEquals(refURL.hashCode(), url.hashCode());
		assertNotEquals(difURL.hashCode(), url.hashCode());
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testCompatibleWithPlainFragment() {
		String testURL = TEST_DID + "#test";

		DIDURL url1 = new DIDURL(testURL);
		assertEquals(testURL, url1.toString());
		assertEquals("test", url1.getFragment());
		assertTrue(url1.equals(testURL));

		DIDURL url2 = new DIDURL(DID.valueOf(TEST_DID), "test");
		assertEquals(testURL, url2.toString());
		assertEquals("test", url2.getFragment());
		assertTrue(url2.equals(testURL));

		assertTrue(url1.equals(url2));

		DIDURL url = new DIDURL("test");
		assertEquals("test", url.getFragment());
		assertEquals("#test", url.toString());
		assertTrue(url.equals("#test"));
	}

	private String trim(String str) {
		int start = 0;
		int limit = str.length();

		// trim the leading and trailing spaces
		while ((limit > 0) && (str.charAt(limit - 1) <= ' '))
			limit--;		//eliminate trailing whitespace

		while ((start < limit) && (str.charAt(start) <= ' '))
			start++;		// eliminate leading whitespace

		return str.substring(start, limit);
	}

	@SuppressWarnings("unlikely-arg-type")
	@ParameterizedTest
	@CsvSource({
			"did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld",
			"did:elastos:foobar/p.a_t-h/to-/resource_?te_st=tr_ue&ke.y=va_lue&na_me=foobar#helloworld_",
	  		"did:elastos:foobar/path_/to./resource_?test-=true.&ke.y_=va_lue.&name_=foobar.#helloworld_-.",
	  		"did:elastos:foobar/pa...th/to.../resource_-_?test-__.=true...&ke...y_---=va_lue.&name_=foo...bar.#helloworld_-.",
			"did:elastos:foobar/path/to/resou___rce?test=tr----ue&key=va----lue&name=foobar#hello....---world__",
	})
	public void testParseUrlWithSpecialChars(String spec) throws MalformedDIDException {
		DIDURL url = new DIDURL(spec);

		assertTrue(url.getDid().equals(new DID(DID.METHOD, "foobar")));

		String urlString = trim(spec);
		assertEquals(urlString, url.toString());
		assertTrue(url.equals(urlString));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"did1:elastos:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 4",
			"did:unknown:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld | Invalid did at: 0",
			"did:elastos:foobar:/path/to/resource?test=true&key=value&name=foobar#helloworld | Invalid did at: 0",
			"did:elastos:foobar/-path/to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 19",
			"did:elastos:foobar/._path/to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 19",
			"did:elastos:foobar/-._path/to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 19",
			"did:elastos:foobar/path/-to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 24",
			"did:elastos:foobar/path/.to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 24",
			"did:elastos:foobar/path/_to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 24",
			"did:elastos:foobar/path/*to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 24",
			"did:elastos:foobar/path/$to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 24",
			"did:elastos:foobar/path./$to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 25",
			"did:elastos:foobar/path/%to/resource?test=true&key=value&name=foobar#helloworld | Invalid hex char at: 25",
			"did:elastos:foobar/path/to//resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 27",
			"did:elastos:foobar/path/to/resource?test=true&&&key=value&name=foobar#helloworld | Invalid char at: 46",
			"did:elastos:foobar/path/to/resource?test=true&_key=value&name=foobar#helloworld | Invalid char at: 46",
			"did:elastos:foobar/path/to/resource?test=true&*key=value&name=foobar#helloworld | Invalid char at: 46",
			"did:elastos:foobar/path/to/resource?test=true&-key=value&name=foobar#helloworld | Invalid char at: 46",
			"did:elastos:foobar/path/to/resource?test=true.&-key=value&name=foobar#helloworld | Invalid char at: 47",
			"did:elastos:foobar/path/to/resource%20?test=true.&-key=value&name=foobar#helloworld | Invalid char at: 50",
			"did:elastos:foobar/path/to/resource?test=true&key=value&name==foobar#helloworld | Invalid char at: 61",
			"did:elastos:foobar/path/to/resource?test=true&key=value&name%=foobar#helloworld | Invalid hex char at: 61",
			"did:elastos:foobar/path/to/resource?test=true&key=va--lue&name%=foobar#helloworld | Invalid hex char at: 63",
			"did:elastos:foobar/path/to/resource?test=t.rue&ke.y=val_ue&nam-e=^foobar#helloworld | Invalid char at: 65",
			"did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar*#helloworld | Invalid char at: 67",
			"did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar?#helloworld | Invalid char at: 67",
			"did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar##helloworld | Invalid char at: 68",
			"did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld* | Invalid char at: 78",
			"did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld& | Invalid char at: 78",
			"did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld% | Invalid char at: 78",
	}, delimiter = '|')
	public void testParseWrongUrl(String spec, String error) {
		MalformedDIDURLException e = assertThrows(MalformedDIDURLException.class,
				() -> { new DIDURL(spec); });

		assertEquals(error, e.getMessage());
	}

	@Test
	public void testParseWrongUrlWithPadding() {
		MalformedDIDURLException e = assertThrows(MalformedDIDURLException.class,
				() -> { new DIDURL("       \t did:elastos:foobar/-path/to/resource?test=true&key=value&name=foobar#helloworld"); });

		assertEquals("Invalid char at: 28", e.getMessage());
	}

	@Test
	public void testParseEmptyAndNull() {
		assertThrows(IllegalArgumentException.class,
				() -> { new DIDURL(null); });

		assertThrows(IllegalArgumentException.class,
				() -> { new DIDURL(""); });

		MalformedDIDURLException e = assertThrows(MalformedDIDURLException.class,
				() -> { new DIDURL("		   "); });

		assertEquals("empty DIDURL string", e.getMessage());
	}
}
