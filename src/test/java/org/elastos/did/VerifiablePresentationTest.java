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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;

import org.elastos.did.exception.DIDException;
import org.elastos.did.utils.DIDTestExtension;
import org.elastos.did.utils.TestConfig;
import org.elastos.did.utils.TestData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@ExtendWith(DIDTestExtension.class)
public class VerifiablePresentationTest {
	private TestData testData;
	private DIDStore store;

    @BeforeEach
    public void beforeEach() throws DIDException {
    	testData = new TestData();
    	store = testData.getStore();
    }

    @AfterEach
    public void afterEach() {
    	testData.cleanup();
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testReadPresentationNonempty(int version) throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(version);

    	// For integrity check
		cd.getDIDDocument("issuer");
		DIDDocument user = cd.getDIDDocument("user1");
		VerifiablePresentation vp = cd.getPresentation("user1", "nonempty");

		assertEquals(VerifiablePresentation.DEFAULT_PRESENTATION_TYPE, vp.getType());
		assertEquals(user.getSubject(), vp.getSigner());

		assertEquals(4, vp.getCredentialCount());
		List<VerifiableCredential> vcs = vp.getCredentials();
		for (VerifiableCredential vc : vcs) {
			assertEquals(user.getSubject(), vc.getSubject().getId());

			assertTrue(vc.getId().getFragment().equals("profile")
					|| vc.getId().getFragment().equals("email")
					|| vc.getId().getFragment().equals("twitter")
					|| vc.getId().getFragment().equals("passport"));
		}

		assertNotNull(vp.getCredential(new DIDURL(vp.getSigner(), "profile")));
		assertNotNull(vp.getCredential(new DIDURL(vp.getSigner(), "email")));
		assertNotNull(vp.getCredential(new DIDURL(vp.getSigner(), "twitter")));
		assertNotNull(vp.getCredential(new DIDURL(vp.getSigner(), "passport")));
		assertNull(vp.getCredential(new DIDURL(vp.getSigner(), "notExist")));

		assertTrue(vp.isGenuine());
		assertTrue(vp.isValid());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testReadPresentationEmpty(int version) throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(version);

    	// For integrity check
		cd.getDIDDocument("issuer");
		DIDDocument user = cd.getDIDDocument("user1");
		VerifiablePresentation vp = cd.getPresentation("user1", "empty");

		assertEquals(VerifiablePresentation.DEFAULT_PRESENTATION_TYPE, vp.getType());
		assertEquals(user.getSubject(), vp.getSigner());

		assertEquals(0, vp.getCredentialCount());
		assertNull(vp.getCredential(new DIDURL(vp.getSigner(), "notExist")));

		assertTrue(vp.isGenuine());
		assertTrue(vp.isValid());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testParseAndSerializeNonempty(int version) throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(version);

    	// For integrity check
		cd.getDIDDocument("issuer");
		cd.getDIDDocument("user1");
		VerifiablePresentation vp = cd.getPresentation("user1", "nonempty");

		assertNotNull(vp);
		assertTrue(vp.isGenuine());
		assertTrue(vp.isValid());

		String normalizedJson = cd.getPresentationJson("user1", "nonempty", "normalized");

		VerifiablePresentation normalized = VerifiablePresentation.parse(normalizedJson);
		assertNotNull(normalized);
		assertTrue(normalized.isGenuine());
		assertTrue(normalized.isValid());

		System.out.println(normalizedJson);
		System.out.println(normalized.toString(true));
		System.out.println(vp.toString(true));

		assertEquals(normalizedJson, normalized.toString(true));
		assertEquals(normalizedJson, vp.toString(true));
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void testParseAndSerializeEmpty(int version) throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(version);

    	// For integrity check
		cd.getDIDDocument("issuer");
		cd.getDIDDocument("user1");
		VerifiablePresentation vp = cd.getPresentation("user1", "empty");

		assertNotNull(vp);
		assertTrue(vp.isGenuine());
		assertTrue(vp.isValid());

		String normalizedJson = cd.getPresentationJson("user1", "empty", "normalized");

		VerifiablePresentation normalized = VerifiablePresentation.parse(normalizedJson);
		assertNotNull(normalized);
		assertTrue(normalized.isGenuine());
		assertTrue(normalized.isValid());

		assertEquals(normalizedJson, normalized.toString(true));
		assertEquals(normalizedJson, vp.toString(true));
	}

	@Test
	public void testBuildNonempty() throws DIDException, IOException {
		TestData.InstantData td = testData.getInstantData();
		DIDDocument doc = td.getUser1Document();

		VerifiablePresentation.Builder pb = VerifiablePresentation.createFor(
				doc.getSubject(), store);

		VerifiablePresentation vp = pb
				.credentials(doc.getCredential("#profile"))
				.credentials(doc.getCredential("#email"))
				.credentials(td.getUser1TwitterCredential())
				.credentials(td.getUser1PassportCredential())
				.realm("https://example.com/")
				.nonce("873172f58701a9ee686f0630204fee59")
				.seal(TestConfig.storePass);

		assertNotNull(vp);

		assertEquals(VerifiablePresentation.DEFAULT_PRESENTATION_TYPE, vp.getType());
		assertEquals(doc.getSubject(), vp.getSigner());

		assertEquals(4, vp.getCredentialCount());
		List<VerifiableCredential> vcs = vp.getCredentials();
		for (VerifiableCredential vc : vcs) {
			assertEquals(doc.getSubject(), vc.getSubject().getId());

			assertTrue(vc.getId().getFragment().equals("profile")
					|| vc.getId().getFragment().equals("email")
					|| vc.getId().getFragment().equals("twitter")
					|| vc.getId().getFragment().equals("passport"));
		}

		assertNotNull(vp.getCredential(new DIDURL(vp.getSigner(), "profile")));
		assertNotNull(vp.getCredential(new DIDURL(vp.getSigner(), "email")));
		assertNotNull(vp.getCredential(new DIDURL(vp.getSigner(), "twitter")));
		assertNotNull(vp.getCredential(new DIDURL(vp.getSigner(), "passport")));
		assertNull(vp.getCredential(new DIDURL(vp.getSigner(), "notExist")));

		assertTrue(vp.isGenuine());
		assertTrue(vp.isValid());
	}

	@Test
	public void testBuildEmpty() throws DIDException, IOException {
		DIDDocument doc = testData.getInstantData().getUser1Document();

		VerifiablePresentation.Builder pb = VerifiablePresentation.createFor(
				doc.getSubject(), store);

		VerifiablePresentation vp = pb
				.realm("https://example.com/")
				.nonce("873172f58701a9ee686f0630204fee59")
				.seal(TestConfig.storePass);

		assertNotNull(vp);

		assertEquals(VerifiablePresentation.DEFAULT_PRESENTATION_TYPE, vp.getType());
		assertEquals(doc.getSubject(), vp.getSigner());

		assertEquals(0, vp.getCredentialCount());
		assertNull(vp.getCredential(new DIDURL(vp.getSigner(), "notExist")));

		assertTrue(vp.isGenuine());
		assertTrue(vp.isValid());
	}
}
