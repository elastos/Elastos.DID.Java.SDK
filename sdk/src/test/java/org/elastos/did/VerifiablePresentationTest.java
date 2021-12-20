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
import org.junit.jupiter.params.provider.CsvSource;
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
	@ValueSource(strings = {"1", "2", "2.2"})
	public void testReadPresentationNonempty(String version) throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(version);

    	// For integrity check
		cd.getDocument("issuer");
		DIDDocument user = cd.getDocument("user1");
		VerifiablePresentation vp = cd.getPresentation("user1", "nonempty");

		if (Float.valueOf(version) < 2.0)
			assertNull(vp.getId());
		else
			assertNotNull(vp.getId());
		assertEquals(1, vp.getType().size());
		assertEquals(VerifiablePresentation.DEFAULT_PRESENTATION_TYPE, vp.getType().get(0));
		assertEquals(user.getSubject(), vp.getHolder());

		assertEquals(4, vp.getCredentialCount());
		List<VerifiableCredential> vcs = vp.getCredentials();
		for (VerifiableCredential vc : vcs) {
			assertEquals(user.getSubject(), vc.getSubject().getId());

			assertTrue(vc.getId().getFragment().equals("profile")
					|| vc.getId().getFragment().equals("email")
					|| vc.getId().getFragment().equals("twitter")
					|| vc.getId().getFragment().equals("passport"));
		}

		assertNotNull(vp.getCredential(new DIDURL(vp.getHolder(), "#profile")));
		assertNotNull(vp.getCredential(new DIDURL(vp.getHolder(), "#email")));
		assertNotNull(vp.getCredential(new DIDURL(vp.getHolder(), "#twitter")));
		assertNotNull(vp.getCredential(new DIDURL(vp.getHolder(), "#passport")));
		assertNull(vp.getCredential(new DIDURL(vp.getHolder(), "#notExist")));

		assertTrue(vp.isGenuine());
		assertTrue(vp.isValid());
	}

	@ParameterizedTest
	@ValueSource(strings = {"1", "2", "2.2"})
	public void testReadPresentationEmpty(String version) throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(version);

    	// For integrity check
		cd.getDocument("issuer");
		DIDDocument user = cd.getDocument("user1");
		VerifiablePresentation vp = cd.getPresentation("user1", "empty");

		if (Float.valueOf(version) < 2.0)
			assertNull(vp.getId());
		else
			assertNotNull(vp.getId());
		assertEquals(1, vp.getType().size());
		assertEquals(VerifiablePresentation.DEFAULT_PRESENTATION_TYPE, vp.getType().get(0));
		assertEquals(user.getSubject(), vp.getHolder());

		assertEquals(0, vp.getCredentialCount());
		assertNull(vp.getCredential(new DIDURL(vp.getHolder(), "#notExist")));

		assertTrue(vp.isGenuine());
		assertTrue(vp.isValid());
	}

    @ParameterizedTest
    @CsvSource({
    	"1,user1,empty",
    	"1,user1,nonempty",
    	"2,user1,empty",
    	"2,user1,nonempty",
    	"2,user1,optionalattrs",
    	"2,foobar,empty",
    	"2,foobar,nonempty",
    	"2,foobar,optionalattrs",
    	"2.2,user1,empty",
    	"2.2,user1,nonempty",
    	"2.2,user1,optionalattrs",
    	"2.2,foobar,empty",
    	"2.2,foobar,nonempty",
    	"2.2,foobar,optionalattrs"
    })
	public void testParseAndSerialize(String version, String did, String presentation)
			throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(version);
    	// For integrity check
    	cd.loadAll();

		VerifiablePresentation vp = cd.getPresentation(did, presentation);

		assertNotNull(vp);
		assertTrue(vp.isGenuine());
		assertTrue(vp.isValid());

		String normalizedJson = cd.getPresentationJson(did, presentation, "normalized");

		VerifiablePresentation normalized = VerifiablePresentation.parse(normalizedJson);
		assertNotNull(normalized);
		assertTrue(normalized.isGenuine());
		assertTrue(normalized.isValid());

		assertEquals(normalizedJson, normalized.toString(true));
		assertEquals(normalizedJson, vp.toString(true));
	}

    @ParameterizedTest
    @CsvSource({
    	"1,user1,empty",
    	"1,user1,nonempty",
    	"2,user1,empty",
    	"2,user1,nonempty",
    	"2,user1,optionalattrs",
    	"2,foobar,empty",
    	"2,foobar,nonempty",
    	"2,foobar,optionalattrs",
    	"2.2,user1,empty",
    	"2.2,user1,nonempty",
    	"2.2,user1,optionalattrs",
    	"2.2,foobar,empty",
    	"2.2,foobar,nonempty",
    	"2.2,foobar,optionalattrs"
    })
	public void testGenuineAndValidWithListener(String version, String did, String presentation)
			throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(version);
    	// For integrity check
    	cd.loadAll();

	   	VerificationEventListener listener = VerificationEventListener.getDefault("  ", "- ", "* ");

		VerifiablePresentation vp = cd.getPresentation(did, presentation);

		assertNotNull(vp);

		assertTrue(vp.isGenuine(listener));
		assertTrue(listener.toString().startsWith("  - "));
		listener.reset();

		assertTrue(vp.isValid(listener));
		assertTrue(listener.toString().startsWith("  - "));
		listener.reset();
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

		assertNull(vp.getId());
		assertEquals(1, vp.getType().size());
		assertEquals(VerifiablePresentation.DEFAULT_PRESENTATION_TYPE, vp.getType().get(0));
		assertEquals(doc.getSubject(), vp.getHolder());

		assertEquals(4, vp.getCredentialCount());
		List<VerifiableCredential> vcs = vp.getCredentials();
		for (VerifiableCredential vc : vcs) {
			assertEquals(doc.getSubject(), vc.getSubject().getId());

			assertTrue(vc.getId().getFragment().equals("profile")
					|| vc.getId().getFragment().equals("email")
					|| vc.getId().getFragment().equals("twitter")
					|| vc.getId().getFragment().equals("passport"));
		}

		assertNotNull(vp.getCredential(new DIDURL(vp.getHolder(), "#profile")));
		assertNotNull(vp.getCredential(new DIDURL(vp.getHolder(), "#email")));
		assertNotNull(vp.getCredential(new DIDURL(vp.getHolder(), "#twitter")));
		assertNotNull(vp.getCredential(new DIDURL(vp.getHolder(), "#passport")));
		assertNull(vp.getCredential(new DIDURL(vp.getHolder(), "#notExist")));

		assertTrue(vp.isGenuine());
		assertTrue(vp.isValid());
	}

    @Test
 	public void testBuildNonemptyWithOptionalAttrs() throws DIDException, IOException {

		TestData.InstantData td = testData.getInstantData();
		DIDDocument doc = td.getUser1Document();

		VerifiablePresentation.Builder pb = VerifiablePresentation.createFor(
				doc.getSubject(), store);

		VerifiablePresentation vp = pb
				.id("#test-vp")
				.type("TestPresentation", "https://example.com/credential/v1")
				.credentials(doc.getCredential("#profile"))
				.credentials(doc.getCredential("#email"))
				.credentials(td.getUser1TwitterCredential())
				.credentials(td.getUser1PassportCredential())
				.realm("https://example.com/")
				.nonce("873172f58701a9ee686f0630204fee59")
				.seal(TestConfig.storePass);

		assertNotNull(vp);

		assertEquals(new DIDURL(doc.getSubject(), "#test-vp"), vp.getId());
		assertEquals(2, vp.getType().size());
		assertEquals("TestPresentation", vp.getType().get(0));
		assertEquals("VerifiablePresentation", vp.getType().get(1));
		assertEquals(doc.getSubject(), vp.getHolder());

		assertEquals(4, vp.getCredentialCount());
		List<VerifiableCredential> vcs = vp.getCredentials();
		for (VerifiableCredential vc : vcs) {
			assertEquals(doc.getSubject(), vc.getSubject().getId());

			assertTrue(vc.getId().getFragment().equals("profile")
					|| vc.getId().getFragment().equals("email")
					|| vc.getId().getFragment().equals("twitter")
					|| vc.getId().getFragment().equals("passport"));
		}

		assertNotNull(vp.getCredential(new DIDURL(vp.getHolder(), "#profile")));
		assertNotNull(vp.getCredential(new DIDURL(vp.getHolder(), "#email")));
		assertNotNull(vp.getCredential(new DIDURL(vp.getHolder(), "#twitter")));
		assertNotNull(vp.getCredential(new DIDURL(vp.getHolder(), "#passport")));
		assertNull(vp.getCredential(new DIDURL(vp.getHolder(), "#notExist")));

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

		assertNull(vp.getId());
		assertEquals(1, vp.getType().size());
		assertEquals(VerifiablePresentation.DEFAULT_PRESENTATION_TYPE, vp.getType().get(0));
		assertEquals(doc.getSubject(), vp.getHolder());

		assertEquals(0, vp.getCredentialCount());
		assertNull(vp.getCredential(new DIDURL(vp.getHolder(), "#notExist")));

		assertTrue(vp.isGenuine());
		assertTrue(vp.isValid());
	}

    @Test
	public void testBuildEmptyWithOptionsAttrs() throws DIDException, IOException {
		DIDDocument doc = testData.getInstantData().getUser1Document();

		VerifiablePresentation.Builder pb = VerifiablePresentation.createFor(
				doc.getSubject(), store);

		VerifiablePresentation vp = pb
				.id("#test-vp")
				.type("TestPresentation", "https://example.com/credential/v1")
				.type("SessionPresentation", "https://session.com/credential/v1")
				.realm("https://example.com/")
				.nonce("873172f58701a9ee686f0630204fee59")
				.seal(TestConfig.storePass);

		assertNotNull(vp);

		assertEquals(new DIDURL(doc.getSubject(), "#test-vp"), vp.getId());
		assertEquals(3, vp.getType().size());
		assertEquals("SessionPresentation", vp.getType().get(0));
		assertEquals("TestPresentation", vp.getType().get(1));
		assertEquals("VerifiablePresentation", vp.getType().get(2));
		assertEquals(doc.getSubject(), vp.getHolder());

		assertEquals(0, vp.getCredentialCount());
		assertNull(vp.getCredential(new DIDURL(vp.getHolder(), "#notExist")));

		assertTrue(vp.isGenuine());
		assertTrue(vp.isValid());
	}
}
