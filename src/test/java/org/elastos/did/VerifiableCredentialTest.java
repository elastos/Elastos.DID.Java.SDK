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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Arrays;

import org.elastos.did.exception.DIDException;
import org.elastos.did.utils.DIDTestExtension;
import org.elastos.did.utils.TestData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

@ExtendWith(DIDTestExtension.class)
public class VerifiableCredentialTest {
	private TestData testData;

    @BeforeEach
    public void beforeEach() throws DIDException {
    	testData = new TestData();
    }

    @AfterEach
    public void afterEach() {
    	testData.cleanup();
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void TestKycCredential(int version) throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(version);

    	DIDDocument issuer = cd.getDocument("issuer");
		DIDDocument user = cd.getDocument("user1");

		VerifiableCredential vc = cd.getCredential("user1", "twitter");

		assertEquals(new DIDURL(user.getSubject(), "#twitter"), vc.getId());

		assertTrue(Arrays.asList(vc.getType()).contains("InternetAccountCredential"));
		assertTrue(Arrays.asList(vc.getType()).contains("TwitterCredential"));

		assertEquals(issuer.getSubject(), vc.getIssuer());
		assertEquals(user.getSubject(), vc.getSubject().getId());

		assertEquals("@john", vc.getSubject().getProperty("twitter"));

		assertNotNull(vc.getIssuanceDate());
		assertNotNull(vc.getExpirationDate());

		assertFalse(vc.isSelfProclaimed());
		assertFalse(vc.isExpired());
		assertTrue(vc.isGenuine());
		assertTrue(vc.isValid());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void TestSelfProclaimedCredential(int version) throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(version);

    	DIDDocument user = cd.getDocument("user1");
		VerifiableCredential vc = cd.getCredential("user1", "passport");

		assertEquals(new DIDURL(user.getSubject(), "#passport"), vc.getId());

		assertTrue(Arrays.asList(vc.getType()).contains("BasicProfileCredential"));
		assertTrue(Arrays.asList(vc.getType()).contains("SelfProclaimedCredential"));

		assertEquals(user.getSubject(), vc.getIssuer());
		assertEquals(user.getSubject(), vc.getSubject().getId());

		assertEquals("Singapore", vc.getSubject().getProperty("nation"));
		assertEquals("S653258Z07", vc.getSubject().getProperty("passport"));

		assertNotNull(vc.getIssuanceDate());
		assertNotNull(vc.getExpirationDate());

		assertTrue(vc.isSelfProclaimed());
		assertFalse(vc.isExpired());
		assertTrue(vc.isGenuine());
		assertTrue(vc.isValid());
	}

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
	public void TestJsonCredential(int version) throws DIDException, IOException {
    	TestData.CompatibleData cd = testData.getCompatibleData(version);

    	DIDDocument issuer = cd.getDocument("issuer");
    	DIDDocument user = cd.getDocument("user1");
		VerifiableCredential vc = cd.getCredential("user1", "json");

		assertEquals(new DIDURL(user.getSubject(), "#json"), vc.getId());

		assertTrue(Arrays.asList(vc.getType()).contains("JsonCredential"));
		assertTrue(Arrays.asList(vc.getType()).contains("TestCredential"));

		assertEquals(issuer.getSubject(), vc.getIssuer());
		assertEquals(user.getSubject(), vc.getSubject().getId());

		assertEquals("Technologist", vc.getSubject().getProperty("Description"));
		assertEquals(true, vc.getSubject().getProperty("booleanValue"));
		assertEquals(1234, vc.getSubject().getProperty("numberValue"));

		assertNotNull(vc.getIssuanceDate());
		assertNotNull(vc.getExpirationDate());

		assertFalse(vc.isSelfProclaimed());
		assertFalse(vc.isExpired());
		assertTrue(vc.isGenuine());
		assertTrue(vc.isValid());
	}

    @ParameterizedTest
    @CsvSource({"1,user1,twitter", "1,user1,passport", "1,user1,json",
    		"2,user1,twitter", "2,user1,passport", "2,user1,json"})
	public void testParseAndSerializeJsonCredential(int version, String did, String vc)
			throws DIDException, IOException {
	   	TestData.CompatibleData cd = testData.getCompatibleData(version);

		String normalizedJson = cd.getCredentialJson(did, vc, "normalized");
		VerifiableCredential normalized = VerifiableCredential.parse(normalizedJson);

		String compactJson = cd.getCredentialJson(did, vc, "compact");
		VerifiableCredential compact = VerifiableCredential.parse(compactJson);

		VerifiableCredential credential = cd.getCredential(did, vc);

		assertEquals(normalizedJson, normalized.toString(true));
		assertEquals(normalizedJson, compact.toString(true));
		assertEquals(normalizedJson, credential.toString(true));

		// Don't check the compact mode for the old versions
		if (cd.isLatestVersion()) {
			assertEquals(compactJson, normalized.toString(false));
			assertEquals(compactJson, compact.toString(false));
			assertEquals(compactJson, credential.toString(false));
		}
	}
}
