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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(DIDTestExtension.class)
public class VerifiableCredentialTest {
	private TestData testData;

    @BeforeEach
    public void beforeEach() throws DIDException {
    	testData = new TestData();
    	testData.init(true);
    }

    @Test
	public void TestKycCredential() throws DIDException, IOException {
		DIDDocument issuer = testData.loadTestIssuer();
		DIDDocument test = testData.loadTestDocument();

		VerifiableCredential vc = testData.loadEmailCredential();

		assertEquals(new DIDURL(test.getSubject(), "email"), vc.getId());

		assertTrue(Arrays.asList(vc.getType()).contains("BasicProfileCredential"));
		assertTrue(Arrays.asList(vc.getType()).contains("InternetAccountCredential"));
		assertTrue(Arrays.asList(vc.getType()).contains("EmailCredential"));

		assertEquals(issuer.getSubject(), vc.getIssuer());
		assertEquals(test.getSubject(), vc.getSubject().getId());

		assertEquals("john@example.com", vc.getSubject().getProperty("email"));

		assertNotNull(vc.getIssuanceDate());
		assertNotNull(vc.getExpirationDate());

		assertFalse(vc.isExpired());
		assertTrue(vc.isGenuine());
		assertTrue(vc.isValid());
	}

	@Test
	public void TestSelfProclaimedCredential() throws DIDException, IOException {
		DIDDocument test = testData.loadTestDocument();

		VerifiableCredential vc = testData.loadProfileCredential();

		assertEquals(new DIDURL(test.getSubject(), "profile"), vc.getId());

		assertTrue(Arrays.asList(vc.getType()).contains("BasicProfileCredential"));
		assertTrue(Arrays.asList(vc.getType()).contains("SelfProclaimedCredential"));

		assertEquals(test.getSubject(), vc.getIssuer());
		assertEquals(test.getSubject(), vc.getSubject().getId());

		assertEquals("John", vc.getSubject().getProperty("name"));
		assertEquals("Male", vc.getSubject().getProperty("gender"));
		assertEquals("Singapore", vc.getSubject().getProperty("nation"));
		assertEquals("English", vc.getSubject().getProperty("language"));
		assertEquals("john@example.com", vc.getSubject().getProperty("email"));
		assertEquals("@john", vc.getSubject().getProperty("twitter"));

		assertNotNull(vc.getIssuanceDate());
		assertNotNull(vc.getExpirationDate());

		assertFalse(vc.isExpired());
		assertTrue(vc.isGenuine());
		assertTrue(vc.isValid());
	}

	@Test
	public void testParseAndSerializeKycCredential()
			throws DIDException, IOException {
		String json = testData.loadTwitterVcNormalizedJson();
		VerifiableCredential normalized = VerifiableCredential.parse(json);

		json = testData.loadTwitterVcCompactJson();
		VerifiableCredential compact = VerifiableCredential.parse(json);

		VerifiableCredential vc = testData.loadTwitterCredential();

		assertEquals(testData.loadTwitterVcNormalizedJson(), normalized.toString(true));
		assertEquals(testData.loadTwitterVcNormalizedJson(), compact.toString(true));
		assertEquals(testData.loadTwitterVcNormalizedJson(), vc.toString(true));

		// Don't check the compact mode anymore
		/*
		assertEquals(testData.loadTwitterVcCompactJson(), normalized.toString(false));
		assertEquals(testData.loadTwitterVcCompactJson(), compact.toString(false));
		assertEquals(testData.loadTwitterVcCompactJson(), vc.toString(false));
		*/
	}

	@Test
	public void testParseAndSerializeSelfProclaimedCredential()
			throws DIDException, IOException {
		String json = testData.loadProfileVcNormalizedJson();
		VerifiableCredential normalized = VerifiableCredential.parse(json);

		json = testData.loadProfileVcCompactJson();
		VerifiableCredential compact = VerifiableCredential.parse(json);

		VerifiableCredential vc = testData.loadProfileCredential();

		assertEquals(testData.loadProfileVcNormalizedJson(), normalized.toString(true));
		assertEquals(testData.loadProfileVcNormalizedJson(), compact.toString(true));
		assertEquals(testData.loadProfileVcNormalizedJson(), vc.toString(true));

		// Don't check the compact mode anymore
		/*
		assertEquals(testData.loadProfileVcCompactJson(), normalized.toString(false));
		assertEquals(testData.loadProfileVcCompactJson(), compact.toString(false));
		assertEquals(testData.loadProfileVcCompactJson(), vc.toString(false));
		*/
	}

	@Test
	public void testParseAndSerializeJsonCredential()
			throws DIDException, IOException {
		String json = testData.loadJsonVcNormalizedJson();
		VerifiableCredential normalized = VerifiableCredential.parse(json);

		json = testData.loadJsonVcCompactJson();
		VerifiableCredential compact = VerifiableCredential.parse(json);

		VerifiableCredential vc = testData.loadJsonCredential();

		assertEquals(testData.loadJsonVcNormalizedJson(), normalized.toString(true));
		assertEquals(testData.loadJsonVcNormalizedJson(), compact.toString(true));
		assertEquals(testData.loadJsonVcNormalizedJson(), vc.toString(true));

		// Don't check the compact mode anymore
		/*
		assertEquals(testData.loadJsonVcCompactJson(), normalized.toString(false));
		assertEquals(testData.loadJsonVcCompactJson(), compact.toString(false));
		assertEquals(testData.loadJsonVcCompactJson(), vc.toString(false));
		*/
	}
}
