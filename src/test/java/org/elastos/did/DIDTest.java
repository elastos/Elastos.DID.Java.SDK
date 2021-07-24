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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.elastos.did.exception.MalformedDIDException;
import org.elastos.did.utils.DIDTestExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

@ExtendWith(DIDTestExtension.class)
public class DIDTest {
	@SuppressWarnings("unlikely-arg-type")
	@ParameterizedTest
	@ValueSource(strings = {
			"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
			"     did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
			"    \n\t  did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
			"      did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN        ",
			"    \n \t  did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN     ",
			"\n\t     did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN \t  \n  ",
			"\t \n did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN     \n   \t",
			" \n \t\t did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN\t     \n   \t  ",
	})
	public void testDid(String spec) throws MalformedDIDException {
		String didString = "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN";
		String methodSpecificId = "icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN";

		// parse
		DID did = new DID(spec);
		assertEquals(DID.METHOD, did.getMethod());
		assertEquals(methodSpecificId, did.getMethodSpecificId());
		assertEquals(didString, did.toString());


		DID ref = new DID(DID.METHOD, methodSpecificId);
		DID dif = new DID(DID.METHOD, "abc");

		// equals
		assertTrue(did.equals(didString));
		assertTrue(did.equals(ref));
		assertFalse(did.equals(dif));

		// hash code
		assertEquals(ref.hashCode(), did.hashCode());
		assertNotEquals(dif.hashCode(), did.hashCode());
	}

	@ParameterizedTest
	@CsvSource({
			"did:elastos:ic-J4_z2D.ULrHEzYSvjKNJpKyhqFDxvYV7pN, ic-J4_z2D.ULrHEzYSvjKNJpKyhqFDxvYV7pN",
			"did:elastos:icJ.4z2D.ULrHE.zYSvj-KNJp_KyhqFDxvYV7pN-, icJ.4z2D.ULrHE.zYSvj-KNJp_KyhqFDxvYV7pN-",
			"did:elastos:icJ.4z2D.ULrHE.zYSvj-KNJp_KyhqFDxvYV7pN-_, icJ.4z2D.ULrHE.zYSvj-KNJp_KyhqFDxvYV7pN-_",
			"did:elastos:icJ.4z2D.ULrHE.zYSvj-KNJp_KyhqFDxvYV7pN-_., icJ.4z2D.ULrHE.zYSvj-KNJp_KyhqFDxvYV7pN-_.",
			"did:elastos:icJ.4z2D.ULrHE.zYSvj-KNJp_KyhqFDxvYV7pN-_.-, icJ.4z2D.ULrHE.zYSvj-KNJp_KyhqFDxvYV7pN-_.-"
	 })
	public void testParseDidWithSpecialChars(String spec, String methodSpecificId) throws MalformedDIDException {
		DID did = new DID(spec);
		assertEquals(DID.METHOD, did.getMethod());
		assertEquals(methodSpecificId, did.getMethodSpecificId());
		assertEquals(spec, did.toString());
	}

	@ParameterizedTest
	@CsvSource(value = {
			"did1:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid DID schema: 'did1', at: 0",
			"d-i_d:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid DID schema: 'd-i_d', at: 0",
			"d-i.d:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid DID schema: 'd-i.d', at: 0",
			"foo:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid DID schema: 'foo', at: 0",
			"foo:bar:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid DID schema: 'foo', at: 0",
			"did:bar:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Unknown DID method: 'bar', at: 4",
			"did:elastos-:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Unknown DID method: 'elastos-', at: 4",
			"did:e-l.a_stos-:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Unknown DID method: 'e-l.a_stos-', at: 4",
			"-did:elastos:icJ4z2%DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 0",
			".did:elastos:icJ4z2%DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 0",
			"_did:elastos:icJ4z2%DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 0",
			"did :elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 3",
			"did: elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 4",
			"did:-elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 4",
			"did:_elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 4",
			"did:.elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 4",
			"did:*elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 4",
			"did:/elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 4",
			"did:ela*stos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 7",
			"did:elastos\t:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 11",
			"did:elastos: icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 12",
			"did:elastos:-icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 12",
			"did:elastos:_icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 12",
			"did:elastos:.icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 12",
			"did:elastos:icJ4z2%DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid char at: 18",
			"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN$ | Invalid char at: 46",
			":elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Invalid DID schema: '', at: 0",
			"did::icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN | Unknown DID method: '', at: 4",
			"did:elastos: | Missing id string at: 12",
			"did:elastos | Missing id string at: 11",
			"did:elastos:abc:  |  Invalid char at: 15"
	}, delimiter = '|')
	public void testParseWrongDid(String spec, String error) {
		MalformedDIDException e = assertThrows(MalformedDIDException.class,
				() -> { new DID(spec); });

		assertEquals(error, e.getMessage());
	}

	@Test
	public void testParseWrongDidWithPadding() {
		MalformedDIDException e = assertThrows(MalformedDIDException.class,
				() -> { new DID("   d-i.d:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN"); });

		assertEquals("Invalid DID schema: 'd-i.d', at: 3", e.getMessage());
	}

	@Test
	public void testParseEmptyAndNull() {
		assertThrows(IllegalArgumentException.class,
				() -> { new DID(null); });

		assertThrows(IllegalArgumentException.class,
				() -> { new DID(""); });

		MalformedDIDException e = assertThrows(MalformedDIDException.class,
				() -> { new DID("		   "); });

		assertEquals("empty DID string", e.getMessage());
	}
}
