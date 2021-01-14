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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.elastos.did.exception.DIDException;
import org.elastos.did.utils.DIDTestExtension;
import org.elastos.did.utils.TestConfig;
import org.elastos.did.utils.TestData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(DIDTestExtension.class)
public class MnemonicTest {
	private TestData testData;

    @BeforeEach
    public void beforeEach() throws DIDException {
    	testData = new TestData(true);
    }

    @AfterEach
    public void afterEach() {
    	testData.cleanup();
    }

    @Test
	public void testBuiltinWordList() throws DIDException {
		String[] languages = {
				Mnemonic.DEFAULT,
				Mnemonic.CHINESE_SIMPLIFIED,
				Mnemonic.CHINESE_TRADITIONAL,
				Mnemonic.CZECH,
				Mnemonic.ENGLISH,
				Mnemonic.FRENCH,
				Mnemonic.ITALIAN,
				Mnemonic.JAPANESE,
				Mnemonic.KOREAN,
				Mnemonic.SPANISH
		};

		for (String lang : languages) {
			Mnemonic mc = Mnemonic.getInstance(lang);
			String mnemonic = mc.generate();
			assertTrue(mc.isValid(mnemonic));

			DIDStore store = testData.getStore();
	    	RootIdentity.create(lang, mnemonic, TestConfig.passphrase,
	    			true, store, TestConfig.storePass);

			mnemonic = mnemonic + "z";
			assertFalse(mc.isValid(mnemonic));
		}
	}

	@Test
	public void testFrenchMnemonic() throws DIDException {
		String mnemonic = "remarque séduire massif boire horde céleste exact dribbler pulpe prouesse vagabond opale";

		Mnemonic mc = Mnemonic.getInstance(Mnemonic.FRENCH);
		assertTrue(mc.isValid(mnemonic));
	}
}
