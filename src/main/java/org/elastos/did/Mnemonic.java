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
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.StringJoiner;

import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.crypto.MnemonicException;
import org.elastos.did.exception.DIDException;

/**
 * The class represents the mnemonic content.
 */
public class Mnemonic {
	/**
	 * The default language is English.
	 */
	public static final String DEFAULT = null;

	/**
	 * language: "chinese_simplified"
	 */
	public static final String CHINESE_SIMPLIFIED = "chinese_simplified";

	/**
	 * language: "chinese_traditional"
	 */
	public static final String CHINESE_TRADITIONAL = "chinese_traditional";

	/**
	 * language: "czech"
	 */
	public static final String CZECH = "czech";

	/**
	 * language: "english"
	 */
	public static final String ENGLISH = "english";

	/**
	 * language: "french"
	 */
	public static final String FRENCH = "french";

	/**
	 * language: "italian"
	 */
	public static final String ITALIAN = "italian";

	/**
	 * language: "japanese"
	 */
	public static final String JAPANESE = "japanese";

	/**
	 * language: "korean"
	 */
	public static final String KOREAN = "korean";

	/**
	 * language: "spanish"
	 */
	public static final String SPANISH = "spanish";

	private static final int TWELVE_WORDS_ENTROPY = 16;

	private MnemonicCode mc;

	private static HashMap<String, Mnemonic> mcTable = new HashMap<String, Mnemonic>(4);

	private Mnemonic(MnemonicCode mc) {
		this.mc = mc;
	}

	/**
	 * Get empty Mnemonic's instance.
	 *
	 * @return the Mnemonic object
	 */
	public static Mnemonic getInstance() {
		String language = "";

		if (mcTable.containsKey(language))
			return mcTable.get(language);

		Mnemonic m = new Mnemonic(MnemonicCode.INSTANCE);
		mcTable.put(language, m);
		return m;
	}

	/**
	 * Get the Mnemonic's instance with the given language.
	 *
	 * @param language the language string
	 * @return the Mnemonic object
	 * @throws DIDException generate Mnemonic into table failed.
	 */
	public static Mnemonic getInstance(String language) throws DIDException {
		if (language == null || language.isEmpty())
			return getInstance();

		if (mcTable.containsKey(language))
			return mcTable.get(language);

		try {
			InputStream is = MnemonicCode.openDefaultWords(language);
			MnemonicCode mc = new MnemonicCode(is, null);
			Mnemonic m = new Mnemonic(mc);
			mcTable.put(language, m);
			return m;
		} catch (IOException | IllegalArgumentException e) {
			throw new DIDException(e);
		}
	}

	/**
	 * Generate mnemonic.
	 *
	 * @return the mnemonic string
	 * @throws DIDException generate Mnemonic into table failed.
	 */
	public String generate() throws DIDException {
		try {
			byte[] entropy = new byte[TWELVE_WORDS_ENTROPY];
			new SecureRandom().nextBytes(entropy);
			List<String> words = mc.toMnemonic(entropy);

			StringJoiner joiner = new StringJoiner(" ");
	        for (String word: words)
	            joiner.add(word);

	        return joiner.toString();
		} catch (MnemonicException e) {
			throw new DIDException(e);
		}
	}

	/**
	 * Check that mnemonic string is valid or not.
	 *
	 * @param mnemonic the mnemonic string
	 * @return the returned value is true if mnemonic is valid;
	 *         the returned value is false if mnemonic is not valid.
	 */
	public boolean isValid(String mnemonic) {
    	if (mnemonic == null || mnemonic.isEmpty())
    		throw new IllegalArgumentException();

    	mnemonic = Normalizer.normalize(mnemonic, Normalizer.Form.NFD);
		List<String> words = Arrays.asList(mnemonic.split(" "));

    	try {
	    	mc.check(words);
		    return true;
		} catch (MnemonicException e) {
			return false;
		}
	}

	/**
	 * Get seed from mnemonic and password.
	 *
	 * @param mnemonic the mnemonic string
	 * @param passphrase the password combine with mnemonic
	 * @return the original seed
	 */
	public static byte[] toSeed(String mnemonic, String passphrase) {
    	mnemonic = Normalizer.normalize(mnemonic, Normalizer.Form.NFD);
    	passphrase = Normalizer.normalize(passphrase, Normalizer.Form.NFD);

		List<String> words = Arrays.asList(mnemonic.split(" "));

    	return MnemonicCode.toSeed(words, passphrase);
	}
}
