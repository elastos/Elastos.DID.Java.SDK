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

import static com.google.common.base.Preconditions.checkArgument;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.StringJoiner;

import org.bitcoinj.crypto.MnemonicCode;
import org.elastos.did.exception.MnemonicException;

/**
 * Mnemonic object compliant with
 * <a href="https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki">the BIP 39
 * specification</a>. Support all languages that listed in bip-0039.
 *
 * <p>
 * Mnemonic object can generate a random mnemonic words list, or convert the
 * works list to seed that use to generate the root extended private key.
 * </p>
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
	 * Create a Mnemonic object with default language.
	 *
	 * @return the Mnemonic object
	 * @throws MnemonicException if an error occurred when create the Mnemonic object
	 */
	public static Mnemonic getInstance() throws MnemonicException {
		return getInstance(null);
	}

	/**
	 * Create a Mnemonic object with specified language.
	 *
	 * @param language the language string
	 * @return the Mnemonic object
	 * @throws MnemonicException if an error occurred when create the Mnemonic object
	 */
	public static synchronized Mnemonic getInstance(String language)
			throws MnemonicException {
		if (language == null)
			language = ENGLISH;

		if (mcTable.containsKey(language))
			return mcTable.get(language);

		try {
			MnemonicCode mc =  MnemonicCode.INSTANCE;
			if (!language.isEmpty()) {
				InputStream is = MnemonicCode.openDefaultWords(language);
				mc = new MnemonicCode(is, null);
			}

			Mnemonic m = new Mnemonic(mc);
			mcTable.put(language, m);
			return m;
		} catch (IOException | IllegalArgumentException e) {
			throw new MnemonicException(e);
		}
	}

	/**
	 * Generate a mnemonic from entropy.
	 *
	 * @param entropy the entropy data to generate mnemonic
	 *
	 * @return the mnemonic string
	 * @throws MnemonicException if an error occurred when generating the words list
	 */
	public String generate(byte[] entropy) throws MnemonicException {
		try {
			List<String> words = mc.toMnemonic(entropy);

			StringJoiner joiner = new StringJoiner(" ");
			for (String word: words)
				joiner.add(word);

			return joiner.toString();
		} catch (org.bitcoinj.crypto.MnemonicException e) {
			throw new MnemonicException(e);
		}
	}

	/**
	 * Generate a random mnemonic.
	 *
	 * @return the mnemonic string
	 * @throws MnemonicException if an error occurred when generating the words list
	 */
	public String generate() throws MnemonicException {
		byte[] entropy = new byte[TWELVE_WORDS_ENTROPY];
		new SecureRandom().nextBytes(entropy);
		return generate(entropy);
	}

	/**
	 * Check the mnemonic string is valid or not.
	 *
	 * @param mnemonic the mnemonic string
	 * @return true if valid, otherwise false
	 */
	public boolean isValid(String mnemonic) {
		checkArgument(mnemonic != null && !mnemonic.isEmpty(), "Invalid menmonic");

		mnemonic = Normalizer.normalize(mnemonic, Normalizer.Form.NFD);
		List<String> words = Arrays.asList(mnemonic.split(" "));

		try {
			mc.check(words);
			return true;
		} catch (org.bitcoinj.crypto.MnemonicException e) {
			return false;
		}
	}


	/**
	 * Get the language name from a mnemonic string.
	 *
	 * @param mnemonic a mnemonic string.
	 * @return a language name
	 * @throws MnemonicException if an error occurred
	 */
	public static String getLanguage(String mnemonic) throws MnemonicException {
		checkArgument(mnemonic != null && !mnemonic.isEmpty(), "Invalid menmonic");

		mnemonic = Normalizer.normalize(mnemonic, Normalizer.Form.NFD);
		List<String> words = Arrays.asList(mnemonic.split(" "));

		String[] langs = { ENGLISH, SPANISH, FRENCH, CZECH, ITALIAN,
				CHINESE_SIMPLIFIED, CHINESE_TRADITIONAL, JAPANESE, KOREAN };

		for (String lang : langs) {
			Mnemonic m = getInstance(lang);
			try {
				m.mc.check(words);
				return lang;
			} catch (org.bitcoinj.crypto.MnemonicException e) {
				continue;
			}
		}

		return null;
	}

	/**
	 * Check a mnemonic string is valid or not.
	 *
	 * @param mnemonic a mnemonic string
	 * @return true if valid, otherwise false
	 * @throws MnemonicException if an error occurred
	 */
	public static boolean checkIsValid(String mnemonic) throws MnemonicException {
		checkArgument(mnemonic != null && !mnemonic.isEmpty(), "Invalid menmonic");

		String lang = getLanguage(mnemonic);
		return lang != null;
	}

	/**
	 * Convert the mnemonic and an optional passphrase to seed.
	 *
	 * @param mnemonic a mnemonic string
	 * @param passphrase a passphrase, could be null or empty
	 * @return a seed that use to generate the root extended private key
	 */
	public static byte[] toSeed(String mnemonic, String passphrase) {
		checkArgument(mnemonic != null && !mnemonic.isEmpty(), "Invalid menmonic");

		if (passphrase == null)
			passphrase = "";

		mnemonic = Normalizer.normalize(mnemonic, Normalizer.Form.NFD);
		passphrase = Normalizer.normalize(passphrase, Normalizer.Form.NFD);

		List<String> words = Arrays.asList(mnemonic.split(" "));

		return MnemonicCode.toSeed(words, passphrase);
	}
}
