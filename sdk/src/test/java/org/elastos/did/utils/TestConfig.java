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

package org.elastos.did.utils;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;

public final class TestConfig {
	public static String rpcEndpoint;
	public static String contractAddress;

	public static boolean idChainTest;

	public static String walletPath;
	public static String walletPassword;

	public static String passphrase;
	public static String storePass;

	public static String tempDir;
	public static String storeRoot;

	public static Level level;

	static {
		InputStream input = TestConfig.class
				.getClassLoader().getResourceAsStream("test.conf");

		Properties config = new Properties();
		try {
			config.load(input);
		} catch (IOException e) {
			e.printStackTrace();
		}

		String sysTemp = System.getProperty("java.io.tmpdir");

		rpcEndpoint = config.getProperty("idchain.rpcEndpoint");
		contractAddress = config.getProperty("idchain.contractAddress");

		idChainTest = Boolean.valueOf(config.getProperty("idchain.test"));

		walletPath = config.getProperty("wallet.path");
		walletPassword = config.getProperty("wallet.password");

		passphrase = config.getProperty("mnemnoic.passphrase");
		storePass = config.getProperty("store.pass");

		tempDir = config.getProperty("temp.dir", sysTemp);
		storeRoot = config.getProperty("store.root", tempDir + "/DIDStore");

		level = Level.valueOf(config.getProperty("log.level", "info").toUpperCase());

		// We use logback as the logging backend
	    Logger root = (Logger)LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
	    root.setLevel(level);
	}
}
