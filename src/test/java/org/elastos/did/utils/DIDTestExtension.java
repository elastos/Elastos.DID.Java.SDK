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

import static org.junit.jupiter.api.extension.ExtensionContext.Namespace.GLOBAL;

import org.elastos.did.backend.SPVAdapter;
import org.elastos.did.backend.SimulatedIDChain;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Store.CloseableResource;

public class DIDTestExtension implements BeforeAllCallback, CloseableResource {
	private static SPVAdapter adapter;
	private static SimulatedIDChain simChain;

	private void setup() throws Exception {
		if (TestConfig.network.equalsIgnoreCase("mainnet") ||
				TestConfig.network.equalsIgnoreCase("testnet")) {
			adapter = new SPVAdapter(TestConfig.network,
				TestConfig.walletDir, TestConfig.walletId,
				new SPVAdapter.PasswordCallback() {
					@Override
					public String getPassword(String walletDir, String walletId) {
						return TestConfig.walletPassword;
					}
				});
		}

		simChain = new SimulatedIDChain();
		simChain.start();
	}

	@Override
	public void close() throws Throwable {
		if (simChain != null)
			simChain.stop();

		if (adapter != null)
			adapter.destroy();
	}

	@Override
	public void beforeAll(ExtensionContext context) throws Exception {
	    String key = this.getClass().getName();
	    Object value = context.getRoot().getStore(GLOBAL).get(key);
	    if (value == null) {
	    	// First test container invocation.
	    	setup();
	    	context.getRoot().getStore(GLOBAL).put(key, this);
	    }
	}

	public static SimulatedIDChain getSimChain() {
		return simChain;
	}

	public static SPVAdapter getSpvAdapter() {
		return adapter;
	}
}
