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

import org.elastos.did.DIDAdapter;
import org.elastos.did.DIDBackend;
import org.elastos.did.backend.SimulatedIDChain;
import org.elastos.did.backend.Web3Adapter;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Store.CloseableResource;

public class DIDTestExtension implements BeforeAllCallback, CloseableResource {
	private static DIDAdapter adapter;
	private static SimulatedIDChain simChain;

	private void setup(String name) throws Exception {
		// Force load TestConfig first!!!
		String rpcEndpoint = TestConfig.rpcEndpoint;

		if (name.equals("IDChainOperationsTest")) {
			// When run the IDChainOperationsTest only
			adapter = new Web3Adapter(rpcEndpoint, TestConfig.contractAddress,
					TestConfig.walletPath, TestConfig.walletPassword);
		}

		if (adapter == null) {
			simChain = new SimulatedIDChain();
			simChain.start();
			adapter = simChain.getAdapter();
		}

		DIDBackend.initialize(adapter);
	}

	@Override
	public void close() throws Throwable {
		if (simChain != null)
			simChain.stop();

		simChain = null;
		adapter = null;
	}

	@Override
	public void beforeAll(ExtensionContext context) throws Exception {
		String key = this.getClass().getName();
	    Object value = context.getRoot().getStore(GLOBAL).get(key);
	    if (value == null) {
	    	// First test container invocation.
	    	setup(context.getDisplayName());
	    	context.getRoot().getStore(GLOBAL).put(key, this);
	    }
	}

	public static void resetData() {
		if (simChain != null)
			simChain.reset();
	}

	public static DIDAdapter getAdapter() {
		return adapter;
	}
}
