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

import org.elastos.did.DIDAdapter;
import org.elastos.did.DIDBackend;
import org.elastos.did.Features;
import org.elastos.did.backend.SimulatedIDChain;
import org.elastos.did.backend.SimulatedIDChainAdapter;
import org.elastos.did.backend.Web3Adapter;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Store.CloseableResource;

public class DIDTestExtension implements BeforeAllCallback, CloseableResource {
	private static Web3Adapter web3Adapter;
	private static SimulatedIDChain simChain;

	private static DIDAdapter adapter;

	private static synchronized DIDAdapter getSimChainAdapter() throws IOException {
		if (simChain == null) {
			simChain = new SimulatedIDChain();
			simChain.start();
		}

		return simChain.getAdapter();
	}

	private static synchronized DIDAdapter getWeb3Adapter() {
		String rpcEndpoint = TestConfig.rpcEndpoint;

		if (web3Adapter == null) {
			web3Adapter = new Web3Adapter(rpcEndpoint, TestConfig.contractAddress,
					TestConfig.walletPath, TestConfig.walletPassword);
		}

		return web3Adapter;
	}

	private static synchronized void shutdownAdapter() {
		if (simChain != null) {
			simChain.stop();
			simChain = null;
		}

		if (web3Adapter != null) {
			web3Adapter.shutdown();
			web3Adapter = null;
		}
	}

	@Override
	public void beforeAll(ExtensionContext context) throws Exception {
		if (TestConfig.idChainTest && context.getDisplayName().startsWith("IDChain")) {
			if (context.getUniqueId().indexOf("WithContext") > 0)
				Features.enableJsonLdContext(true);
			else
				Features.enableJsonLdContext(false);

			adapter = getWeb3Adapter();
		} else {
			if (context.getUniqueId().indexOf("WithContext") > 0)
				Features.enableJsonLdContext(true);
			else
				Features.enableJsonLdContext(false);

			adapter = getSimChainAdapter();
		}

		System.out.format(">>>>>>>> Running %s[Chain: %s, JSON-LD: %s]\n", context.getDisplayName(),
				adapter instanceof Web3Adapter ? "EID" : "Simulated", Features.isEnabledJsonLdContext());

		String key = "did-test-ext";
		if (context.getRoot().getStore(ExtensionContext.Namespace.GLOBAL).get(key) == null)
			context.getRoot().getStore(ExtensionContext.Namespace.GLOBAL).put(key, this);

		DIDBackend.initialize(adapter);
	}

	@Override
	public void close() throws Exception {
		resetData();
		shutdownAdapter();
	}

	public static void resetData() {
		if (adapter instanceof SimulatedIDChainAdapter) {
			try {
				((SimulatedIDChainAdapter)adapter).reset();
			} catch (IOException e) {
				throw new IllegalStateException("Can not reset the simulated ID chain.");
			}
		}
	}

	public static DIDAdapter getAdapter() {
		return adapter;
	}
}
