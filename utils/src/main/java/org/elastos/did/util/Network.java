/*
 * Copyright (c) 2022 Elastos Foundation
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

package org.elastos.did.util;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

public class Network {
	public static final Network MAINNET = new Network("mainnet", "mainnet",
			"0x46E5936a9bAA167b3368F4197eDce746A66f7a7a", null);
	public static final Network TESTNET = new Network("testnet", "testnet",
			"0xF654c3cBBB60D7F4ac7cDA325d51E62f47ACD436", null);

	@JsonIgnore
	private String name;

	@JsonProperty
	private String rpcEndpoint;
	@JsonProperty
	private String contractAddress;
	@JsonProperty
	@JsonInclude(Include.NON_EMPTY)
	private Long chainId;

	@JsonCreator
	protected Network(@JsonProperty(value = "rpcEndpoint") String rpcEndpoint,
			@JsonProperty(value = "contractAddress") String contractAddress,
			@JsonProperty(value = "chainId") Long chainId) {
		this(null, rpcEndpoint, contractAddress, chainId);
	}

	Network(String name, String rpcEndpoint, String contractAddress, Long chainId) {
		this.name = name;
		this.rpcEndpoint = rpcEndpoint;
		this.contractAddress = contractAddress;
		this.chainId = chainId;
	}

	public String getName() {
		return name;
	}

	void setName(String name) {
		this.name = name;
	}

	public String getRpcEndpint() {
		return rpcEndpoint;
	}

	public String getContractAddress() {
		return contractAddress;
	}

	public Long getChainId() {
		return chainId;
	}

	@Override
	public String toString() {
		if (name.equals(MAINNET.name))
			return MAINNET.name;
		else if (name.equals(TESTNET.name))
			return TESTNET.name;
		else
			return name + " - " + rpcEndpoint;
	}
}
