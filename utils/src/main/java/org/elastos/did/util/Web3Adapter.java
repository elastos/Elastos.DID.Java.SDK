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

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.ExecutionException;

import org.elastos.did.DefaultDIDAdapter;
import org.elastos.did.exception.DIDTransactionException;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.WalletUtils;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.BatchRequest;
import org.web3j.protocol.core.BatchResponse;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthEstimateGas;
import org.web3j.protocol.core.methods.response.EthGasPrice;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthGetTransactionReceipt;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.FastRawTransactionManager;
import org.web3j.tx.gas.DefaultGasProvider;

/**
* The sample DID adapter implementation that using the Web3 and an EID wallet.
*/
public class Web3Adapter extends DefaultDIDAdapter {
	private static final int MAX_WAIT_BLOCKS = 10;
	private static final int MAX_BATCH_SIZE = 64;

	private static final BigInteger DEFAULT_GAS_PRICE = new BigInteger("10000000000");
	private static final BigInteger DEFAULT_GAS_LIMIT = new BigInteger("40000000");

	// mainnet or testnet
	//private static String  = "0xF654c3cBBB60D7F4ac7cDA325d51E62f47ACD436";

	private Web3j web3j;
	private File walletFile;
	private String walletAddress;
	private Credentials credential;
	private String contractAddress;
	private long chainId;
	private BigInteger nonce;
	private boolean batchMode;
	private BatchRequest batchRequest;

	public Web3Adapter(Network network, File walletFile) {
		super(network.getRpcEndpint());

		this.contractAddress = network.getContractAddress();
		this.chainId = network.getChainId() == null ? -1 : network.getChainId();
		this.walletFile = walletFile;
		this.batchMode = false;
	}

	private Web3j getWeb3j() {
		if (web3j == null) {
			web3j = Web3j.build(new HttpService(getRpcEndpoint().toString()));
		}

		return web3j;
	}

	@Override
	public URL getRpcEndpoint() {
		return super.getRpcEndpoint();
	}

	// Web3j needs to be shutdown.
	public void shutdown() {
		if (web3j != null)
			web3j.shutdown();
	}

	private Credentials getCredential() throws IOException {
		if (credential == null) {
			try {
				credential = WalletUtils.loadCredentials(CommandContext.getPassword(), walletFile);
			} catch (CipherException e) {
				CommandContext.clearPassword();
				throw new IOException(e);
			}
		}

		return credential;
	}

	private String getWalletAddress() throws IOException {
		if (walletAddress == null)
			walletAddress = Wallets.getWalletAddress(walletFile);

		return walletAddress;
	}

	protected BigInteger getNonce() throws IOException {
		EthGetTransactionCount ethGetTransactionCount = getWeb3j().ethGetTransactionCount(
				getCredential().getAddress(), DefaultBlockParameterName.PENDING).send();

		return ethGetTransactionCount.getTransactionCount();
	}

	public void setBatchMode(boolean batch) {
		this.batchMode  = batch;
		this.batchRequest = batchMode ? getWeb3j().newBatch() : null;
	}

	public void commit() throws DIDTransactionException {
		if (!batchMode)
			return;

		if (batchRequest.getRequests().isEmpty())
			return;

		try {
			@SuppressWarnings("unused")
			BatchResponse response = batchRequest.send();
			// TODO check the response
		} catch (IOException e) {
			throw new DIDTransactionException("Send batch request failed", e);
		}

		this.batchRequest = getWeb3j().newBatch();
	}

	@Override
	public void createIdTransaction(String payload, String memo)
			throws DIDTransactionException {
		@SuppressWarnings("rawtypes")
		Function contract = new Function("publishDidTransaction",
				Arrays.<Type>asList(new Utf8String(payload)),
				Collections.<TypeReference<?>>emptyList());

		String encodedContract = FunctionEncoder.encode(contract);

		try {
			if (nonce == null)
				nonce = getNonce();

			BigInteger gasPrice = null;
			BigInteger gasLimit = null;

			// Get the user-set gas price and limit
			if (System.getenv("DID_GAS_PRICE") != null) {
				try {
					gasPrice = new BigInteger(System.getenv("DID_GAS_PRICE"));
				} catch (NumberFormatException ignore) {
					System.out.println(Colorize.yellow("Invalid DID_GAS_PRICE variable, ingnore!"));
				}
			}

			if (System.getenv("DID_GAS_LIMIT") != null) {
				try {
					gasLimit = new BigInteger(System.getenv("DID_GAS_LIMIT"));
				} catch (NumberFormatException ignore) {
					System.out.println(Colorize.yellow("Invalid DID_GAS_LIMIT variable, ingnore!"));
				}
			}

			// Get the default gas price and estimate the gas limit
			if (gasPrice == null) {
				EthGasPrice ethGasPrice = web3j.ethGasPrice().sendAsync().get();
				if (ethGasPrice.hasError()) {
					System.out.println(Colorize.yellow("Get gas price error: " + ethGasPrice.getError().getMessage() + "\nWill use default."));
					gasPrice = DEFAULT_GAS_PRICE;
				} else {
					gasPrice = ethGasPrice.getGasPrice();
				}
			}

			if (gasLimit == null) {
				Transaction etx = Transaction.createFunctionCallTransaction(getWalletAddress(),
						BigInteger.ONE, gasPrice, DefaultGasProvider.GAS_LIMIT, contractAddress, encodedContract);

				EthEstimateGas ethEstimateGas = web3j.ethEstimateGas(etx).sendAsync().get();
				if (ethEstimateGas.hasError()) {
					System.out.println(Colorize.yellow("Estimate gas limit error: " + ethEstimateGas.getError().getMessage() + "\nWill use default."));
					gasLimit = DEFAULT_GAS_LIMIT;
				} else {
					gasLimit = ethEstimateGas.getAmountUsed();
				}
			}

			// System.out.format("Gas for DID transaction: price %s, limit %s\n", gasPrice.toString(), gasLimit.toString());

			RawTransaction tx = RawTransaction.createTransaction(
					nonce,
					gasPrice,
					gasLimit,
					contractAddress,
					encodedContract);

			FastRawTransactionManager txm = new FastRawTransactionManager(getWeb3j(), getCredential(), chainId);
			String signedTxStr = txm.sign(tx);

			Request<?, EthSendTransaction> request = getWeb3j().ethSendRawTransaction(signedTxStr);

			nonce = nonce.add(BigInteger.ONE);

			if (batchMode) {
				batchRequest.add(request);

				if (batchRequest.getRequests().size() >= MAX_BATCH_SIZE)
					commit();
			} else {
				EthSendTransaction ethSendTx = request.send();

				if (ethSendTx.hasError()) {
					throw new DIDTransactionException("Error send transaction : " +
							ethSendTx.getError().getMessage());
				}

				String txHash = ethSendTx.getTransactionHash();
				// log.info("Create transaction succeed, tx hash: " + txHash);

				int waitBlocks = MAX_WAIT_BLOCKS;
				while (true) {
					EthGetTransactionReceipt receipt = getWeb3j().ethGetTransactionReceipt(txHash).sendAsync().get();
					if (receipt.hasError()) {
						//log.error("Transaction receipt return error: ", receipt.getError().getMessage());
						throw new DIDTransactionException("Error transaction response: " +
								receipt.getError().getMessage());
					}

					if (!receipt.getTransactionReceipt().isPresent()) {
						if (waitBlocks-- == 0) {
							throw new DIDTransactionException("Create transaction timeout.");
						}

						Thread.sleep(5000);
					} else {
						break;
					}
				}
			}
		} catch(ExecutionException | InterruptedException | IOException e) {
			throw new DIDTransactionException("Error create transaction: " + e.getMessage(), e);
		}
	}
}
