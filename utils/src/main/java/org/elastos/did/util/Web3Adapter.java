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

package org.elastos.did.util;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
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
import org.web3j.protocol.core.methods.response.EthGetBalance;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthGetTransactionReceipt;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.FastRawTransactionManager;
import org.web3j.utils.Convert;

/**
* The sample DID adapter implementation that using the Web3 and an EID wallet.
*/
public class Web3Adapter extends DefaultDIDAdapter {
	private static final int MAX_WAIT_BLOCKS = 10;
	private static final int MAX_BATCH_SIZE = 64;

	// mainnet or testnet
	// private static String contractAddress = "0xF654c3cBBB60D7F4ac7cDA325d51E62f47ACD436";

	// Privatenet
	private static long CHAIN_ID = 23;
	private static String contractAddress = "0xdDCF19F9A52BC3c58F89C43BfB3614293F977ccA";

	private Web3j web3j;
	private Credentials account;
	private String network;
	private String walletFile;
	private String walletPassword;
	private BigInteger nonce;
	private boolean batchMode;
	private BatchRequest batchRequest;

	public Web3Adapter(String network, String walletFile, String walletPassword) {
		super(network);

		this.network = network;
		this.walletFile = walletFile;
		this.walletPassword = walletPassword;
		this.batchMode = false;

		initWeb3j();
	}

	private void printWalletInfo() {
		BigDecimal balance = BigDecimal.ZERO;
		try {
			EthGetBalance ethGetBalance = web3j.ethGetBalance(account.getAddress(),
					 DefaultBlockParameterName.LATEST).send();
			BigInteger wei = ethGetBalance.getBalance();
			balance = Convert.fromWei(new BigDecimal(wei), Convert.Unit.ETHER);
		} catch (IOException e) {
			e.printStackTrace();
		}

		System.out.println("================================================");
		System.out.println("Network: " + network);
		System.out.format("Wallet address: %s\n", account.getAddress());
		System.out.format("Account nonce: %s\n", nonce.toString());
		System.out.format("Wallet balance: %s\n", balance.toString());
		System.out.println("================================================");
	}

	private void initWeb3j() {
		web3j = Web3j.build(new HttpService(getRpcEndpoint().toString()));
		try {
			account = WalletUtils.loadCredentials(walletPassword, walletFile);
			nonce = getNonce();
			printWalletInfo();
		} catch (IOException | CipherException e) {
			throw new RuntimeException("Can not load wallet: " + e.getMessage(), e);
		}
	}

	// Web3j needs to be shutdown.
	public void shutdown() {
		printWalletInfo();
		web3j.shutdown();
	}

    protected BigInteger getNonce() throws IOException {
        EthGetTransactionCount ethGetTransactionCount =
                web3j.ethGetTransactionCount(
                                account.getAddress(), DefaultBlockParameterName.PENDING)
                        .send();

        return ethGetTransactionCount.getTransactionCount();
    }

	public void setBatchMode(boolean batch) {
		this.batchMode  = batch;
		this.batchRequest = web3j.newBatch();
	}

	public void commit() throws DIDTransactionException {
		if (!batchMode)
			return;

		try {
			BatchResponse response = batchRequest.send();
			// TODO check the response
		} catch (IOException e) {
			throw new DIDTransactionException("Send batch request failed", e);
		}

		this.batchRequest = web3j.newBatch();
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
			//BigInteger gasPrice = web3j.ethGasPrice().sendAsync().get().getGasPrice();
			BigInteger gasPrice = new BigInteger("10000000000");
			BigInteger gasLimit = new BigInteger("40000000");

			// log.info("Creating transaction via {}", getRpcEndpoint());
			RawTransaction tx = RawTransaction.createTransaction(
					nonce,
					gasPrice,
					gasLimit,
					contractAddress,
					encodedContract);

			/*
			byte[] signedTx = TransactionEncoder.signMessage(tx, account);
			String signedTxStr = Numeric.toHexString(signedTx);
			*/

			FastRawTransactionManager txm = new FastRawTransactionManager(web3j, account, CHAIN_ID);
			String signedTxStr = txm.sign(tx);

			/*
			byte[] signedTx = TransactionEncoder.signMessage(tx, account);
			String signedTxStr = Numeric.toHexString(signedTx);
			*/

			Request<?, EthSendTransaction> request = web3j.ethSendRawTransaction(signedTxStr);

			/*
			Transaction tx = Transaction.createFunctionCallTransaction(
					account.getAddress(),
					nonce,
					gasPrice,
					gasLimit,
					contractAddress,
					encodedContract);

			Request<?, EthSendTransaction> request =
					web3j.ethSendTransaction(tx);
			*/

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
					EthGetTransactionReceipt receipt = web3j.ethGetTransactionReceipt(txHash).sendAsync().get();
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
