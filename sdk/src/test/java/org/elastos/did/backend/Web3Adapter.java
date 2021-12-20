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

package org.elastos.did.backend;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.ExecutionException;

import org.elastos.did.DefaultDIDAdapter;
import org.elastos.did.exception.DIDTransactionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetBalance;
import org.web3j.protocol.core.methods.response.EthGetTransactionReceipt;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.EthTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.RawTransactionManager;
import org.web3j.tx.TransactionManager;
import org.web3j.utils.Convert;

public class Web3Adapter extends DefaultDIDAdapter {
	private static final int MAX_WAIT_BLOCKS = 5;
	private static final BigInteger WAIT_FOR_CONFIRMS = BigInteger.valueOf(3);

	private static final Logger log = LoggerFactory.getLogger(Web3Adapter.class);

	private String contractAddress;

	private String rpcEndpoint;
	private Web3j web3j;
	private Credentials account;
	private String lastTxHash;

	public Web3Adapter(String rpcEndpoint, String contractAddress,
			String walletFile, String walletPassword) {
		super(rpcEndpoint);
		initWeb3j(rpcEndpoint, walletFile, walletPassword);
		this.contractAddress = contractAddress;
	}

	private void initWeb3j(String rpcEndpoint, String walletFile, String walletPassword) {
		this.rpcEndpoint = rpcEndpoint;
		web3j = Web3j.build(new HttpService(rpcEndpoint));
		try {
			account = WalletUtils.loadCredentials(walletPassword, walletFile);
			BigDecimal balance = BigDecimal.ZERO;
			try {
				EthGetBalance ethGetBalance = web3j.ethGetBalance(account.getAddress(),
						 DefaultBlockParameterName.LATEST).sendAsync().get();
				BigInteger wei = ethGetBalance.getBalance();
				balance = Convert.fromWei(new BigDecimal(wei), Convert.Unit.ETHER);
			} catch (InterruptedException | ExecutionException e) {
				log.info("Get wallet balance error", e);
			}

			System.out.println("================================================");
			System.out.format("Wallet address: %s\n", account.getAddress());
			System.out.format("Wallet balance: %s\n", balance.toString());
			System.out.println("================================================");
		} catch (IOException | CipherException e) {
			throw new RuntimeException("Can not load wallet: " + e.getMessage(), e);
		}
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
			// BigInteger gasPrice = web3j.ethGasPrice().sendAsync().get().getGasPrice();
			BigInteger gasPrice = new BigInteger("10000000000");
			BigInteger gasLimit = new BigInteger("40000000");

			log.info("Creating transaction via {}", rpcEndpoint);
			TransactionManager txManager = new RawTransactionManager(web3j, account);

			EthSendTransaction ethSendTx = txManager.sendTransaction(
					gasPrice,
					gasLimit,
				    contractAddress,
				    encodedContract,
				    BigInteger.ZERO);

			if (ethSendTx.hasError()) {
				log.error("Create transaction failed: " + ethSendTx.getError().getMessage());
				throw new DIDTransactionException("Error send transaction: " +
						ethSendTx.getError().getMessage());
			}

			String txHash = ethSendTx.getTransactionHash();
			log.info("Create transaction succeed, tx hash: " + txHash);

			int waitBlocks = MAX_WAIT_BLOCKS;
			while (true) {
				EthGetTransactionReceipt receipt = web3j.ethGetTransactionReceipt(txHash).sendAsync().get();
				if (receipt.hasError()) {
					log.error("Transaction receipt return error: ", receipt.getError().getMessage());
					throw new DIDTransactionException("Error transaction response: " +
							receipt.getError().getMessage());
				}

				if (!receipt.getTransactionReceipt().isPresent()) {
					if (waitBlocks-- == 0) {
						log.error("Get transaction receipt timeout.");
						throw new DIDTransactionException("Create transaction timeout.");
					}

					log.info("Retry to get transaction receipt...");
					Thread.sleep(5000);
				} else {
					log.info("Transaction block number: {}", receipt.getResult().getBlockNumberRaw());
					break;
				}
			}

			lastTxHash = txHash;
		} catch(ExecutionException | InterruptedException | IOException e) {
			throw new DIDTransactionException("Error create transaction: " + e.getMessage(), e);
		}
	}

	public boolean isAvailable() {
		if (lastTxHash == null)
			return true;

		try {
			EthTransaction tx = web3j.ethGetTransactionByHash(lastTxHash).sendAsync().get();
			if (!tx.getTransaction().isPresent())
				return true;

			BigInteger lastBlock = web3j.ethBlockNumber().sendAsync().get().getBlockNumber();
			BigInteger txBlock = tx.getResult().getBlockNumber();
			BigInteger confirms = lastBlock.subtract(txBlock);
			return confirms.compareTo(WAIT_FOR_CONFIRMS) >= 0;
		} catch (InterruptedException | ExecutionException e) {
			throw new RuntimeException("Error get confirmations: " + e.getMessage(), e);
		}
	}

	public void shutdown() {
		web3j.shutdown();
	}
}
