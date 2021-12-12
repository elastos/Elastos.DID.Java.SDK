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

package org.elastos.did.samples;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.Properties;
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
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.RawTransactionManager;
import org.web3j.tx.TransactionManager;
import org.web3j.utils.Convert;

import ch.qos.logback.classic.Level;

/**
 * The sample DID adapter implementation that using the Web3 and an EID wallet.
 */
public class Web3Adapter extends DefaultDIDAdapter {
	private static final int MAX_WAIT_BLOCKS = 5;

	private static final Logger log = LoggerFactory.getLogger(Web3Adapter.class);
	private static Properties config;

	private String contractAddress;

	private Web3j web3j;
	private Credentials account;

	static {
		InputStream input = Web3Adapter.class
				.getClassLoader().getResourceAsStream("samples.conf");

		config = new Properties();
		try {
			config.load(input);
		} catch (IOException e) {
			e.printStackTrace();
		}

		Level level = Level.valueOf(config.getProperty("log.level", "info").toUpperCase());

		// We use logback as the logging backend
		ch.qos.logback.classic.Logger root = (ch.qos.logback.classic.Logger)LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
	    root.setLevel(level);
	}

	public Web3Adapter() {
		super(config.getProperty("idchain.network"));
		initWeb3j();
		this.contractAddress = config.getProperty("idchain.contractAddress");
	}

	private void initWeb3j() {
		String walletFile = config.getProperty("wallet.path");
		String walletPassword = config.getProperty("wallet.password");

		web3j = Web3j.build(new HttpService(getRpcEndpoint().toString()));
		try {
			account = WalletUtils.loadCredentials(walletPassword, walletFile);
			BigDecimal balance = BigDecimal.ZERO;
			try {
				EthGetBalance ethGetBalance = web3j.ethGetBalance(account.getAddress(),
						 DefaultBlockParameterName.LATEST).sendAsync().get();
				BigInteger wei = ethGetBalance.getBalance();
				balance = Convert.fromWei(new BigDecimal(wei), Convert.Unit.ETHER);
			} catch (InterruptedException | ExecutionException e) {
				e.printStackTrace();
			}

			System.out.println("================================================");
			System.out.println("Network: " + config.getProperty("idchain.network"));
			System.out.format("Wallet address: %s\n", account.getAddress());
			System.out.format("Wallet balance: %s\n", balance.toString());
			System.out.println("================================================");
		} catch (IOException | CipherException e) {
			throw new RuntimeException("Can not load wallet: " + e.getMessage(), e);
		}
	}

	// Web3j needs to be shutdown.
	public void shutdown() {
		web3j.shutdown();
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
			BigInteger gasPrice = new BigInteger("1000000000000");
			BigInteger gasLimit = new BigInteger("3000000");

			log.info("Creating transaction via {}", getRpcEndpoint());
			TransactionManager txManager = new RawTransactionManager(web3j, account);
			EthSendTransaction ethSendTx = txManager.sendTransaction(
					gasPrice,
					gasLimit,
				    contractAddress,
				    encodedContract,
				    BigInteger.ZERO);

			if (ethSendTx.hasError()) {
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
						throw new DIDTransactionException("Create transaction timeout.");
					}

					Thread.sleep(5000);
				} else {
					break;
				}
			}
		} catch(ExecutionException | InterruptedException | IOException e) {
			throw new DIDTransactionException("Error create transaction: " + e.getMessage(), e);
		}
	}
}
