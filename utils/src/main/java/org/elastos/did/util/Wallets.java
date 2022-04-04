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
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.concurrent.Callable;

import org.web3j.crypto.Bip32ECKeyPair;
import org.web3j.crypto.Bip44WalletUtils;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.MnemonicUtils;
import org.web3j.crypto.WalletUtils;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetBalance;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Convert;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "wallet", mixinStandardHelpOptions = true, version = Version.VERSION,
description = "Wallet management commands.", subcommands = {
		Wallets.Address.class,
		Wallets.Balance.class,
		Wallets.Transfer.class
})
public class Wallets {
	private static final String WALLET_FILE_NAME = "wallet.json";

	protected static File getWalletFile(String identity) {
		return new File(Identities.getIdentityHome(identity), WALLET_FILE_NAME);
	}

	protected static String create(File walletDir, String mnemonic, String passphrase, String password)
			throws CipherException, IOException {
		if (!walletDir.exists())
			walletDir.mkdirs();

        byte[] seed = MnemonicUtils.generateSeed(mnemonic, passphrase);

        Bip32ECKeyPair masterKeypair = Bip32ECKeyPair.generateKeyPair(seed);
        Bip32ECKeyPair bip44Keypair = Bip44WalletUtils.generateBip44KeyPair(masterKeypair);

        String filename = Bip44WalletUtils.generateWalletFile(password, bip44Keypair, walletDir, false);

		File walletFile = new File(walletDir, WALLET_FILE_NAME);
		if (walletFile.exists()) {
			if (!walletFile.isFile())
				throw new IllegalStateException("Wallet file: " + walletFile.getAbsolutePath() + " exists, but not a regular file");

			File toBeRename =  new File(walletFile.getAbsolutePath());
			File backupFile = new File(walletFile.getAbsolutePath() + "-" + System.currentTimeMillis());
			toBeRename.renameTo(backupFile);
		}

		File tempWalletFile = new File(walletDir, filename);
		tempWalletFile.renameTo(walletFile);

		Credentials account = WalletUtils.loadCredentials(password, walletFile);
		return account.getAddress();
	}

	protected static String getWalletAddress(File walletFile) throws IOException {
		ObjectMapper mapper = new ObjectMapper();
		JsonNode wallet = mapper.readTree(walletFile);
		String address = "0x" + wallet.get("address").asText();

		return address;
	}

	@Command(name = "address", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Show the wallet address.", sortOptions = false)
	public static class Address extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Override
		public Integer call() {
			try {
				File walletFile = getActiveWallet();
				if (!walletFile.exists()) {
					System.out.println(Colorize.yellow("No active wallet."));
					return -1;
				}

				String address = getWalletAddress(walletFile);
				System.out.println("Wallet address: " + Colorize.green(address));
				return 0;
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "balance", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Show the wallet balance.", sortOptions = false)
	public static class Balance extends CommandBase implements Callable<Integer> {
		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Override
		public Integer call() {
			try {
				File walletFile = getActiveWallet();
				if (!walletFile.exists()) {
					System.out.println(Colorize.yellow("No active wallet."));
					return -1;
				}

				String address = getWalletAddress(walletFile);
				Web3j web3j = Web3j.build(new HttpService(getActiveDidAdapter().getRpcEndpoint().toString()));

				EthGetBalance ethGetBalance = web3j.ethGetBalance(address, DefaultBlockParameterName.LATEST).send();
				BigInteger wei = ethGetBalance.getBalance();
				BigDecimal balance = Convert.fromWei(new BigDecimal(wei), Convert.Unit.ETHER);

				System.out.println("Wallet balance: " + Colorize.green(balance.toString()));
				web3j.shutdown();
				return 0;
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

	@Command(name = "transfer", mixinStandardHelpOptions = true, version = Version.VERSION,
			description = "Transfer token to address.", sortOptions = false)
	public static class Transfer extends CommandBase implements Callable<Integer> {

		@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
		private boolean verboseErrors = false;

		@Parameters(paramLabel = "ADDRESS", index = "0", description = "The recipient address.")
		private String address;

		@Parameters(paramLabel = "AMOUNT", index = "1", description = "The amount of ELA to be transfer.")
		private Double amount;

		@Override
		public Integer call() {
			try {
				File walletFile = getActiveWallet();
				if (!walletFile.exists()) {
					System.out.println(Colorize.yellow("No active wallet."));
					return -1;
				}

				Credentials account = WalletUtils.loadCredentials(CommandContext.getPassword(), walletFile);
				Web3j web3j = Web3j.build(new HttpService(getActiveDidAdapter().getRpcEndpoint().toString()));

				TransactionReceipt receipt = org.web3j.tx.Transfer.sendFunds(
						web3j, account, address, BigDecimal.valueOf(amount), Convert.Unit.ETHER).send();

				if (receipt.isStatusOK()) {
					System.out.println("Transfered " + amount + " ELA to " + address + ".");
					web3j.shutdown();
					return 0;
				} else {
					System.out.println(Colorize.red("Transfer failed: " + receipt.getStatus()));
					web3j.shutdown();
					return -1;
				}
			} catch (Exception e) {
				System.err.println(Colorize.red("Error: " + e.getMessage()));
				if (verboseErrors)
					e.printStackTrace(System.err);

				return -1;
			}
		}
	}

}
