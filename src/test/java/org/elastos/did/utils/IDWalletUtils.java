package org.elastos.did.utils;

import java.io.File;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;

import org.elastos.did.utils.IDWalletUtils.CreateWallet;
import org.elastos.did.utils.IDWalletUtils.TransferToken;
import org.elastos.did.utils.IDWalletUtils.WalletBalance;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetBalance;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.Transfer;
import org.web3j.utils.Convert;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "org.elastos.did.util.WalletUtils", description = "Elastos DID wallet utils.",
subcommands = {
	CreateWallet.class,
	WalletBalance.class,
	TransferToken.class
})
public class IDWalletUtils {
	/*
	private static String superWallet = "$HOME/Projects/Elastos/DID/wallet.prvnet";
	private static String superWalletPassword = "123";
	*/

	@Command(name = "create", mixinStandardHelpOptions = true, version = "walletutil 1.0",
			description = "Create new ID side chain wallet.")
	public static class CreateWallet implements Callable<Integer> {
		@Option(names = {"-p", "--passwd"}, required = true, arity = "0..1", interactive = true, description = "Wallet password")
		private String password;

		@Option(names = {"-o", "--out"}, description = "Output directory, default is current directory")
		private String outputDir = null;

		@Override
		public Integer call() throws Exception {
			try {
				if (outputDir == null)
					outputDir = new File("").getAbsolutePath();

				File outputPath = new File(outputDir);

				String filename = WalletUtils.generateNewWalletFile(password, outputPath);
				File walletFile = new File(outputPath, filename);
				Credentials account = WalletUtils.loadCredentials(password, walletFile);
				String address = account.getAddress();

				File finalWalletFile = new File(outputPath, address + ".json");
				walletFile.renameTo(finalWalletFile);
				System.out.println("New wallet created: " + finalWalletFile.toString());
				System.out.println("Account: " + account.getAddress());
				return 0;
			} catch (Exception e) {
				e.printStackTrace(System.err);
				return -1;
			}
		}
	}

	@Command(name = "balance", mixinStandardHelpOptions = true, version = "walletutil 1.0",
			description = "Get address balance.")
	public static class WalletBalance implements Callable<Integer> {
		@Option(names = {"-a", "--address"}, required = true, description = "Account address")
		private String address;

		@Option(names = {"-e", "--endpoint"}, required = true, description = "ID Chain RPC endpoint")
		private String endpoint;

		@Override
		public Integer call() throws Exception {
			try {
				Web3j web3j = Web3j.build(new HttpService(endpoint));
				EthGetBalance ethGetBalance = web3j.ethGetBalance(address,
						 DefaultBlockParameterName.LATEST).sendAsync().get();
				BigInteger wei = ethGetBalance.getBalance();
				BigDecimal balance = Convert.fromWei(new BigDecimal(wei), Convert.Unit.ETHER);

				System.out.format("Wallet address: %s, balance: %s\n", address, balance.toString());
				return 0;
			} catch (InterruptedException | ExecutionException e) {
				e.printStackTrace(System.err);
				return -1;
			}
		}
	}

	@Command(name = "transfer", mixinStandardHelpOptions = true, version = "walletutil 1.0",
			description = "Transfer tokens to address.")
	public static class TransferToken implements Callable<Integer> {
		@Option(names = {"-w", "--wallet"}, required = true, description = "From wallet")
		private String wallet;

		@Option(names = {"-p", "--passwd"}, required = true, arity = "0..1", interactive = true, description = "Wallet password")
		private String password;

		@Option(names = {"-t", "--to"}, required = true, description = "Transfer to address")
		private String address;

		@Option(names = {"-m", "--amount"}, required = true, description = "Transfer amount")
		private double amount;

		@Option(names = {"-e", "--endpoint"}, required = true, description = "ID Chain RPC endpoint")
		private String endpoint;

		@Override
		public Integer call() throws Exception {
			try {
				Web3j web3j = Web3j.build(new HttpService(endpoint));

				// from wallet balance
				Credentials from = WalletUtils.loadCredentials(password, wallet);
				EthGetBalance ethGetBalance = web3j.ethGetBalance(from.getAddress(),
						 DefaultBlockParameterName.LATEST).sendAsync().get();
				BigInteger wei = ethGetBalance.getBalance();
				BigDecimal balance = Convert.fromWei(new BigDecimal(wei), Convert.Unit.ETHER);
				System.out.format("Wallet address: %s, balance: %s\n", from.getAddress(), balance.toString());

				// transfer
				TransactionReceipt transactionReceipt = Transfer.sendFunds(web3j,
						from, address,
						BigDecimal.valueOf(amount), Convert.Unit.ETHER).sendAsync().get();

				BigInteger txBlock = transactionReceipt.getBlockNumber();

				while (true) {
					Thread.sleep(5000);
					BigInteger lastBlock = web3j.ethBlockNumber().sendAsync().get().getBlockNumber();
					int confirms = lastBlock.subtract(txBlock).intValue();
					System.out.println("Confirmations: " + confirms);
					if (confirms >= 2)
						break;
				}

				// Target balance
				ethGetBalance = web3j.ethGetBalance(address,
						 DefaultBlockParameterName.LATEST).sendAsync().get();
				wei = ethGetBalance.getBalance();
				balance = Convert.fromWei(new BigDecimal(wei), Convert.Unit.ETHER);
				System.out.format("Wallet address: %s, balance: %s\n", address, balance.toString());
				return 0;
			} catch (Exception e) {
				e.printStackTrace(System.err);
				return -1;
			}
		}
	}

	public static void main(String[] args) {
		int exitCode = new CommandLine(new IDWalletUtils()).execute(args);
		System.exit(exitCode);
	}
}
