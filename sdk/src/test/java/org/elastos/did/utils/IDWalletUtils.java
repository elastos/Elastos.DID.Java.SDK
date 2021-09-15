package org.elastos.did.utils;

import java.io.File;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetBalance;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.Transfer;
import org.web3j.utils.Convert;

public class IDWalletUtils {
	/*
	private static String superWallet = "$HOME/Projects/Elastos/DID/wallet.prvnet";
	private static String superWalletPassword = "123";
	*/

	public final static String[] CMD_HELPS = {
		"create <password> <output-dir>",
		"balance <address> <rpc-endpoint>",
		"transfer <wallet> <password> <to-address> <amount> <rpc-endpoint>"
	};

	private static int create(String[] args) {
		if (args.length != 2) {
			System.out.println(CMD_HELPS[0]);
			return -1;
		}

		String password = args[0];
		String outputDir = args[1];

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

	private static int balance(String[] args) {
		if (args.length != 2) {
			System.out.println(CMD_HELPS[1]);
			return -1;
		}

		String address = args[0];
		String endpoint = args[1];

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

	private static int transfer(String[] args) {
		if (args.length != 5) {
			System.out.println(CMD_HELPS[2]);
			return -1;
		}

		String wallet = args[0];
		String password = args[1];
		String address = args[2];
		double amount = Double.valueOf(args[3]);
		String endpoint = args[4];

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


	private static int help() {
		System.out.println("Available commands:");
		for (String help : CMD_HELPS)
			System.out.println("  " + help);

		return -1;
	}

	public static void main(String[] args) {
		int exitCode = -1;

		if (args.length < 1) {
			System.out.println("Missing command.");
			System.exit(help());
		}

		String[] subCmdArgs = Arrays.copyOfRange(args, 1, args.length);

		switch (args[0]) {
		case "create":
			exitCode = create(subCmdArgs);
			break;

		case "balance":
			exitCode = balance(subCmdArgs);
			break;

		case "transfer":
			exitCode = transfer(subCmdArgs);
			break;

		default:
			System.out.println("Unknown command: " + args[0]);
			exitCode = help();
		}

		System.exit(exitCode);
	}
}
