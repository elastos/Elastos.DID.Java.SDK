package org.elastos.did.util;

import java.io.File;
import java.util.concurrent.Callable;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "createwallet", mixinStandardHelpOptions = true, version = "createwallet 2.0",
		description = "Create an Ethereum compatible UTC wallet for the EID side chain.")
public class CreateWallet extends CommandBase implements Callable<Integer> {
	@Option(names = {"-w", "--wallet"}, description = "Wallet file name, default: ~/.elastos/did/wallet/eid-wallet.json")
	private String walletFileName = null;

	@Option(names = {"-p", "--password"}, required = true, description = "Password for the DID store")
	private String password = null;

	@Option(names = {"-e", "--verbose-errors"}, description = "Verbose error output, default false.")
	private boolean verboseErrors = false;

	@Override
	public Integer call() throws Exception {
		try {
			File walletFile = null;

			if (walletFileName == null)
				walletFile = getUserFile(".elastos/did/wallet/eid-wallet.json");
			else
				walletFile = new File(walletFileName);

			if (walletFile.exists()) {
				if (!walletFile.isFile()) {
					System.out.println(Colorize.red("Wallet file: " + walletFileName + " exists, but not a regular file"));
					return -1;
				} else {
					File toBeRename =  new File(walletFile.getAbsolutePath());
					File backupFile = new File(walletFile.getAbsolutePath() + "-" + System.currentTimeMillis());
					toBeRename.renameTo(backupFile);
				}
			}

			File walletDir = walletFile.getParentFile();
			if (!walletDir.exists())
				walletDir.mkdirs();

			String filename = WalletUtils.generateNewWalletFile(password, walletDir);
			File tempWalletFile = new File(walletDir, filename);
			tempWalletFile.renameTo(walletFile);

			Credentials account = WalletUtils.loadCredentials(password, walletFile);
			String address = account.getAddress();
			System.out.println(Colorize.green("New wallet created: " + walletFile.toString()));
			System.out.println(Colorize.green("Account: " + address));
			return 0;
		} catch (Exception e) {
			if (verboseErrors)
				e.printStackTrace(System.err);
			else
				System.err.println("Error: " + e.getMessage());

			return -1;
		}
	}
}
