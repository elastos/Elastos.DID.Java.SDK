package org.elastos.did.utils;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import org.elastos.did.DIDBackend;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDStore;
import org.elastos.did.DefaultDIDAdapter;
import org.elastos.did.Mnemonic;
import org.elastos.did.RootIdentity;
import org.elastos.did.exception.DIDTransactionException;
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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;

public class TestIDTxFee {
	// CHECKME:
	private static final String IDCHAIN_RPC_ENDPOINT = "https://api-testnet.elastos.io/newid";
	private static final String DID_CONTRACT_ADDRESS = "0xdDCF19F9A52BC3c58F89C43BfB3614293F977ccA";

	// CHECKME: Update to your wallet file and password
	private static final String WALLET = "PATH/TO/IDCHAIN/WALLET/FILE";
	private static final String WALLET_PASSWD = "password";

	// CHECKME: Add test document size
	private static final int TEST_SIZES[] = {1024, 32768, 65536, 98304, 131072};

	private static final String DIDSTORE_PASSWD = "password";
	private static final int FIX_EMBEDDED_VC_CONTENT_SIZE = 590;

	public static class Web3Adapter extends DefaultDIDAdapter {
		private static final BigInteger MAX_WAIT_BLOCKS = BigInteger.valueOf(5);
		private static final BigInteger WAIT_FOR_CONFIRMS = BigInteger.valueOf(2);

		private String contractAddress;

		private Web3j web3j;
		private Credentials account;
		private BigDecimal lastBalance = BigDecimal.ZERO;

		public Web3Adapter(String rpcEndpoint, String contractAddress,
				String walletFile, String walletPassword) {
			super(rpcEndpoint);
			initWeb3j(rpcEndpoint, walletFile, walletPassword);
			this.contractAddress = contractAddress;
		}

		private void initWeb3j(String rpcEndpoint, String walletFile, String walletPassword) {
			web3j = Web3j.build(new HttpService(rpcEndpoint));
			try {
				account = WalletUtils.loadCredentials(walletPassword, walletFile);
				lastBalance = getBalance(account.getAddress());

				System.out.println("================================================");
				System.out.format("Wallet address: %s\n", account.getAddress());
				System.out.format("Wallet balance: %s\n", lastBalance.toString());
				System.out.println("================================================");
			} catch (IOException | CipherException e) {
				throw new RuntimeException("Can not load wallet: " + e.getMessage(), e);
			}
		}

		private BigDecimal getBalance(String address) {
			try {
				EthGetBalance ethGetBalance = web3j.ethGetBalance(address,
						 DefaultBlockParameterName.LATEST).sendAsync().get();
				BigInteger wei = ethGetBalance.getBalance();
				return Convert.fromWei(new BigDecimal(wei), Convert.Unit.ETHER);
			} catch (InterruptedException | ExecutionException e) {
				throw new RuntimeException("Get balance error.", e);
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
				BigInteger gasPrice = new BigInteger("1000000000000");
				BigInteger gasLimit = new BigInteger("3000000");

				TransactionManager txManager = new RawTransactionManager(web3j, account);
				EthSendTransaction ethSendTx = txManager.sendTransaction(
						gasPrice,
						gasLimit,
					    contractAddress,
					    encodedContract,
					    BigInteger.ZERO);

				if (ethSendTx.hasError())
					throw new DIDTransactionException("Error send transaction: " +
							ethSendTx.getError().getMessage());

				String txHash = ethSendTx.getTransactionHash();

				BigInteger currentBlock = web3j.ethBlockNumber().sendAsync().get().getBlockNumber();
				BigInteger lastBlock = web3j.ethBlockNumber().sendAsync().get().getBlockNumber();

				while (true) {
					System.out.print(".");
					EthGetTransactionReceipt receipt = web3j.ethGetTransactionReceipt(txHash).sendAsync().get();
					if (receipt.hasError())
						throw new DIDTransactionException("Error transaction response: " +
								receipt.getError().getMessage());

					if (!receipt.getTransactionReceipt().isPresent()) {
						if (lastBlock.subtract(currentBlock).compareTo(MAX_WAIT_BLOCKS) > 0)
							throw new DIDTransactionException("Create transaction timeout.");

						Thread.sleep(5000);
					} else {
						break;
					}
				}

				while (true) {
					System.out.print(".");

					lastBlock = web3j.ethBlockNumber().sendAsync().get().getBlockNumber();

					EthTransaction tx = web3j.ethGetTransactionByHash(txHash).sendAsync().get();

					BigInteger txBlock = tx.getResult().getBlockNumber();
					BigInteger confirms = lastBlock.subtract(txBlock);
					if (confirms.compareTo(WAIT_FOR_CONFIRMS) >= 0)
						break;
					else
						Thread.sleep(5000);
				}
			} catch(ExecutionException | InterruptedException | IOException e) {
				throw new DIDTransactionException("Error create transaction: " + e.getMessage(), e);
			}

			BigDecimal balance = getBalance(account.getAddress());
			BigDecimal spend = lastBalance.subtract(balance);
			lastBalance = balance;

			System.out.format("Spend %s ELA\n", spend.toString());
		}
	}

	public static void main(String[] args) {
		// Close the verbose log output
	    Logger logger = (Logger)LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
	    logger.setLevel(Level.ERROR);

		DIDBackend.initialize(new Web3Adapter(IDCHAIN_RPC_ENDPOINT, DID_CONTRACT_ADDRESS, WALLET, WALLET_PASSWD));

		try {
			DIDStore store = DIDStore.open("/Users/jingyu/Temp/id/store");

			String mnemonic = Mnemonic.getInstance().generate();

			RootIdentity root = RootIdentity.create(mnemonic, "", store, DIDSTORE_PASSWD);

			for (int size : TEST_SIZES) {
				DIDDocument doc = root.newDid(DIDSTORE_PASSWD);

				int docSize = doc.serialize(true).length();
				if (size - docSize >= FIX_EMBEDDED_VC_CONTENT_SIZE) {
					DIDDocument.Builder db = doc.edit();

					// Create padding data
					int paddingSize = size - docSize - FIX_EMBEDDED_VC_CONTENT_SIZE;
					char[] paddingArray = new char[paddingSize];
					Arrays.fill(paddingArray, 'd');
					String padding = new String(paddingArray);

					// Create vc subject with padding
					Map<String, Object> subject = new HashMap<String, Object>();
					subject.put("data", padding);
					db.addCredential("#test", subject, DIDSTORE_PASSWD);

					doc = db.seal(DIDSTORE_PASSWD);
				}

				docSize = doc.serialize(true).length();
				System.out.format("Publising %s, size(%d).", doc.getSubject().toString(), docSize);
				doc.publish(DIDSTORE_PASSWD);
			}
		} catch (Exception e) {
			e.printStackTrace(System.err);
		}
	}
}
