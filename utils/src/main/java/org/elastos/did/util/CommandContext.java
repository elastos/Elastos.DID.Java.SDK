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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.elastos.did.DID;
import org.elastos.did.DIDBackend;
import org.elastos.did.DIDEntity;
import org.elastos.did.DIDStore;
import org.elastos.did.DefaultDIDAdapter;
import org.elastos.did.Features;
import org.elastos.did.RootIdentity;
import org.elastos.did.exception.DIDException;
import org.jline.reader.LineReader;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;

public class CommandContext extends DIDEntity<CommandContext> {
	@JsonProperty
	@JsonInclude(Include.NON_EMPTY)
	private String network;
	@JsonProperty
	@JsonInclude(Include.NON_EMPTY)
	private String identity;

	@JsonProperty
	@JsonInclude(Include.NON_EMPTY)
	private Map<String, Network> networks;

	@JsonIgnore
	private DIDStore didStore;
	@JsonIgnore
	private Web3Adapter didAdapter;

	@JsonIgnore
	private LineReader reader;

	@JsonIgnore
	private static String password;

	@JsonIgnore
	private static CommandContext context;

	@JsonIgnore
	private static File contextFile;

	@JsonCreator
	private CommandContext(@JsonProperty(value = "network") String network,
			@JsonProperty(value = "identity") String identity) {
		this.network = network;
		this.identity = identity;
		networks = new HashMap<>();
	}

	private CommandContext(CommandContext ref) {
		this.network = ref.network;
		this.identity = ref.identity;
		this.networks = ref.networks;
	}

	protected static void initialize() {
		if (context != null)
			return;

		Features.enableJsonLdContext(true);

		try {
			CommandContext ctx;
			File dir = DIDUtils.getHome();
			contextFile = new File(dir, "config.json");
			if (!contextFile.exists())
				ctx = new CommandContext(null, null);
			else
				ctx = parse(contextFile, CommandContext.class);

			ctx.reinitialize();
			context = ctx;
		} catch (Exception e) {
			System.out.println(Colorize.red("Error initialize the command context: " + e.getMessage()));
			e.printStackTrace(System.err);

			// Quit directly when we can not initialize the context
			System.exit(-1);
		}
	}

	public static CommandContext getInstance() {
		if (context == null)
			initialize();

		return context;
	}

	public void setLineReader(LineReader reader) {
		this.reader = reader;
	}

	public LineReader getLineReader() {
		return reader;
	}

	private void save() throws IOException {
		serialize(contextFile);
	}

	private void reinitialize() throws DIDException {
		if (getIdentity() == null) {
			// Initialize DIDBackend in resolve-only mode.
			DIDBackend.initialize(new DefaultDIDAdapter(getActiveNetwork().getRpcEndpint()));
		} else {
			// Initialize the Web3 adapter using wallet at: $APPHOME/identity/wallet.json
			File walletFile = new File(DIDUtils.getHome(), getIdentity() + File.separator + "wallet.json");
			didAdapter = new Web3Adapter(getNetwork(getNetwork()), walletFile);

			DIDBackend.initialize(didAdapter);
		}
	}

	private String getNetwork() {
		return network != null ? network : Network.MAINNET.getName();
	}

	private String getIdentity() {
		return identity;
	}

	public Network getNetwork(String name) {
		if (name.equalsIgnoreCase(Network.MAINNET.getName()))
			return Network.MAINNET;
		else if (name.equalsIgnoreCase(Network.TESTNET.getName()))
			return Network.TESTNET;
		else
			return networks.get(name);
	}

	protected void addNetwork1(String name, String rpcEndpoint, String contractAddress, Long chainId) throws IOException {
		if (networks.containsKey(name))
			throw new IllegalArgumentException("Network " + name + " already exists");

		Network network = new Network(name, rpcEndpoint, contractAddress, chainId);
		networks.put(network.getName(), network);

		save();
	}

	@JsonSetter("networks")
	protected void setNetworks(Map<String, Network> networks) {
		for (Map.Entry<String, Network> entry : networks.entrySet())
			entry.getValue().setName(entry.getKey());

		this.networks = networks;
	}

	protected boolean addNetwork(Network network) throws IOException {
		if (getNetwork(network.getName()) != null)
			return false;

		networks.put(network.getName(), network);
		save();
		return true;
	}

	protected boolean deleteNetwork(String name) throws IOException {
		if (!networks.containsKey(name))
			return false;

		networks.remove(name);
		save();
		return true;
	}

	public Map<String, Network> getNetworks() {
		return Collections.unmodifiableMap(networks);
	}

	public boolean switchIdentity(String identity) throws DIDException, IOException {
		if (!Identities.exists(identity))
			return false;

		CommandContext ctx = new CommandContext(context);
		ctx.identity = identity;
		ctx.reinitialize();
		ctx.save();

		password = null;
		context = ctx;
		return true;
	}

	public boolean switchNetwork(String network) throws DIDException, IOException {
		if (getNetwork(network) == null)
			return false;

		CommandContext ctx = new CommandContext(context);
		ctx.network = network;
		ctx.reinitialize();
		ctx.save();

		password = null;
		context = ctx;
		return true;
	}


	public Network getActiveNetwork() {
		return getNetwork(getNetwork());
	}

	public String getActiveIdentity() {
		return getIdentity();
	}

	protected DIDStore getActiveStore() throws IOException, DIDException {
		if (identity == null)
			return null;

		if (didStore != null)
			return didStore;

		didStore = Identities.openStore(getIdentity(), getNetwork());
		return didStore;
	}

	protected RootIdentity getActiveRootIdentity() throws IOException, DIDException {
		if (identity == null)
			return null;

		DIDStore store = getActiveStore();
		return store.loadRootIdentity();
	}

	public DID getActivateDid() throws IOException, DIDException {
		if (identity == null)
			return null;

		DIDStore store = getActiveStore();
		return store.loadRootIdentity().getDefaultDid();
	}

	protected File getActiveWallet() {
		if (identity == null)
			return null;

		return Wallets.getWalletFile(getIdentity());
	}

	protected Web3Adapter getActiveDidAdapter() {
		return didAdapter;
	}

	static String getPassword() {
		if (password == null) {
			while (true) {
				password = new String(System.console().readPassword("Password: "));
				if (password.isEmpty())
					System.out.println(Colorize.yellow("Password can not be empty."));
				else
					break;
			}
		}

		return password;
	}
}