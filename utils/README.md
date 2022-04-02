# User manual

## Download and installation

The latest DIDUtils binary tarball can be downloaded from: http://github.com/elastos/Elastos.DID.Java.SDK/releases/latest/. First extract the download tarball file `didutils-x.x.x-builddate.tar.gz` to the intended location, e.g. `~/local/didutils`, and you can run the command line tools via the following command.

```shell
cd ~/local/didutils/bin
./didutils
```

## Concepts

The principle of DIDUtils entirely follows the Essentials Identity application. So if you have an identity and DIDs in Essentials, it'll be easy for you to understand and adopt this command line tool.

This tool will run under a real user's identity and DID context, including:

- Network - current active network, could be mainnet, testnet or any user deployed private network.
- Identity - the user's root identity, identical with the identity in Essentials.
- DID - the user's active DID, identical with the user's DID in Essentials.
- Wallet - the wallet that manages the ELA tokens used for ID transactions.

By default, the DIDUtils will adopt mainnet and without the user's identity. Users need to create a new identity or import an existing one, before which only limited features are enabled and the DIDUtils can only run the resolve and verify related subcommands. 


The DIDUtils's command line syntax adopts the following pattern:

```shell
didutils <subcommand> [options]
```

Get the subcommands list and help using `--help` command line option, which applies to any subcommands.

DIDUtils also provides an interactive shell mode. Use the `sh` subcommand to enter the interactive shell.

```shell
didutils sh
```

In the shell mode, the subcommands can be entered directly, which will be much more convenient if you want to do a series of DID operations. `exit` or `quit` will end the interactive shell and return to the system shell.

## Begin using DIDUtils with your identity

When you begin using DIDUtils, you can create a new identity or import an existing identity with mnemonic words.

### Creating a new identity

```shell
didutils id create <your-identity-name>
```
The mnemonic, having been prints on the console safely, should be backuped.  Then set the mnemonic passphrase(ENTER for empty) and the password for the newly created DID store, following the prompt. By default, the DIDUtils will create a DID(at index 0)  that won't be published, as there's no fund in the newly created wallet to create the DID publish transaction at the moment. In accordance to this, all later created DIDs will not be published after creation as well, and should be published manually using the `did publish` subcommand.

### Importing an existing identity

```shell
didutils id create -i <your-identity-name>
```

Next, input your mnemonic and passphrase(ENTER for empty), and set the password for the newly created DID store, following the prompt.

### ID Wallet

When the DIDUtils create or import an identity, the **ID wallet** related to the identity will be created automatically. If the identity is newly created, the wallet balance will be 0. If the identity is an existing one, the wallet will be identical with the previous wallet related to the identity and have the same balance.

Any compatible ID wallet(e.g. Essentials ID sidechain wallet) can be used to transfer the fund to the wallet. If the wallet has enough fund, it can be used to publish your DIDs or VCs. Within DIDUtils, the subcommand `wallet address` can be used to show the wallet address, and the subcommand `wallet balance` can be used to show the current balance.

## Subcommands

Only a brief list for the subcommands is shown here, and the subcommands all support getting the detailed command line syntax via the `--help` option.

### network

Switch or manage the networks.

- [empty] - show the current network information.
- **switch** - Wwitch the active network.
- **list** - List the available private networks.
- **add** - Add a new private network.
- **delete -** Delete a private network.

### wallet

Manage the wallet and funds.

- **address** - Show the wallet address.
- **balance** - Show the wallet balance.
- **transfer** - Transfer tokens from this wallet to another.

### id

Switch or manage the identities.

- [empty] - Show the current identity.
- **switch** - Switch the active identity.
- **list -** List all the identities.
- **create -** Create a user identity.
- **delete** - Delete a user identity.
- **export** Export the identity.
- **sync -** Synchronize all DIDs that belong to the identity.
- **recover -** Check all the DIDs attached to the identity and try to recover if something goes wrong.

### did

Switch or manage the DIDs.

- [empty] - Show the current DID.
- **switch** - Switch the active DID.
- **resolve** - Resolve DIDs from the ID side chain.
- **show** - Show the local DID document and metadata.
- **create** - Create a new DID.
- **createappdid** - Create a new application DID.
- **createcid** - Create a new customized DID.
- **acquirecid** - Acquire a customized DID.
- **transfercid** - Transfer a customized DID.
- **edit** - Modify the DID document.
- **list** - List all the DIDs.
- **delete** - Delete a DID.
- **publish** - Publish a DID.
- **renew** - Renew a DID.
- **export** - Export a DID.
- **sync** - Synchronize a DID.
- **deactivate** - Deactivate a DID.
- **verify** - Verify the local DID document.

### vc

Manage the user's credentials.

- **resolve** - Resolve credentials from the ID side chain.
- **show** - Show the local credential and metadata.
- **issue** - Issue a new credential.
- **list** - List the local credentials.
- **rlist** - List the declared credentials from the ID side chain.
- **delete** - Delete a credential.
- **declare** - Declare a credential.
- **revoke** - Revoke a credential.
- **verify** - Verify a local credential.

### vp

Create or verify the presentations.

- **create** - Create a presentation.

- **verify** - Verify the local verifiable presentation.

### jwt

Create or verify the JSON web tokens.

- **create** - Create a JWT/JWS token.

- **verify** - Verify the JWT/JWS token.

### jsonld

JSON-LD tools for developer.

- **expand** - Expand the JSON-LD document.
- **compact** - Compact the expanded JSON-LD document.
- **verify** - Verify the JSON-LD document.

### sh

The interactive shell.

### simchain

The simulated ID side chain with a local HTTP server and REST API used for development and testing.
