# Hadamard/op-geth — Hash-Only L2 Execution Engine

This is a research fork of [op-geth](https://github.com/ethereum-optimism/op-geth) (OP Stack execution layer) extended with two new transaction types and an ECDSA-free state transition for the **Hash-Only L2** protocol.

> Part of [Hadamard/OP](https://github.com/Hadamard/OP) — a post-quantum OP Stack rollup where all L2 authentication uses hash-preimage reveals instead of elliptic-curve signatures.

**Branch:** `feat/hash-l2-txtypes`  
**Latest commit:** `9cbad25` — cross-block Commit-Reveal (nonce N+1 design, contractCreation override)

---

## Hash-Only L2 Changes

### New Transaction Types

| TxType | Hex | Name | Description |
|--------|-----|------|-------------|
| `0x7C` | 124 | `HashCommitTx` | Commit phase — binds `txDigest` in `hashCommit` before revealing the preimage |
| `0x7F` | 127 | `HashRevealTx` | Reveal phase — authenticates via hash-chain preimage, no ECRECOVER |

> `0x7E` = DepositTx (standard OP Stack). `0x7D` = PostExecTxType (reserved).

### New Files

| File | Description |
|------|-------------|
| `core/types/tx_hashcommit.go` | `HashCommitTx` struct, RLP encoding, innerTx interface |
| `core/types/tx_hashreveal.go` | `HashRevealTx` struct, `TxDigest()`, `Nullifier` |
| `core/types/tx_hashsigning.go` | `HashSenderFromTx()`, `HashRevealInner()`, `HashCommitInner()` |
| `core/types/transaction_signing.go` | `modernSigner.Sender()` dispatches hash types without ECRECOVER |
| `core/hash_nullifier.go` | `NullifierState` — reads/writes `NullifierTree` predeploy storage via slot math |
| `core/state_transition_hash.go` | `hashRevealPreCheck` (6 steps), `hashCommitPostExec`, `hashRevealPostExec` |
| `core/state_transition.go` | `IsHashRevealTx`/`IsHashCommitTx` message fields; ecrecover gate post-Onyx |
| `core/vm/evm.go` | `BlockContext.HashCommitSlots` — block-local commit map for same-block path |
| `core/vm/contracts_hash_l2.go` | Precompiles `0x0101` hashAddr, `0x0102` verifyHashChain, `0x0A` Poseidon-BN254 |
| `core/vm/contracts.go` | `PrecompiledContractsOnyx`; `activePrecompiledContracts()` Onyx case |
| `core/hash_stealth.go` | OTA key derivation helpers, `StealthPoolState` reader |
| `core/hash_e2e_test.go` | `TestHashRevealTxE2E`, `TestHashRevealTxCrossBlock` integration tests |

### Custom Precompiles (active post-Onyx hardfork)

| Address | Name | Gas | Description |
|---------|------|-----|-------------|
| `0x0101` | `hashAddr` | 600 | `trunc20(keccak256("OP_HASH_ADDR_v1" ‖ commitment))` |
| `0x0102` | `verifyHashChain` | 600 | `keccak256(curr) == prev → 0x01 / 0x00` |
| `0x0A` | Poseidon-BN254 | 3000 | Poseidon hash (t=3, RF=8, RP=57) for NullifierTree IMT |

> `0x0B`–`0x11` are reserved by EIP-2537 (BLS12-381). `0x0A` is safe post-Cancun (KZG point-evaluation is `0x0A` only until EIP-4844 activation — post-Cancun it is a precompile, but Onyx is only active after Cancun).

### Commit-Reveal State Transition

`HashCommitTx` execution in `state_transition.go`:
1. `contractCreation = false` override → intrinsic gas = `TxGas` (21000), not `TxGasContractCreation` (53000)
2. Skip EVM; only `SetNonce(from, N→N+1)`
3. `hashCommitPostExec` writes `hashCommit` to `NullifierTree` slots 73 (`pendingCommits`) + 74 (`commitExpiry`)

`HashRevealTx` 6-step pre-check in `state_transition_hash.go`:
1. Verify `NullifierTree.isRegistered(from)` (OTA exists)
2. Verify chain link: `keccak256(preImage) == lastReveal[from]`
3. Verify nullifier not spent
4. Verify `txDigest` matches reveal transaction fields
5. Verify nullifier formula
6. Verify `hashCommit` — same-block path (`BlockContext.HashCommitSlots`) OR cross-block path (`pendingCommits[from]`, block ≤ `commitExpiry[from]`)

**Nonce design:** CommitTx sends with nonce N (increments to N+1). RevealTx sends with nonce N+1. All hash-chain bindings (txDigest, nullifier, hashCommit) use reveal nonce N+1.

### Integration Tests

```bash
go test ./core/ -run "TestHashRevealTxE2E|TestHashRevealTxCrossBlock" -v
```

Both pass on `feat/hash-l2-txtypes` (commit `9cbad25`).

### Building

```bash
git clone https://github.com/Hadamard/op-geth
cd op-geth
git checkout feat/hash-l2-txtypes
go build ./cmd/geth
```

For use in the monorepo, see [Hadamard/OP](https://github.com/Hadamard/OP) (`feat/hash-only-l2`).

---

## Go Ethereum

Golang execution layer implementation of the Ethereum protocol.

[![API Reference](
https://pkg.go.dev/badge/github.com/ethereum/go-ethereum
)](https://pkg.go.dev/github.com/ethereum/go-ethereum?tab=doc)
[![Go Report Card](https://goreportcard.com/badge/github.com/ethereum/go-ethereum)](https://goreportcard.com/report/github.com/ethereum/go-ethereum)
[![Travis](https://app.travis-ci.com/ethereum/go-ethereum.svg?branch=master)](https://app.travis-ci.com/github/ethereum/go-ethereum)
[![Discord](https://img.shields.io/badge/discord-join%20chat-blue.svg)](https://discord.gg/nthXNEv)
[![Twitter](https://img.shields.io/twitter/follow/go_ethereum)](https://x.com/go_ethereum)

Automated builds are available for stable releases and the unstable master branch. Binary
archives are published at https://geth.ethereum.org/downloads/.

## Building the source

For prerequisites and detailed build instructions please read the [Installation Instructions](https://geth.ethereum.org/docs/getting-started/installing-geth).

Building `geth` requires both a Go (version 1.23 or later) and a C compiler. You can install
them using your favourite package manager. Once the dependencies are installed, run

```shell
make geth
```

or, to build the full suite of utilities:

```shell
make all
```

## Executables

The go-ethereum project comes with several wrappers/executables found in the `cmd`
directory.

|  Command   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| :--------: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`geth`** | Our main Ethereum CLI client. It is the entry point into the Ethereum network (main-, test- or private net), capable of running as a full node (default), archive node (retaining all historical state) or a light node (retrieving data live). It can be used by other processes as a gateway into the Ethereum network via JSON RPC endpoints exposed on top of HTTP, WebSocket and/or IPC transports. `geth --help` and the [CLI page](https://geth.ethereum.org/docs/fundamentals/command-line-options) for command line options. |
|   `clef`   | Stand-alone signing tool, which can be used as a backend signer for `geth`.                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|  `devp2p`  | Utilities to interact with nodes on the networking layer, without running a full blockchain.                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|  `abigen`  | Source code generator to convert Ethereum contract definitions into easy-to-use, compile-time type-safe Go packages. It operates on plain [Ethereum contract ABIs](https://docs.soliditylang.org/en/develop/abi-spec.html) with expanded functionality if the contract bytecode is also available. However, it also accepts Solidity source files, making development much more streamlined. Please see our [Native DApps](https://geth.ethereum.org/docs/developers/dapp-developer/native-bindings) page for details.                                  |
|   `evm`    | Developer utility version of the EVM (Ethereum Virtual Machine) that is capable of running bytecode snippets within a configurable environment and execution mode. Its purpose is to allow isolated, fine-grained debugging of EVM opcodes (e.g. `evm --code 60ff60ff --debug run`).                                                                                                                                                                                                                                               |
| `rlpdump`  | Developer utility tool to convert binary RLP ([Recursive Length Prefix](https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp)) dumps (data encoding used by the Ethereum protocol both network as well as consensus wise) to user-friendlier hierarchical representation (e.g. `rlpdump --hex CE0183FFFFFFC4C304050583616263`).                                                                                                                                                                                |

## Running `geth`

Going through all the possible command line flags is out of scope here (please consult our
[CLI Wiki page](https://geth.ethereum.org/docs/fundamentals/command-line-options)),
but we've enumerated a few common parameter combos to get you up to speed quickly
on how you can run your own `geth` instance.

### Hardware Requirements

Minimum:

* CPU with 4+ cores
* 8GB RAM
* 1TB free storage space to sync the Mainnet
* 8 MBit/sec download Internet service

Recommended:

* Fast CPU with 8+ cores
* 16GB+ RAM
* High-performance SSD with at least 1TB of free space
* 25+ MBit/sec download Internet service

### Full node on the main Ethereum network

By far the most common scenario is people wanting to simply interact with the Ethereum
network: create accounts; transfer funds; deploy and interact with contracts. For this
particular use case, the user doesn't care about years-old historical data, so we can
sync quickly to the current state of the network. To do so:

```shell
$ geth console
```

This command will:
 * Start `geth` in snap sync mode (default, can be changed with the `--syncmode` flag),
   causing it to download more data in exchange for avoiding processing the entire history
   of the Ethereum network, which is very CPU intensive.
 * Start the built-in interactive [JavaScript console](https://geth.ethereum.org/docs/interacting-with-geth/javascript-console),
   (via the trailing `console` subcommand) through which you can interact using [`web3` methods](https://github.com/ChainSafe/web3.js/blob/0.20.7/DOCUMENTATION.md) 
   (note: the `web3` version bundled within `geth` is very old, and not up to date with official docs),
   as well as `geth`'s own [management APIs](https://geth.ethereum.org/docs/interacting-with-geth/rpc).
   This tool is optional and if you leave it out you can always attach it to an already running
   `geth` instance with `geth attach`.

### A Full node on the Holesky test network

Transitioning towards developers, if you'd like to play around with creating Ethereum
contracts, you almost certainly would like to do that without any real money involved until
you get the hang of the entire system. In other words, instead of attaching to the main
network, you want to join the **test** network with your node, which is fully equivalent to
the main network, but with play-Ether only.

```shell
$ geth --holesky console
```

The `console` subcommand has the same meaning as above and is equally
useful on the testnet too.

Specifying the `--holesky` flag, however, will reconfigure your `geth` instance a bit:

 * Instead of connecting to the main Ethereum network, the client will connect to the Holesky 
   test network, which uses different P2P bootnodes, different network IDs and genesis
   states.
 * Instead of using the default data directory (`~/.ethereum` on Linux for example), `geth`
   will nest itself one level deeper into a `holesky` subfolder (`~/.ethereum/holesky` on
   Linux). Note, on OSX and Linux this also means that attaching to a running testnet node
   requires the use of a custom endpoint since `geth attach` will try to attach to a
   production node endpoint by default, e.g.,
   `geth attach <datadir>/holesky/geth.ipc`. Windows users are not affected by
   this.

*Note: Although some internal protective measures prevent transactions from
crossing over between the main network and test network, you should always
use separate accounts for play and real money. Unless you manually move
accounts, `geth` will by default correctly separate the two networks and will not make any
accounts available between them.*

### Configuration

As an alternative to passing the numerous flags to the `geth` binary, you can also pass a
configuration file via:

```shell
$ geth --config /path/to/your_config.toml
```

To get an idea of how the file should look like you can use the `dumpconfig` subcommand to
export your existing configuration:

```shell
$ geth --your-favourite-flags dumpconfig
```

#### Docker quick start

One of the quickest ways to get Ethereum up and running on your machine is by using
Docker:

```shell
docker run -d --name ethereum-node -v /Users/alice/ethereum:/root \
           -p 8545:8545 -p 30303:30303 \
           ethereum/client-go
```

This will start `geth` in snap-sync mode with a DB memory allowance of 1GB, as the
above command does.  It will also create a persistent volume in your home directory for
saving your blockchain as well as map the default ports. There is also an `alpine` tag
available for a slim version of the image.

Do not forget `--http.addr 0.0.0.0`, if you want to access RPC from other containers
and/or hosts. By default, `geth` binds to the local interface and RPC endpoints are not
accessible from the outside.

### Programmatically interfacing `geth` nodes

As a developer, sooner rather than later you'll want to start interacting with `geth` and the
Ethereum network via your own programs and not manually through the console. To aid
this, `geth` has built-in support for a JSON-RPC based APIs ([standard APIs](https://ethereum.org/en/developers/docs/apis/json-rpc/)
and [`geth` specific APIs](https://geth.ethereum.org/docs/interacting-with-geth/rpc)).
These can be exposed via HTTP, WebSockets and IPC (UNIX sockets on UNIX based
platforms, and named pipes on Windows).

The IPC interface is enabled by default and exposes all the APIs supported by `geth`,
whereas the HTTP and WS interfaces need to manually be enabled and only expose a
subset of APIs due to security reasons. These can be turned on/off and configured as
you'd expect.

HTTP based JSON-RPC API options:

  * `--http` Enable the HTTP-RPC server
  * `--http.addr` HTTP-RPC server listening interface (default: `localhost`)
  * `--http.port` HTTP-RPC server listening port (default: `8545`)
  * `--http.api` API's offered over the HTTP-RPC interface (default: `eth,net,web3`)
  * `--http.corsdomain` Comma separated list of domains from which to accept cross-origin requests (browser enforced)
  * `--ws` Enable the WS-RPC server
  * `--ws.addr` WS-RPC server listening interface (default: `localhost`)
  * `--ws.port` WS-RPC server listening port (default: `8546`)
  * `--ws.api` API's offered over the WS-RPC interface (default: `eth,net,web3`)
  * `--ws.origins` Origins from which to accept WebSocket requests
  * `--ipcdisable` Disable the IPC-RPC server
  * `--ipcpath` Filename for IPC socket/pipe within the datadir (explicit paths escape it)

You'll need to use your own programming environments' capabilities (libraries, tools, etc) to
connect via HTTP, WS or IPC to a `geth` node configured with the above flags and you'll
need to speak [JSON-RPC](https://www.jsonrpc.org/specification) on all transports. You
can reuse the same connection for multiple requests!

**Note: Please understand the security implications of opening up an HTTP/WS based
transport before doing so! Hackers on the internet are actively trying to subvert
Ethereum nodes with exposed APIs! Further, all browser tabs can access locally
running web servers, so malicious web pages could try to subvert locally available
APIs!**

### Operating a private network

Maintaining your own private network is more involved as a lot of configurations taken for
granted in the official networks need to be manually set up.

Unfortunately since [the Merge](https://ethereum.org/en/roadmap/merge/) it is no longer possible
to easily set up a network of geth nodes without also setting up a corresponding beacon chain.

There are three different solutions depending on your use case:

  * If you are looking for a simple way to test smart contracts from go in your CI, you can use the [Simulated Backend](https://geth.ethereum.org/docs/developers/dapp-developer/native-bindings#blockchain-simulator).
  * If you want a convenient single node environment for testing, you can use our [Dev Mode](https://geth.ethereum.org/docs/developers/dapp-developer/dev-mode).
  * If you are looking for a multiple node test network, you can set one up quite easily with [Kurtosis](https://geth.ethereum.org/docs/fundamentals/kurtosis).

## Contribution

Thank you for considering helping out with the source code! We welcome contributions
from anyone on the internet, and are grateful for even the smallest of fixes!

If you'd like to contribute to go-ethereum, please fork, fix, commit and send a pull request
for the maintainers to review and merge into the main code base. If you wish to submit
more complex changes though, please check up with the core devs first on [our Discord Server](https://discord.gg/invite/nthXNEv)
to ensure those changes are in line with the general philosophy of the project and/or get
some early feedback which can make both your efforts much lighter as well as our review
and merge procedures quick and simple.

Please make sure your contributions adhere to our coding guidelines:

 * Code must adhere to the official Go [formatting](https://golang.org/doc/effective_go.html#formatting)
   guidelines (i.e. uses [gofmt](https://golang.org/cmd/gofmt/)).
 * Code must be documented adhering to the official Go [commentary](https://golang.org/doc/effective_go.html#commentary)
   guidelines.
 * Pull requests need to be based on and opened against the `master` branch.
 * Commit messages should be prefixed with the package(s) they modify.
   * E.g. "eth, rpc: make trace configs optional"

Please see the [Developers' Guide](https://geth.ethereum.org/docs/developers/geth-developer/dev-guide)
for more details on configuring your environment, managing project dependencies, and
testing procedures.

### Contributing to geth.ethereum.org

For contributions to the [go-ethereum website](https://geth.ethereum.org), please checkout and raise pull requests against the `website` branch.
For more detailed instructions please see the `website` branch [README](https://github.com/ethereum/go-ethereum/tree/website#readme) or the 
[contributing](https://geth.ethereum.org/docs/developers/geth-developer/contributing) page of the website.

## License

The go-ethereum library (i.e. all code outside of the `cmd` directory) is licensed under the
[GNU Lesser General Public License v3.0](https://www.gnu.org/licenses/lgpl-3.0.en.html),
also included in our repository in the `COPYING.LESSER` file.

The go-ethereum binaries (i.e. all code inside of the `cmd` directory) are licensed under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html), also
included in our repository in the `COPYING` file.
