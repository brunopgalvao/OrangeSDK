// ethers v6 against an Orange node: what a dapp or a backend does with it.
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import {
  ContractFactory,
  JsonRpcProvider,
  Wallet,
  isCallException,
  parseEther,
  parseUnits,
} from 'ethers';
import { CHAIN_ID, FUNDED, FUNDED_KEY, RPC, SUPPLY, rpc, token, until } from './common.mjs';

// ethers answers a request identical to one made in the last 250 ms from
// its cache (`cacheTimeout`). With 400 ms slots a transaction can be sent,
// mined and its receipt read within that, and the next send then signs
// with the cached pending nonce, which the node refuses as too low: the
// same happens against anvil or hardhat. Fast chains turn the cache off
// (spec 20 §7).
const provider = new JsonRpcProvider(RPC, undefined, { pollingInterval: 250, cacheTimeout: -1 });
const funded = new Wallet(FUNDED_KEY, provider);
const user = Wallet.createRandom(provider);

after(() => provider.destroy());

describe('ethers: chain', () => {
  it('reports the chain id', async () => {
    const network = await provider.getNetwork();
    assert.equal(network.chainId, BigInt(CHAIN_ID));
  });

  it('sees blocks being made', async () => {
    const first = await provider.getBlockNumber();
    await until('a new block', async () => Number(await rpc('eth_blockNumber')) > first);
  });

  it('reads blocks by number, hash and tag', async () => {
    const latest = await provider.getBlock('latest');
    assert.ok(latest.number > 0);
    assert.match(latest.hash, /^0x[0-9a-f]{64}$/);
    const byHash = await provider.getBlock(latest.hash);
    assert.equal(byHash.number, latest.number);
    assert.equal(byHash.parentHash, (await provider.getBlock(latest.number - 1)).hash);
    assert.ok(latest.baseFeePerGas >= parseUnits('1', 'gwei'), 'the suite genesis sets a 1 gwei floor');
    const finalized = await provider.getBlock('finalized');
    assert.ok(finalized.number <= latest.number + 1);
    const genesis = await provider.getBlock(0);
    assert.equal(genesis.number, 0);
  });
});

describe('ethers: accounts and transfers', () => {
  it('reads the funded balance and nonce', async () => {
    assert.ok((await provider.getBalance(FUNDED)) > parseEther('1000'));
    const nonce = await provider.getTransactionCount(FUNDED, 'latest');
    assert.equal(await provider.getTransactionCount(FUNDED, 'pending'), nonce);
  });

  it('prices transactions from the fee market', async () => {
    const fees = await provider.getFeeData();
    assert.ok(fees.gasPrice > 0n);
    assert.ok(fees.maxFeePerGas > fees.maxPriorityFeePerGas);
    const history = await provider.send('eth_feeHistory', ['0x4', 'latest', [25, 75]]);
    assert.equal(history.baseFeePerGas.length, 5);
    assert.equal(history.reward.length, 4);
  });

  it('sends a signed EIP-1559 transfer and waits for its receipt', async () => {
    const value = parseEther('5');
    const tx = await funded.sendTransaction({ to: user.address, value });
    assert.equal(tx.type, 2);
    const receipt = await tx.wait();
    assert.equal(receipt.status, 1);
    assert.equal(receipt.type, 2);
    assert.equal(receipt.gasUsed, 21000n);
    assert.equal(await provider.getBalance(user.address), value);
    const mined = await provider.getTransaction(tx.hash);
    assert.equal(mined.blockNumber, receipt.blockNumber);
    assert.equal(mined.from, FUNDED);
    const block = await provider.getBlock(receipt.blockNumber);
    assert.ok(block.transactions.includes(tx.hash));
  });

  it('sends a legacy EIP-155 transaction', async () => {
    const gasPrice = (await provider.getFeeData()).gasPrice;
    const tx = await user.sendTransaction({ type: 0, to: FUNDED, value: 1n, gasPrice });
    assert.equal(tx.type, 0);
    assert.equal(tx.chainId, BigInt(CHAIN_ID));
    const receipt = await tx.wait();
    assert.equal(receipt.status, 1);
    assert.equal(receipt.type, 0);
    const mined = await provider.getTransaction(tx.hash);
    assert.equal(mined.type, 0);
    assert.equal(mined.chainId, BigInt(CHAIN_ID));
  });

  it('sends an EIP-2930 access-list transaction', async () => {
    const gasPrice = (await provider.getFeeData()).gasPrice;
    const tx = await user.sendTransaction({
      type: 1,
      to: FUNDED,
      value: 1n,
      gasPrice,
      accessList: [{ address: FUNDED, storageKeys: [] }],
    });
    const receipt = await tx.wait();
    assert.equal(receipt.status, 1);
    assert.equal(receipt.type, 1);
  });

  it('refuses a reused nonce in geth words', async () => {
    const nonce = (await provider.getTransactionCount(user.address)) - 1;
    await assert.rejects(user.sendTransaction({ to: FUNDED, value: 1n, nonce }), (e) => {
      assert.equal(e.code, 'NONCE_EXPIRED');
      return true;
    });
  });
});

describe('ethers: a token contract', () => {
  let erc20;
  let address;
  let deployBlock;

  before(async () => {
    const { abi, bytecode } = token();
    const factory = new ContractFactory(abi, bytecode, funded);
    erc20 = await factory.deploy(SUPPLY);
    const receipt = await erc20.deploymentTransaction().wait();
    deployBlock = receipt.blockNumber;
    await erc20.waitForDeployment();
    address = await erc20.getAddress();
    assert.equal(receipt.contractAddress, address);
  });

  it('serves the deployed code and the calls', async () => {
    assert.ok((await provider.getCode(address)).length > 2);
    assert.equal(await erc20.name(), 'Orange Test Token');
    assert.equal(await erc20.symbol(), 'STT');
    assert.equal(await erc20.decimals(), 18n);
    assert.equal(await erc20.totalSupply(), SUPPLY);
    assert.equal(await erc20.balanceOf(FUNDED), SUPPLY);
  });

  it('estimates gas, transfers and logs', async () => {
    const estimate = await erc20.transfer.estimateGas(user.address, 1000n);
    assert.ok(estimate > 21000n && estimate < 100000n, `estimate ${estimate}`);
    const tx = await erc20.transfer(user.address, 1000n);
    const receipt = await tx.wait();
    assert.equal(receipt.status, 1);
    assert.ok(receipt.gasUsed <= estimate);
    const [log] = receipt.logs;
    const parsed = erc20.interface.parseLog(log);
    assert.equal(parsed.name, 'Transfer');
    assert.equal(parsed.args.to, user.address);
    assert.equal(parsed.args.value, 1000n);
    assert.equal(await erc20.balanceOf(user.address), 1000n);
  });

  it('finds events with eth_getLogs', async () => {
    const all = await erc20.queryFilter(erc20.filters.Transfer(), deployBlock);
    assert.equal(all.length, 2, 'the mint and the transfer');
    assert.equal(all[0].args.from, '0x0000000000000000000000000000000000000000');
    const toUser = await erc20.queryFilter(erc20.filters.Transfer(null, user.address), deployBlock);
    assert.equal(toUser.length, 1);
  });

  it('delivers events to a listener through a log filter', async () => {
    const seen = new Promise((resolve) => {
      erc20.once('Transfer', (from, to, value) => resolve({ from, to, value }));
    });
    // The listener installs its filter before the transfer is sent.
    await new Promise((resolve) => setTimeout(resolve, 500));
    await (await erc20.transfer(user.address, 7n)).wait();
    const event = await Promise.race([
      seen,
      new Promise((_, reject) => setTimeout(() => reject(new Error('no event')), 20_000)),
    ]);
    assert.equal(event.to, user.address);
    assert.equal(event.value, 7n);
  });

  it('delivers new blocks to a listener', async () => {
    const block = await new Promise((resolve) => provider.once('block', resolve));
    assert.ok(block > 0);
  });

  it('surfaces a custom error from a call', async () => {
    await assert.rejects(erc20.connect(user).transfer.staticCall(FUNDED, 10n ** 30n), (e) => {
      assert.ok(isCallException(e), e.message);
      assert.equal(e.revert?.name, 'InsufficientBalance');
      assert.equal(e.revert.args[2], 10n ** 30n);
      return true;
    });
  });

  it('surfaces a revert string from gas estimation', async () => {
    await assert.rejects(erc20.connect(user).transferFrom.estimateGas(FUNDED, user.address, 1n), (e) => {
      assert.ok(isCallException(e), e.message);
      assert.equal(e.reason, 'allowance exceeded');
      return true;
    });
  });

  it('reports a reverted transaction as failed', async () => {
    const tx = await erc20.connect(user).transfer(FUNDED, 10n ** 30n, { gasLimit: 100000n });
    await assert.rejects(tx.wait(), (e) => {
      assert.ok(isCallException(e), e.message);
      assert.equal(e.receipt.status, 0);
      return true;
    });
  });
});
