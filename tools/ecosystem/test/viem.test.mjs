// viem against a Solo node: public and wallet clients over HTTP, the way
// wagmi apps and scripts use them.
import assert from 'node:assert/strict';
import { before, describe, it } from 'node:test';
import {
  BaseError,
  ContractFunctionRevertedError,
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
  parseEther,
  parseGwei,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { CHAIN_ID, FUNDED, FUNDED_KEY, RPC, SUPPLY, token, until } from './common.mjs';

const chain = defineChain({
  id: CHAIN_ID,
  name: 'Solo devnet',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: [RPC] } },
});
const transport = http(RPC);
const client = createPublicClient({ chain, transport, pollingInterval: 250 });
const funded = createWalletClient({ account: privateKeyToAccount(FUNDED_KEY), chain, transport });
const userAccount = privateKeyToAccount(generatePrivateKey());
const user = createWalletClient({ account: userAccount, chain, transport });

/** The revert a viem error carries, if any. */
function revertOf(error) {
  assert.ok(error instanceof BaseError, String(error));
  const revert = error.walk((e) => e instanceof ContractFunctionRevertedError);
  assert.ok(revert, `no revert in: ${error.message}`);
  return revert;
}

describe('viem: chain', () => {
  it('reports the chain id', async () => {
    assert.equal(await client.getChainId(), CHAIN_ID);
  });

  it('watches the block number rise', async () => {
    const seen = [];
    await new Promise((resolve, reject) => {
      const unwatch = client.watchBlockNumber({
        onBlockNumber: (n) => {
          seen.push(n);
          if (seen.length === 3) {
            unwatch();
            resolve();
          }
        },
        onError: reject,
      });
    });
    assert.ok(seen[2] > seen[0]);
  });

  it('reads blocks by number, hash and tag', async () => {
    const latest = await client.getBlock();
    const byHash = await client.getBlock({ blockHash: latest.hash });
    assert.equal(byHash.number, latest.number);
    const parent = await client.getBlock({ blockNumber: latest.number - 1n });
    assert.equal(latest.parentHash, parent.hash);
    const finalized = await client.getBlock({ blockTag: 'finalized' });
    assert.ok(finalized.number <= latest.number + 1n);
    assert.ok(latest.baseFeePerGas >= parseGwei('1'));
  });

  it('prices transactions from the fee market', async () => {
    const fees = await client.estimateFeesPerGas();
    assert.ok(fees.maxFeePerGas > fees.maxPriorityFeePerGas);
    assert.ok((await client.estimateMaxPriorityFeePerGas()) > 0n);
    const history = await client.getFeeHistory({ blockCount: 4, rewardPercentiles: [50] });
    assert.equal(history.baseFeePerGas.length, 5);
    assert.equal(history.gasUsedRatio.length, 4);
    assert.ok((await client.getGasPrice()) > 0n);
  });
});

describe('viem: accounts and transactions', () => {
  it('reads the funded balance and nonce', async () => {
    assert.ok((await client.getBalance({ address: FUNDED })) > parseEther('1000'));
    const nonce = await client.getTransactionCount({ address: FUNDED });
    assert.equal(await client.getTransactionCount({ address: FUNDED, blockTag: 'pending' }), nonce);
  });

  it('sends an EIP-1559 transfer and waits for its receipt', async () => {
    const hash = await funded.sendTransaction({ to: userAccount.address, value: parseEther('5') });
    const receipt = await client.waitForTransactionReceipt({ hash });
    assert.equal(receipt.status, 'success');
    assert.equal(receipt.type, 'eip1559');
    const tx = await client.getTransaction({ hash });
    assert.equal(tx.type, 'eip1559');
    assert.equal(tx.chainId, CHAIN_ID);
    assert.equal(await client.getBalance({ address: userAccount.address }), parseEther('5'));
    await until('a confirmation', async () => (await client.getTransactionConfirmations({ hash })) >= 2n);
    // The same transaction by its position in the block.
    const count = await client.getBlockTransactionCount({ blockNumber: receipt.blockNumber });
    assert.equal(count, 1);
    const byPosition = await client.getTransaction({ blockNumber: receipt.blockNumber, index: 0 });
    assert.equal(byPosition.hash, hash);
    const byHashAndPosition = await client.getTransaction({ blockHash: receipt.blockHash, index: 0 });
    assert.equal(byHashAndPosition.hash, hash);
  });

  it('reports the blob base fee of a chain without blobs', async () => {
    assert.equal(await client.getBlobBaseFee(), 1n);
  });

  it('sends a legacy EIP-155 transaction', async () => {
    const hash = await user.sendTransaction({ to: FUNDED, value: 1n, type: 'legacy' });
    const receipt = await client.waitForTransactionReceipt({ hash });
    assert.equal(receipt.status, 'success');
    assert.equal(receipt.type, 'legacy');
    const tx = await client.getTransaction({ hash });
    assert.equal(tx.chainId, CHAIN_ID, 'EIP-155 signature');
  });

  it('delegates an account with an EIP-7702 authorization', async () => {
    // Delegate the user's account to the funded account's address: an
    // account without code, so calls to the user still succeed.
    const authorization = await user.signAuthorization({ contractAddress: FUNDED, executor: 'self' });
    const hash = await user.sendTransaction({
      authorizationList: [authorization],
      to: userAccount.address,
      data: '0x',
    });
    const receipt = await client.waitForTransactionReceipt({ hash });
    assert.equal(receipt.status, 'success');
    assert.equal(receipt.type, 'eip7702');
    const code = await client.getCode({ address: userAccount.address });
    assert.equal(code, `0xef0100${FUNDED.slice(2).toLowerCase()}`);
  });

  it('proves an account with eth_getProof', async () => {
    const proof = await client.getProof({ address: FUNDED, storageKeys: [] });
    assert.ok(proof.accountProof.length > 0);
    assert.ok(proof.balance > 0n);
  });
});

describe('viem: a token contract', () => {
  const { abi, bytecode } = token();
  let address;
  let deployBlock;

  before(async () => {
    const hash = await funded.deployContract({ abi, bytecode, args: [SUPPLY] });
    const receipt = await client.waitForTransactionReceipt({ hash });
    assert.equal(receipt.status, 'success');
    address = receipt.contractAddress;
    deployBlock = receipt.blockNumber;
  });

  it('reads the contract', async () => {
    assert.equal(await client.readContract({ address, abi, functionName: 'symbol' }), 'STT');
    const supply = await client.readContract({ address, abi, functionName: 'totalSupply' });
    assert.equal(supply, SUPPLY);
  });

  it('simulates, estimates and writes a transfer', async () => {
    const args = [userAccount.address, 500n];
    const { request, result } = await client.simulateContract({
      account: funded.account,
      address,
      abi,
      functionName: 'transfer',
      args,
    });
    assert.equal(result, true);
    const gas = await client.estimateContractGas({
      account: funded.account,
      address,
      abi,
      functionName: 'transfer',
      args,
    });
    assert.ok(gas > 21000n && gas < 100000n, `estimate ${gas}`);
    const hash = await funded.writeContract(request);
    const receipt = await client.waitForTransactionReceipt({ hash });
    assert.equal(receipt.status, 'success');
    assert.equal(receipt.logs.length, 1);
    const balance = await client.readContract({
      address,
      abi,
      functionName: 'balanceOf',
      args: [userAccount.address],
    });
    assert.equal(balance, 500n);
  });

  it('finds events with eth_getLogs', async () => {
    const events = await client.getContractEvents({ address, abi, eventName: 'Transfer', fromBlock: deployBlock });
    assert.equal(events.length, 2);
    assert.equal(events[1].args.value, 500n);
    const logs = await client.getLogs({
      address,
      event: abi.find((x) => x.name === 'Transfer'),
      args: { to: userAccount.address },
      fromBlock: deployBlock,
    });
    assert.equal(logs.length, 1);
  });

  it('polls a log filter and a block filter', async () => {
    const logs = await client.createContractEventFilter({ address, abi, eventName: 'Transfer' });
    const blocks = await client.createBlockFilter();
    const pending = await client.createPendingTransactionFilter();
    const hash = await funded.writeContract({
      address,
      abi,
      functionName: 'transfer',
      args: [userAccount.address, 3n],
    });
    await client.waitForTransactionReceipt({ hash });
    const changes = await client.getFilterChanges({ filter: logs });
    assert.equal(changes.length, 1);
    assert.equal(changes[0].transactionHash, hash);
    assert.equal(changes[0].args.value, 3n);
    assert.deepEqual(await client.getFilterChanges({ filter: logs }), []);
    const all = await client.getFilterLogs({ filter: logs });
    assert.equal(all.length, 1);
    const newBlocks = await client.getFilterChanges({ filter: blocks });
    assert.ok(newBlocks.length > 0);
    assert.match(newBlocks[0], /^0x[0-9a-f]{64}$/);
    const seen = await client.getFilterChanges({ filter: pending });
    assert.ok(seen.includes(hash), 'the pending filter saw the transfer');
    assert.equal(await client.uninstallFilter({ filter: logs }), true);
    assert.equal(await client.uninstallFilter({ filter: logs }), false);
    await client.uninstallFilter({ filter: blocks });
    await client.uninstallFilter({ filter: pending });
  });

  it('watches contract events', async () => {
    const event = new Promise((resolve, reject) => {
      const unwatch = client.watchContractEvent({
        address,
        abi,
        eventName: 'Transfer',
        onLogs: (logs) => {
          unwatch();
          resolve(logs[0]);
        },
        onError: reject,
      });
    });
    await new Promise((resolve) => setTimeout(resolve, 500));
    await funded.writeContract({ address, abi, functionName: 'transfer', args: [userAccount.address, 9n] });
    const log = await Promise.race([
      event,
      new Promise((_, reject) => setTimeout(() => reject(new Error('no event')), 20_000)),
    ]);
    assert.equal(log.args.value, 9n);
  });

  it('decodes a custom error', async () => {
    await assert.rejects(
      client.simulateContract({
        account: userAccount,
        address,
        abi,
        functionName: 'transfer',
        args: [FUNDED, 10n ** 30n],
      }),
      (e) => {
        const revert = revertOf(e);
        assert.equal(revert.data?.errorName, 'InsufficientBalance');
        assert.equal(revert.data.args[2], 10n ** 30n);
        return true;
      },
    );
  });

  it('decodes a revert string', async () => {
    await assert.rejects(
      client.estimateContractGas({
        account: userAccount,
        address,
        abi,
        functionName: 'transferFrom',
        args: [FUNDED, userAccount.address, 1n],
      }),
      (e) => {
        assert.equal(revertOf(e).reason, 'allowance exceeded');
        return true;
      },
    );
  });

  it('reports a reverted transaction as reverted', async () => {
    const hash = await user.writeContract({
      address,
      abi,
      functionName: 'transfer',
      args: [FUNDED, 10n ** 30n],
      gas: 100000n,
    });
    const receipt = await client.waitForTransactionReceipt({ hash });
    assert.equal(receipt.status, 'reverted');
  });
});
