// ethers' WebSocketProvider and viem's webSocket transport against an
// OrangeSDK node: ordinary calls over the socket, and the three
// subscriptions (spec 20 §8.7).
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { Contract, ContractFactory, JsonRpcProvider, Wallet, WebSocketProvider } from 'ethers';
import { createPublicClient, defineChain, webSocket } from 'viem';
import { CHAIN_ID, FUNDED_KEY, RPC, SUPPLY, WS, token } from './common.mjs';

/** `promise`, or a failure naming `what` after 20 s. */
function within(what, promise) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`no ${what} within 20 s`)), 20_000);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/** Resolves with what `start` hands its callback first. */
function first(what, start) {
  return within(what, new Promise((resolve) => start(resolve)));
}

/** Watches announced hashes for one that is known only once it is sent. */
function hashWatch() {
  const seen = new Set();
  let wanted;
  let done;
  const found = new Promise((resolve) => {
    done = resolve;
  });
  return {
    saw(hash) {
      seen.add(hash);
      if (hash === wanted) done(hash);
    },
    want(hash) {
      wanted = hash;
      if (seen.has(hash)) done(hash);
      return within('pending hash', found);
    },
  };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 500));

// Transactions go over HTTP, as a dapp's wallet sends them; what they
// cause is watched over the socket.
const http = new JsonRpcProvider(RPC, undefined, { cacheTimeout: -1 });
const funded = new Wallet(FUNDED_KEY, http);
const recipient = Wallet.createRandom().address;
let erc20;

before(async () => {
  const { abi, bytecode } = token();
  erc20 = await new ContractFactory(abi, bytecode, funded).deploy(SUPPLY);
  await erc20.waitForDeployment();
});

after(() => http.destroy());

describe('ethers: WebSocketProvider', () => {
  const provider = new WebSocketProvider(WS);
  after(() => provider.destroy());

  it('serves ordinary calls over the socket', async () => {
    assert.equal((await provider.getNetwork()).chainId, BigInt(CHAIN_ID));
    assert.ok((await provider.getBlockNumber()) > 0);
    assert.ok((await provider.getBalance(funded.address)) > 0n);
  });

  it('announces new heads', async () => {
    const head = await first('block', (resolve) => provider.once('block', resolve));
    assert.ok(head > 0);
  });

  it('announces a contract event through a logs subscription', async () => {
    const watched = new Contract(await erc20.getAddress(), token().abi, provider);
    const seen = first('Transfer', (resolve) =>
      watched.once('Transfer', (from, to, value) => resolve({ from, to, value })),
    );
    // The subscription is made before the transfer is sent.
    await settle();
    await (await erc20.transfer(recipient, 11n)).wait();
    const event = await seen;
    assert.equal(event.to, recipient);
    assert.equal(event.value, 11n);
  });

  it('announces pending transactions', async () => {
    const watch = hashWatch();
    await provider.on('pending', (hash) => watch.saw(hash));
    await settle();
    const tx = await funded.sendTransaction({ to: recipient, value: 1n });
    assert.equal(await watch.want(tx.hash), tx.hash);
    await provider.off('pending');
    await tx.wait();
  });
});

describe('viem: webSocket transport', () => {
  const chain = defineChain({
    id: CHAIN_ID,
    name: 'OrangeSDK devnet',
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [RPC], webSocket: [WS] } },
  });
  const client = createPublicClient({ chain, transport: webSocket(WS) });
  after(async () => (await client.transport.getRpcClient()).close());

  it('serves ordinary calls over the socket', async () => {
    assert.equal(await client.getChainId(), CHAIN_ID);
    assert.ok((await client.getBlockNumber()) > 0n);
  });

  it('watches blocks through newHeads', async () => {
    let unwatch;
    const block = await first('block', (resolve) => {
      unwatch = client.watchBlocks({ onBlock: resolve });
    });
    unwatch();
    assert.ok(block.number > 0n);
    assert.match(block.hash, /^0x[0-9a-f]{64}$/);
  });

  it('watches a contract event through a logs subscription', async () => {
    let unwatch;
    const seen = first('Transfer', (resolve) => {
      unwatch = client.watchContractEvent({
        address: erc20.target,
        abi: token().abi,
        eventName: 'Transfer',
        onLogs: (logs) => resolve(logs[0]),
      });
    });
    await settle();
    await (await erc20.transfer(recipient, 13n)).wait();
    const log = await seen;
    unwatch();
    assert.equal(log.args.to, recipient);
    assert.equal(log.args.value, 13n);
  });

  it('watches pending transactions', async () => {
    const watch = hashWatch();
    const unwatch = client.watchPendingTransactions({
      onTransactions: (hashes) => hashes.forEach((hash) => watch.saw(hash)),
    });
    await settle();
    const tx = await funded.sendTransaction({ to: recipient, value: 1n });
    assert.equal(await watch.want(tx.hash), tx.hash);
    unwatch();
    await tx.wait();
  });
});
