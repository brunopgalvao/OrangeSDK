// Shared by the ethers and viem suites: where the node is, the funded key,
// and the token contract compiled with solc-js (the same 0.8.28 the
// Foundry half builds with).
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const solc = require('solc');

/** The node's JSON-RPC URL. */
export const RPC = process.env.SOLO_RPC ?? 'http://127.0.0.1:8545';

/** The chain id the suite's genesis sets (../genesis.json). */
export const CHAIN_ID = Number(process.env.SOLO_CHAIN_ID ?? 1337);

/** The key the genesis funds, 32 bytes of 0x01 (the README's key). */
export const FUNDED_KEY = '0x' + '01'.repeat(32);

/** Its address. */
export const FUNDED = '0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1';

/** Supply the token's constructor mints to the deployer. */
export const SUPPLY = 10n ** 24n;

let compiled;

/** The token's ABI and creation bytecode. */
export function token() {
  if (!compiled) {
    const source = readFileSync(new URL('../contracts/Token.sol', import.meta.url), 'utf8');
    const input = {
      language: 'Solidity',
      sources: { 'Token.sol': { content: source } },
      settings: {
        optimizer: { enabled: true, runs: 200 },
        evmVersion: 'prague',
        outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
      },
    };
    const output = JSON.parse(solc.compile(JSON.stringify(input)));
    const errors = (output.errors ?? []).filter((e) => e.severity === 'error');
    if (errors.length) {
      throw new Error(errors.map((e) => e.formattedMessage).join('\n'));
    }
    const contract = output.contracts['Token.sol'].Token;
    compiled = { abi: contract.abi, bytecode: '0x' + contract.evm.bytecode.object };
  }
  return compiled;
}

/** A plain JSON-RPC call, for what neither client wraps. */
export async function rpc(method, params = []) {
  const response = await fetch(RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const body = await response.json();
  if (body.error) {
    const error = new Error(`${method}: ${body.error.message}`);
    error.rpc = body.error;
    throw error;
  }
  return body.result;
}

/** Resolves once `check` returns a truthy value, polling every 200 ms. */
export async function until(what, check, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
}
