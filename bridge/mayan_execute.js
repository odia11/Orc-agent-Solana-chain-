#!/usr/bin/env node
'use strict';

/*
 * bridge/mayan_execute.js
 *
 * Executes a Solana<->BSC bridge swap via Mayan Finance's official SDK.
 *
 * Usage:
 *   node mayan_execute.js <action> <sourceChain> <destChain> <tokenIn> <tokenOut> <amount>
 *
 * WALLET_PRIVATE_KEY (env) must be in the format native to sourceChain --
 * these are two different key systems, not interchangeable:
 *   sourceChain === 'solana' -> base58-encoded Solana secret key
 *   sourceChain === 'bsc'    -> 0x-prefixed EVM private key (32 bytes hex)
 * The caller is responsible for supplying the key that matches sourceChain --
 * this script only validates the format, it can't tell if the wrong key for
 * the right chain was passed in.
 *
 * On success: {"tx_hash": "...", "order_hash": "..."} to stdout, exit 0.
 * On any failure: {"error": "..."} to stderr, exit 1. Never writes
 * WALLET_PRIVATE_KEY or any derived signer material to stdout/stderr.
 *
 * ── IMPORTANT: unverified against the live SDK ──
 * This has not been run end-to-end. @mayanfinance/swap-sdk is not installed
 * in this repo (no package.json exists yet), so the function names/
 * signatures below (fetchQuote, swapFromSolana, swapFromEvm) are written
 * from the SDK's documented shape, not confirmed against an installed
 * copy's actual exports/types for whatever version ends up pinned. Treat
 * this as a first draft: run it against a trivial real amount (or Mayan's
 * testnet if they offer one) and fix whatever the SDK actually expects
 * before wiring it into any endpoint a real user can reach.
 */

const { fetchQuote, swapFromSolana, swapFromEvm } = require('@mayanfinance/swap-sdk');
const { Connection, Keypair } = require('@solana/web3.js');
const { ethers } = require('ethers');
const bs58 = require('bs58');

function fail(msg) {
  process.stderr.write(JSON.stringify({ error: String(msg) }) + '\n');
  process.exit(1);
}

function succeed(txHash, orderHash) {
  process.stdout.write(JSON.stringify({ tx_hash: txHash, order_hash: orderHash || null }) + '\n');
  process.exit(0);
}

async function main() {
  const [, , action, sourceChain, destChain, tokenIn, tokenOut, amountStr] = process.argv;

  if (!action || !sourceChain || !destChain || !tokenIn || !tokenOut || !amountStr) {
    fail('Usage: mayan_execute.js <action> <sourceChain> <destChain> <tokenIn> <tokenOut> <amount>');
    return;
  }
  if (sourceChain !== 'solana' && sourceChain !== 'bsc') {
    fail(`Unsupported sourceChain: ${sourceChain} (expected 'solana' or 'bsc')`);
    return;
  }
  const amount = parseFloat(amountStr);
  if (!(amount > 0)) {
    fail(`Invalid amount: ${amountStr}`);
    return;
  }

  const privateKey = process.env.WALLET_PRIVATE_KEY;
  if (!privateKey) {
    fail('WALLET_PRIVATE_KEY not set');
    return;
  }

  // ── Step 1: quote (same call shape as get_mayan_bridge_quote() in
  // dashboard.py -- kept here too since execution needs the live quote
  // object itself, not just its displayed numbers) ──
  let quotes;
  try {
    quotes = await fetchQuote({
      amount,
      fromToken: tokenIn,
      fromChain: sourceChain,
      toToken: tokenOut,
      toChain: destChain,
      slippageBps: 'auto',
    });
  } catch (e) {
    fail(`Quote fetch failed: ${e && e.message ? e.message : e}`);
    return;
  }
  if (!quotes || !quotes.length) {
    fail('No bridge route found for this pair/amount');
    return;
  }
  const quote = quotes[0]; // best-return quote, matches get_mayan_bridge_quote()'s ordering

  // ── Step 2: sign + broadcast on the source chain ──
  try {
    if (sourceChain === 'solana') {
      let secretKeyBytes;
      try {
        secretKeyBytes = bs58.decode(privateKey);
      } catch (e) {
        fail('WALLET_PRIVATE_KEY is not valid base58 (expected a Solana secret key for sourceChain=solana)');
        return;
      }
      const keypair = Keypair.fromSecretKey(secretKeyBytes);
      const connection = new Connection(
        process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com',
        'confirmed'
      );
      const signSolanaTransaction = async (tx) => {
        tx.sign([keypair]);
        return tx;
      };

      const result = await swapFromSolana(
        quote,
        keypair.publicKey.toString(),
        keypair.publicKey.toString(),
        [],
        signSolanaTransaction,
        connection
      );
      const txHash = result && (result.signature || result.txHash || result.hash);
      if (!txHash) {
        fail(`swapFromSolana returned no transaction hash: ${JSON.stringify(result)}`);
        return;
      }
      succeed(txHash, quote.orderHash || (result && result.orderHash) || null);
      return;

    } else {
      // sourceChain === 'bsc'
      if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) {
        fail('WALLET_PRIVATE_KEY is not a valid EVM private key (expected 0x + 64 hex chars for sourceChain=bsc)');
        return;
      }
      const rpcUrl = process.env.BSC_RPC_URL || 'https://bsc-dataseed.binance.org/';
      const provider = new ethers.JsonRpcProvider(rpcUrl);
      const signer = new ethers.Wallet(privateKey, provider);

      const result = await swapFromEvm(
        quote,
        signer.address,
        signer.address,
        [],
        signer,
        null,
        {}
      );
      const txHash = result && (result.hash || result.txHash);
      if (!txHash) {
        fail(`swapFromEvm returned no transaction hash: ${JSON.stringify(result)}`);
        return;
      }
      succeed(txHash, quote.orderHash || (result && result.orderHash) || null);
      return;
    }
  } catch (e) {
    fail(`Swap execution failed: ${e && e.message ? e.message : e}`);
  }
}

main().catch((e) => fail(`Unhandled error: ${e && e.message ? e.message : e}`));
