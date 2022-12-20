// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_RAWTRANSACTION_UTIL_H
#define BITCOIN_RPC_RAWTRANSACTION_UTIL_H

#include <map>
#include <string>
#include <optional>
#include <node/blockstorage.h>

struct bilingual_str;
class FillableSigningProvider;
class UniValue;
struct CMutableTransaction;
class Coin;
class COutPoint;
class SigningProvider;

/**
 * Sign a transaction with the given keystore and previous transactions
 *
 * @param  mtx           The transaction to-be-signed
 * @param  keystore      Temporary keystore containing signing keys
 * @param  coins         Map of unspent outputs
 * @param  hashType      The signature hash type
 * @param result         JSON object where signed transaction results accumulate
 */
void SignTransaction(CMutableTransaction& mtx, const SigningProvider* keystore, const std::map<COutPoint, Coin>& coins, const UniValue& hashType, UniValue& result);
void SignTransactionResultToJSON(CMutableTransaction& mtx, bool complete, const std::map<COutPoint, Coin>& coins, const std::map<int, bilingual_str>& input_errors, UniValue& result);

/**
  * Parse a prevtxs UniValue array and get the map of coins from it
  *
  * @param  prevTxsUnival Array of previous txns outputs that tx depends on but may not yet be in the block chain
  * @param  keystore      A pointer to the temporary keystore if there is one
  * @param  coins         Map of unspent outputs - coins in mempool and current chain UTXO set, may be extended by previous txns outputs after call
  */
void ParsePrevouts(const UniValue& prevTxsUnival, FillableSigningProvider* keystore, std::map<COutPoint, Coin>& coins);

/** Create a transaction from univalue parameters */
CMutableTransaction ConstructTransaction(const UniValue& inputs_in, const UniValue& outputs_in, const UniValue& locktime, std::optional<bool> rbf);

/**
 * Compress a Transaction to a hex encoded string
 *
 * @param  mtx           The transaction to be compressed
 * @param  result        The compressed, serilized, hex encoded transaction
 */
void CompressRawTransaction(CMutableTransaction& mtx, Chainstate& active_chainstate, std::string& transaction_result, std::string& result);

/**
 * Decompress a compressed transaction encoded as a hex string
 *
 * @param  mtx           The compressed, serilized, hex encoded transaction
 * @param  result        The decompressed transaction
 */
void DecompressRawTransaction(std::string& hex, Chainstate& active_chainstate, CMutableTransaction& transaction_result, std::string& result);

#endif // BITCOIN_RPC_RAWTRANSACTION_UTIL_H
