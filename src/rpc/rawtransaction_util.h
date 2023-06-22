// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_RAWTRANSACTION_UTIL_H
#define BITCOIN_RPC_RAWTRANSACTION_UTIL_H

#include <map>
#include <string>
#include <optional>
#include <node/blockstorage.h>
#include <node/transaction.h>
#include <secp256k1.h>
using node::GetTransaction;

struct bilingual_str;
class FillableSigningProvider;
class UniValue;
struct CMutableTransaction;
class Coin;
class COutPoint;
class SigningProvider;

const uint32_t SEQUENCE_F0 = 0xFFFFFFF0;
const uint32_t SEQUENCE_FE = 0xFFFFFFFE;
const uint32_t SEQUENCE_FF = 0xFFFFFFFF;

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


/** Normalize univalue-represented inputs and add them to the transaction */
void AddInputs(CMutableTransaction& rawTx, const UniValue& inputs_in, bool rbf);

/** Normalize univalue-represented outputs and add them to the transaction */
void AddOutputs(CMutableTransaction& rawTx, const UniValue& outputs_in);

/** Create a transaction from univalue parameters */
CMutableTransaction ConstructTransaction(const UniValue& inputs_in, const UniValue& outputs_in, const UniValue& locktime, std::optional<bool> rbf);

////int binary_to_int(std::string binary);

////std::string binary_to_hex(std::string binary);

////std::string int_to_hex(int64_t byte);

////std::string hex_to_binary(std::string hex);

////std::vector<unsigned char> to_varint(uint64_t value);

////void checkSize(int size, int index);

////uint64_t from_varint(std::vector<unsigned char>& transaction_bytes, int& index);

////bool get_input_type(secp256k1_context* ctx, CTxIn input, CTransactionRef tx, std::vector<unsigned char>& vchRet);

////OutputScriptType get_output_type(CScript script_pubkey, std::vector<unsigned char>& vchRet);

////int get_first_push_bytes(std::vector<unsigned char>& data, CScript script);

////std::vector<unsigned char> hex_to_bytes(std::string hex);



#endif // BITCOIN_RPC_RAWTRANSACTION_UTIL_H
