// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_RAWTRANSACTION_UTIL_H
#define BITCOIN_RPC_RAWTRANSACTION_UTIL_H

#include <map>
#include <string>
#include <optional>
#include <node/blockstorage.h>
#include <node/transaction.h>
using node::GetTransaction;

struct bilingual_str;
class FillableSigningProvider;
class UniValue;
struct CMutableTransaction;
class Coin;
class COutPoint;
class SigningProvider;

enum OutputScriptType { CustomOutput=1, P2PK, P2SH, P2PKH, P2WSH, P2WPKH, P2TR};
enum InputScriptType { CustomInput=0, Legacy, Segwit, Taproot };
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

/** Create a transaction from univalue parameters */
CMutableTransaction ConstructTransaction(const UniValue& inputs_in, const UniValue& outputs_in, const UniValue& locktime, std::optional<bool> rbf);

long int binary_to_long_int(std::string binary);

int32_t binary_to_int(std::string binary);

std::string binary_to_hex(std::string binary);

std::string int_to_hex(int32_t byte);

std::string hex_to_binary(std::string hex);

std::vector<unsigned char> to_varint(long int intager);

long int from_varint(std::vector<unsigned char>& transaction_bytes, int& index, std::string& result);

InputScriptType get_input_type(CTxIn input, std::vector<unsigned char>& vchRet, std::string& result);

//	std::vector<unsigned char> script_to_bytes(CScript script);

int get_first_push_bytes(std::vector<unsigned char>& data, CScript script);

OutputScriptType get_output_type(CScript script_pubkey, std::vector<unsigned char>& vchRet, std::string& result);

std::vector<unsigned char> hex_to_bytes(std::string hex);



#endif // BITCOIN_RPC_RAWTRANSACTION_UTIL_H
