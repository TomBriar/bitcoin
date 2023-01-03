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

int32_t char_to_int(char hex_byte);

std::string bytes_to_hex(std::vector<unsigned char> bytes, int trim = 0);

int32_t hex_to_int(std::string hex);

unsigned char hex_to_char(std::string hex);

std::vector<unsigned char> hex_to_bytes(std::string hex);

std::string hex_to_binary(std::string hex);

std::string to_varint(long int intager);

std::tuple<long int, long int> from_varint(std::string hex);

std::tuple<int, std::vector<unsigned char>> test_ecdsa_sig(std::vector<unsigned char> vchRet, std::string& result);

std::tuple<std::string, std::vector<unsigned char>> get_input_type(CTxIn input, std::string& result);

std::string serialize_script(CScript script);

int get_first_push_bytes(std::vector<unsigned char>& data, CScript script);

std::tuple<std::string, std::vector<unsigned char>> get_output_type(CTxOut output, std::string& result);





#endif // BITCOIN_RPC_RAWTRANSACTION_UTIL_H
