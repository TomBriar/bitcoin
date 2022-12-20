// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/rawtransaction_util.h>

#include <coins.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <key_io.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <rpc/request.h>
#include <rpc/util.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/rbf.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <string>
#include <bitset>
#include <cmath>
#include <iomanip>
#include <vector>
#include <prevector.h>
#include <inttypes.h>
#include <assert.h>
#include <chain.h>
#include <validation.h>

#include <script/sign.h>
// #include <node/transaction.h>
// #include <node/transaction.cpp>
#include <node/blockstorage.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>


#include <base58.h>
#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <index/txindex.h>
#include <key_io.h>
#include <node/blockstorage.h>
#include <node/coin.h>
#include <node/context.h>
#include <node/psbt.h>
#include <node/transaction.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <rpc/rawtransaction_util.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <uint256.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/vector.h>
#include <validation.h>
#include <validationinterface.h>

#include <numeric>
#include <stdint.h>

#include <univalue.h>


using node::NodeContext;
using node::ReadBlockFromDisk;
using node::GetTransaction;
using node::BlockManager;

CMutableTransaction ConstructTransaction(const UniValue& inputs_in, const UniValue& outputs_in, const UniValue& locktime, std::optional<bool> rbf)
{
    if (outputs_in.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, output argument must be non-null");
    }

    UniValue inputs;
    if (inputs_in.isNull()) {
        inputs = UniValue::VARR;
    } else {
        inputs = inputs_in.get_array();
    }

    const bool outputs_is_obj = outputs_in.isObject();
    UniValue outputs = outputs_is_obj ? outputs_in.get_obj() : outputs_in.get_array();

    CMutableTransaction rawTx;

    if (!locktime.isNull()) {
        int64_t nLockTime = locktime.getInt<int64_t>();
        if (nLockTime < 0 || nLockTime > LOCKTIME_MAX)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, locktime out of range");
        rawTx.nLockTime = nLockTime;
    }

    for (unsigned int idx = 0; idx < inputs.size(); idx++) {
        const UniValue& input = inputs[idx];
        const UniValue& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");

        const UniValue& vout_v = find_value(o, "vout");
        if (!vout_v.isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.getInt<int>();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout cannot be negative");

        uint32_t nSequence;

        if (rbf.value_or(true)) {
            nSequence = MAX_BIP125_RBF_SEQUENCE; /* CTxIn::SEQUENCE_FINAL - 2 */
        } else if (rawTx.nLockTime) {
            nSequence = CTxIn::MAX_SEQUENCE_NONFINAL; /* CTxIn::SEQUENCE_FINAL - 1 */
        } else {
            nSequence = CTxIn::SEQUENCE_FINAL;
        }

        // set the sequence number if passed in the parameters object
        const UniValue& sequenceObj = find_value(o, "sequence");
        if (sequenceObj.isNum()) {
            int64_t seqNr64 = sequenceObj.getInt<int64_t>();
            if (seqNr64 < 0 || seqNr64 > CTxIn::SEQUENCE_FINAL) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, sequence number is out of range");
            } else {
                nSequence = (uint32_t)seqNr64;
            }
        }

        CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);

        rawTx.vin.push_back(in);
    }

    if (!outputs_is_obj) {
        // Translate array of key-value pairs into dict
        UniValue outputs_dict = UniValue(UniValue::VOBJ);
        for (size_t i = 0; i < outputs.size(); ++i) {
            const UniValue& output = outputs[i];
            if (!output.isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, key-value pair not an object as expected");
            }
            if (output.size() != 1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, key-value pair must contain exactly one key");
            }
            outputs_dict.pushKVs(output);
        }
        outputs = std::move(outputs_dict);
    }

    // Duplicate checking
    std::set<CTxDestination> destinations;
    bool has_data{false};

    for (const std::string& name_ : outputs.getKeys()) {
        if (name_ == "data") {
            if (has_data) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, duplicate key: data");
            }
            has_data = true;
            std::vector<unsigned char> data = ParseHexV(outputs[name_].getValStr(), "Data");

            CTxOut out(0, CScript() << OP_RETURN << data);
            rawTx.vout.push_back(out);
        } else {
            CTxDestination destination = DecodeDestination(name_);
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Bitcoin address: ") + name_);
            }

            if (!destinations.insert(destination).second) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + name_);
            }

            CScript scriptPubKey = GetScriptForDestination(destination);
            CAmount nAmount = AmountFromValue(outputs[name_]);

            CTxOut out(nAmount, scriptPubKey);
            rawTx.vout.push_back(out);
        }
    }

    if (rbf.has_value() && rbf.value() && rawTx.vin.size() > 0 && !SignalsOptInRBF(CTransaction(rawTx))) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter combination: Sequence number(s) contradict replaceable option");
    }

    return rawTx;
}

/** Pushes a JSON object for script verification or signing errors to vErrorsRet. */
static void TxInErrorToJSON(const CTxIn& txin, UniValue& vErrorsRet, const std::string& strMessage)
{
    UniValue entry(UniValue::VOBJ);
    entry.pushKV("txid", txin.prevout.hash.ToString());
    entry.pushKV("vout", (uint64_t)txin.prevout.n);
    UniValue witness(UniValue::VARR);
    for (unsigned int i = 0; i < txin.scriptWitness.stack.size(); i++) {
        witness.push_back(HexStr(txin.scriptWitness.stack[i]));
    }
    entry.pushKV("witness", witness);
    entry.pushKV("scriptSig", HexStr(txin.scriptSig));
    entry.pushKV("sequence", (uint64_t)txin.nSequence);
    entry.pushKV("error", strMessage);
    vErrorsRet.push_back(entry);
}

void ParsePrevouts(const UniValue& prevTxsUnival, FillableSigningProvider* keystore, std::map<COutPoint, Coin>& coins)
{
    if (!prevTxsUnival.isNull()) {
        const UniValue& prevTxs = prevTxsUnival.get_array();
        for (unsigned int idx = 0; idx < prevTxs.size(); ++idx) {
            const UniValue& p = prevTxs[idx];
            if (!p.isObject()) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");
            }

            const UniValue& prevOut = p.get_obj();

            RPCTypeCheckObj(prevOut,
                {
                    {"txid", UniValueType(UniValue::VSTR)},
                    {"vout", UniValueType(UniValue::VNUM)},
                    {"scriptPubKey", UniValueType(UniValue::VSTR)},
                });

            uint256 txid = ParseHashO(prevOut, "txid");

            int nOut = find_value(prevOut, "vout").getInt<int>();
            if (nOut < 0) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout cannot be negative");
            }

            COutPoint out(txid, nOut);
            std::vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            {
                auto coin = coins.find(out);
                if (coin != coins.end() && !coin->second.IsSpent() && coin->second.out.scriptPubKey != scriptPubKey) {
                    std::string err("Previous output scriptPubKey mismatch:\n");
                    err = err + ScriptToAsmStr(coin->second.out.scriptPubKey) + "\nvs:\n"+
                        ScriptToAsmStr(scriptPubKey);
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
                }
                Coin newcoin;
                newcoin.out.scriptPubKey = scriptPubKey;
                newcoin.out.nValue = MAX_MONEY;
                if (prevOut.exists("amount")) {
                    newcoin.out.nValue = AmountFromValue(find_value(prevOut, "amount"));
                }
                newcoin.nHeight = 1;
                coins[out] = std::move(newcoin);
            }

            // if redeemScript and private keys were given, add redeemScript to the keystore so it can be signed
            const bool is_p2sh = scriptPubKey.IsPayToScriptHash();
            const bool is_p2wsh = scriptPubKey.IsPayToWitnessScriptHash();
            if (keystore && (is_p2sh || is_p2wsh)) {
                RPCTypeCheckObj(prevOut,
                    {
                        {"redeemScript", UniValueType(UniValue::VSTR)},
                        {"witnessScript", UniValueType(UniValue::VSTR)},
                    }, true);
                UniValue rs = find_value(prevOut, "redeemScript");
                UniValue ws = find_value(prevOut, "witnessScript");
                if (rs.isNull() && ws.isNull()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing redeemScript/witnessScript");
                }

                // work from witnessScript when possible
                std::vector<unsigned char> scriptData(!ws.isNull() ? ParseHexV(ws, "witnessScript") : ParseHexV(rs, "redeemScript"));
                CScript script(scriptData.begin(), scriptData.end());
                keystore->AddCScript(script);
                // Automatically also add the P2WSH wrapped version of the script (to deal with P2SH-P2WSH).
                // This is done for redeemScript only for compatibility, it is encouraged to use the explicit witnessScript field instead.
                CScript witness_output_script{GetScriptForDestination(WitnessV0ScriptHash(script))};
                keystore->AddCScript(witness_output_script);

                if (!ws.isNull() && !rs.isNull()) {
                    // if both witnessScript and redeemScript are provided,
                    // they should either be the same (for backwards compat),
                    // or the redeemScript should be the encoded form of
                    // the witnessScript (ie, for p2sh-p2wsh)
                    if (ws.get_str() != rs.get_str()) {
                        std::vector<unsigned char> redeemScriptData(ParseHexV(rs, "redeemScript"));
                        CScript redeemScript(redeemScriptData.begin(), redeemScriptData.end());
                        if (redeemScript != witness_output_script) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "redeemScript does not correspond to witnessScript");
                        }
                    }
                }

                if (is_p2sh) {
                    const CTxDestination p2sh{ScriptHash(script)};
                    const CTxDestination p2sh_p2wsh{ScriptHash(witness_output_script)};
                    if (scriptPubKey == GetScriptForDestination(p2sh)) {
                        // traditional p2sh; arguably an error if
                        // we got here with rs.IsNull(), because
                        // that means the p2sh script was specified
                        // via witnessScript param, but for now
                        // we'll just quietly accept it
                    } else if (scriptPubKey == GetScriptForDestination(p2sh_p2wsh)) {
                        // p2wsh encoded as p2sh; ideally the witness
                        // script was specified in the witnessScript
                        // param, but also support specifying it via
                        // redeemScript param for backwards compat
                        // (in which case ws.IsNull() == true)
                    } else {
                        // otherwise, can't generate scriptPubKey from
                        // either script, so we got unusable parameters
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "redeemScript/witnessScript does not match scriptPubKey");
                    }
                } else if (is_p2wsh) {
                    // plain p2wsh; could throw an error if script
                    // was specified by redeemScript rather than
                    // witnessScript (ie, ws.IsNull() == true), but
                    // accept it for backwards compat
                    const CTxDestination p2wsh{WitnessV0ScriptHash(script)};
                    if (scriptPubKey != GetScriptForDestination(p2wsh)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "redeemScript/witnessScript does not match scriptPubKey");
                    }
                }
            }
        }
    }
}

void SignTransaction(CMutableTransaction& mtx, const SigningProvider* keystore, const std::map<COutPoint, Coin>& coins, const UniValue& hashType, UniValue& result)
{
    int nHashType = ParseSighashString(hashType);

    // Script verification errors
    std::map<int, bilingual_str> input_errors;

    bool complete = SignTransaction(mtx, keystore, coins, nHashType, input_errors);
    SignTransactionResultToJSON(mtx, complete, coins, input_errors, result);
}


void SignTransactionResultToJSON(CMutableTransaction& mtx, bool complete, const std::map<COutPoint, Coin>& coins, const std::map<int, bilingual_str>& input_errors, UniValue& result)
{
    // Make errors UniValue
    UniValue vErrors(UniValue::VARR);
    for (const auto& err_pair : input_errors) {
        if (err_pair.second.original == "Missing amount") {
            // This particular error needs to be an exception for some reason
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing amount for %s", coins.at(mtx.vin.at(err_pair.first).prevout).out.ToString()));
        }
        TxInErrorToJSON(mtx.vin.at(err_pair.first), vErrors, err_pair.second.original);
    }

    result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    result.pushKV("complete", complete);
    if (!vErrors.empty()) {
        if (result.exists("errors")) {
            vErrors.push_backV(result["errors"].getValues());
        }
        result.pushKV("errors", vErrors);
    }
}
static int32_t binary_to_int(std::string binary)
{
    int i_byte = 0;
    int length = binary.length();
    for (int x = 0; x < length; x++) {
        if (binary.substr(x, 1) == "1") {
            i_byte += pow(2, ((length-1)-x));
        } 
    }
    return i_byte;
}

static std::string binary_to_hex(std::string binary)
{
    std::string hex, temphex;
    int byte, length;

    length = binary.length();
    assert(length%8 == 0);
    for (int i = 0; i < (length / 8); i++) {
        byte = binary_to_int(binary.substr(i*8, 8));
        std::stringstream stream;
        stream << std::hex << byte;
        temphex = stream.str();
        if (temphex.length() == 1) {
            temphex = "0"+temphex;
        } 
        hex += temphex;
    }
    return hex;
}

static std::string int_to_hex(int32_t byte)
{
    std::string hex;
    std::stringstream stream;
    stream << std::hex << byte;
    hex = stream.str();
    if (hex.length() % 2 == 1) {
        hex = "0"+hex;
    }
    return hex;
}

static int32_t char_to_int(char hex_byte) 
{
    switch(hex_byte)
        {
            case '0':   return 0;
            case '1':   return 1;
            case '2':   return 2;
            case '3':   return 3;
            case '4':   return 4;
            case '5':   return 5;
            case '6':   return 6;
            case '7':   return 7;
            case '8':   return 8;
            case '9':   return 9;
            case 'a':   return 10;
            case 'A':   return 10;
            case 'b':   return 11;
            case 'B':   return 11;
            case 'c':   return 12;
            case 'C':   return 12;
            case 'd':   return 13;
            case 'D':   return 13;
            case 'e':   return 14;
            case 'E':   return 14;
            case 'f':   return 15;
            case 'F':   return 15;
        }
    exit(1);
}

static std::string bytes_to_hex(std::vector<unsigned char> bytes) {
    std::string r;
    int index, length, byte;
    length = bytes.size();
    for (index = 0; index < length; index++) {
        byte = bytes.at(index);
        r += int_to_hex(byte);
    }
    return r;
}

// static unsigned char int_to_char(int32_t intager)
// {
//     unsigned char r;

//     // unsigned char ch = static_cast<unsigned char>(intager);
//     r << intager; 
//     return r; 
// }

static int32_t hex_to_int(std::string hex)
{
    int byte; 
    int r = 0;
    int length = hex.length();
    for (int i = 0; i < length; i++) {
        byte = char_to_int(hex.substr(i, 1)[0]);
        r += pow(16, (length-1)-i)*byte;
    }
    return r;
}

static unsigned char hex_to_char(std::string hex)
{
    int intager = hex_to_int(hex);
    unsigned char r = intager;
    return r; 
}

static std::vector<unsigned char> hex_to_bytes(std::string hex) {
    int index, length;
    unsigned char byte;
    std::vector<unsigned char> r;
    length = hex.length() / 2;
    for (index = 0; index < length; index++) {
        byte = hex_to_char(hex.substr(index*2, 2));
        r.push_back(byte);
    }
    return r;
}



static std::string hex_to_binary(std::string hex)
{
    assert(hex.length() == 2);
    int byte = hex_to_int(hex);
    return std::bitset<8>(byte).to_string();
}

static std::string to_varint(int32_t intager)
{
    int i, varlen, padding, index;
    float fint;
    std::string binary, r, hex;
    index = 0;
    binary = std::bitset<32>(intager).to_string();
    binary.erase(0, binary.find_first_not_of('0'));
    if (binary.length() == 0) {
        return "00";
    }

    fint = binary.length();
    fint = fint / 7;
    varlen = ceil(fint);
    padding = (7*varlen)-binary.length();
    if (varlen > 1) {
        r += "1";
        for (i = 0; i < padding; i++) {
            r += "0";
        }
        r += binary.substr(0, (7-padding));
        index += 7-padding;
        for (i = 1; i < varlen; i++) {
            if (i+1 == varlen) {
                r += "0";
            } else {
                r += "1";
            }
            r += binary.substr(index, 7);
            index += 7;
        }
    } else {
        r += "0";
        for (i = 0; i < padding; i++) {
            r += "0";
        }
        r += binary;
    }
    hex = binary_to_hex(r);
    return hex;
}


static std::tuple<int32_t, int32_t> from_varint(std::string hex) 
{
    int byte;
    std::string hex_byte, binary, r;
    int index = 0;
    bool end = false;
    for (; ;) {
        hex_byte = hex.substr(index, 2);
        index += 2;
        byte = hex_to_int(hex_byte);
        binary = std::bitset<8>(byte).to_string();
        if (binary.substr(0, 1) == "0") {
            end = true;
        }
        r += binary.substr(1, 7);
        if (end) {
            break;
        }
    }
    return std::make_tuple(binary_to_int(r), index);
}

static std::tuple<int, std::vector<unsigned char>> test_ecdsa_sig(std::vector<unsigned char> vchRet, std::string& result)
{
    secp256k1_ecdsa_signature sig;
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char hash_type;
    int r, length;
    
    result += "test = "+bytes_to_hex(vchRet)+"\n";
    hash_type = vchRet.back();
    result += "vchRet.size() = "+std::to_string(vchRet.size())+"\n";
    length = vchRet.size()-1;
    r = secp256k1_ecdsa_signature_parse_der(ctx, &sig, &vchRet[0], length);
    result += "Witness ECDSA Sig parsed = "+std::to_string(r)+"\n";
    if (r) {
        r = secp256k1_ecdsa_signature_serialize_compact(ctx, &vchRet[0], &sig);
        result += "Witness ECDSA Sig Compressed = "+std::to_string(r)+"\n";
        if (r) {
            r = secp256k1_ecdsa_signature_parse_compact(ctx, &sig, &vchRet[0]);
            result += "Re deserilize = "+std::to_string(r)+"\n";
            vchRet[64] = hash_type;
            return std::make_tuple(1, vchRet);
        }
    }
    return std::make_tuple(0, vchRet);
}

/* Get Input Type 
    "00": Custom Script
    "01": Legacy Script
    "10": Segwit Script
    "11": Taproot Script
*/
static std::tuple<std::string, std::vector<unsigned char>> get_input_type(CTxIn input, std::string& result)
{
    std::tuple<int, std::vector<unsigned char>> test_ecdsa_result;
    std::vector<unsigned char> vchRet;
    Consensus::Params consensusParams;
    opcodetype opcodeRet;
    uint256 block_hash;
    int length;
    bool r;
    std::string hex;

    CTransactionRef tx = GetTransaction(NULL, NULL, input.prevout.hash, consensusParams, block_hash);
    CScript scriptPubKey = (*tx).vout.at(input.prevout.n).scriptPubKey;

    /* P2SH and P2WSH are uncompressable */
    if (scriptPubKey.IsPayToScriptHash() || scriptPubKey.IsPayToWitnessScriptHash()) {
        result += "get_input_type = P2SH|P2PWSH";
        return std::make_tuple("00", vchRet);
    }

    if (!input.scriptWitness.IsNull()) {
        length = input.scriptWitness.stack.size();
        if (length == 1 && input.scriptWitness.stack.at(0).size() == 65) {
            /* If the Witness has only has a single entry and is a Schnorr Sginature then Input Type is Taproot */
            result += "TAPROOT\n";
            return std::make_tuple("11", input.scriptWitness.stack.at(0));
        } else if (length == 2) {
            /* If the Witness has two entries and the first is an ECDSA Sginature then Input Type is Segwit */
            vchRet = input.scriptWitness.stack.at(0);
            test_ecdsa_result = test_ecdsa_sig(vchRet, result);
            r = std::get<0>(test_ecdsa_result);
            if (r) {
                vchRet = std::get<1>(test_ecdsa_result);
                return std::make_tuple("10", vchRet);
            }
        }
        /* Witness Can Only be ECDSA or SCHNORR signature, Custom Otherwise */
        return std::make_tuple("00", vchRet);
    } else {
        /* If ScriptSig contains an ECDSA Signature then Input Type is Legacy. */
        CScriptBase::const_iterator pc = input.scriptSig.begin();
        if (!input.scriptSig.GetOp(pc, opcodeRet, vchRet)) {
            return std::make_tuple("00", vchRet);
        };
       
        test_ecdsa_result = test_ecdsa_sig(vchRet, result);
        r = std::get<0>(test_ecdsa_result);
        if (r) {
            vchRet = std::get<1>(test_ecdsa_result);
            return std::make_tuple("01", vchRet);
        }
    }

    return std::make_tuple("00", vchRet);
}


static std::string serialize_script(CScript script) 
{
    std::vector<unsigned char> vchRet;
    opcodetype opcodeRet;
    std::string hex;
    int byte;

    CScriptBase::const_iterator pc = script.begin();
    while (pc < script.end()) 
    {   
        script.GetOp(pc, opcodeRet, vchRet);
        byte = opcodeRet;
        hex += int_to_hex(byte);
        if (!vchRet.empty()) {
            hex += bytes_to_hex(vchRet);
        }
    }
    return hex;
}

// TODO return 0 or 1 based on success
static int get_first_push_bytes(std::vector<unsigned char>& data, CScript script) 
{
    std::vector<unsigned char> vchRet;
    opcodetype opcodeRet;
    int byte;

    CScriptBase::const_iterator pc = script.begin();
    while (pc < script.end()) 
    {   
        script.GetOp(pc, opcodeRet, vchRet);
        byte = opcodeRet;
        if (byte == 0x20) {
            data = vchRet;
            return 1;
        } 
    }
    return 0;
}

/* Get Output Type 
    "001": P2PK.
    "010": P2SH.
    "011": P2PKH.
    "100": V0_P2WSH.
    "101": V0_P2WPKH.
    "110": P2TR.
    "111": Custom Script.
*/
static std::tuple<std::string, std::vector<unsigned char>> get_output_type(CTxOut output, std::string& result)
{
    std::vector<std::vector<unsigned char>> push_bytes;
    CScript script_pubkey = output.scriptPubKey;
    std::vector<unsigned char> result_vector;
    std::vector<unsigned char> vchRet;
    std::vector<opcodetype> op_codes;
    opcodetype opcodeRet;

    script_pubkey = output.scriptPubKey;

    result += "Output Script = "+serialize_script(script_pubkey)+"\n";

    CScriptBase::const_iterator pc = script_pubkey.begin();
    while (pc < script_pubkey.end()) 
    {   
        script_pubkey.GetOp(pc, opcodeRet, vchRet);
        if (!vchRet.empty()) {
            push_bytes.push_back(vchRet);
        }
        op_codes.push_back(opcodeRet);
    }

    if (op_codes.size() == 2 && op_codes.at(0) == 0x41 && op_codes.at(1) == 0xac) {
        result += "get_output_type = P2PK\n";
        result_vector = push_bytes.at(0);
        return std::make_tuple("001", result_vector);
    }

    if (script_pubkey.IsPayToScriptHash()) {
        result += "get_output_type = P2SH\n";
        result_vector = push_bytes.at(0);
        return std::make_tuple("010", result_vector);
    }

    if (op_codes.size() == 5 && op_codes.at(0) == 0x76 && op_codes.at(1) == 0xa9 && op_codes.at(2) && 0x28 && op_codes.at(3) == 0x88 && op_codes.at(4) == 0xac) {
        result += "get_output_type = P2PKH\n";
        result_vector = push_bytes.at(0);
        return std::make_tuple("011", result_vector);
    }

    if (script_pubkey.IsPayToWitnessScriptHash()) {
        result += "get_output_type = P2WSH\n";
        result_vector = push_bytes.at(0);
        return std::make_tuple("100", result_vector);
    } 

    if (op_codes.size() == 2 && op_codes.at(0) == 0x00 && op_codes.at(1) == 0x14) {
        result += "get_output_type = V0_WP2PKH\n";
        result_vector = push_bytes.at(0);
        return std::make_tuple("101", result_vector);
    }

    if (op_codes.size() == 2 && op_codes.at(0) == 0x51 && op_codes.at(1) == 0x20) {
        result += "get_output_type = P2TR\n";
        result_vector = push_bytes.at(0);
        return std::make_tuple("110", result_vector);
    }

    

    result += "get_output_type = CUSTOM SCRIPT\n";
    return std::make_tuple("111", result_vector);
}


void DecompressRawTransaction(const std::string compressed_transaction, Chainstate& active_chainstate, CMutableTransaction& transaction_result, std::string& result)
{
    result += "---------------------------------------------------\n";
    /* Result */
    CMutableTransaction mtx;

     /* Info Byte */
    std::string info_byte;

    /* Info bits */
    std::string version_bits;
    std::string locktime_bits;
    std::string input_count_bits;
    std::string output_count_bits;

    /* Input Ouput Byte */
    std::string io_byte;

    /* Input Output bits */
    std::string sequence_bits;
    std::string input_type_bits;
    std::string output_type_bits;

    /* Transaction Types */
    int input_count, output_count, vout_int, block_index, block_height;
    std::tuple<std::string, std::vector<unsigned char>> output_result;
    std::vector<std::string> compressed_signatures, input_types;
    std::vector<int> half_finished_inputs, hash_types;
    std::string input_type, output_type, script_type;
    std::vector<std::vector<unsigned char>> stack;
    Consensus::Params consensusParams;
    CScript scriptSig, output_script;
    std::vector<uint32_t> sequences;
    CScriptWitness scriptWitness;
    std::vector<CTxOut> vout;
    uint256 txid, block_hash;
    std::vector<CTxIn> vin;
    bool locktime_found;
    COutPoint outpoint;
    uint32_t sequence;
    CAmount amount;
    CTxIn ctxin;

    /* Misc. Variables */
    int byte, index, index2, index3, length, length2, length3, height, r;
    std::tuple<int32_t, int32_t> varint_result;
    std::vector<unsigned char> compact_signature;
    CScript c_script_pubkey, uc_script_pubkey;
    std::string hex, hex2, hex3, binary;
    Consensus::Params consensus_params;
    const CBlockIndex* pindex{nullptr};
    std::vector<CBlockIndex*> blocks;
    std::vector<unsigned char> bytes;
    BlockManager* blockman;
    CTransactionRef tr;
    bool pubkey_found;
    uint256 hash;
    CBlock block;

    /* Secp Variables */
    std::vector<secp256k1_ecdsa_recoverable_signature> recovered_signatures;
    std::vector<unsigned char> public_key_bytes;
    secp256k1_ecdsa_recoverable_signature rsig;
    std::vector<secp256k1_pubkey> pubkeys;
    secp256k1_ecdsa_signature sig;
    secp256k1_pubkey pubkey;

    /* Secp Context */
     secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Init Vars */
    blockman = &active_chainstate.m_blockman;
    int transaction_index = 0;
    locktime_found = true;

    /* Parse Info Byte 
        "xx": Version Encoding
        "xx": LockTime Encoding
        "xx: Input Count
        "xx": Output Count
    */
    hex = compressed_transaction.substr(transaction_index, 2);
    transaction_index += 2;
    info_byte = hex_to_binary(hex);

    version_bits = info_byte.substr(0, 2);
    result += "version_bits = "+version_bits+"\n";

    locktime_bits = info_byte.substr(2, 2);
    result += "locktime_bits = "+locktime_bits+"\n";

    input_count_bits = info_byte.substr(4, 2);
    result += "input_count_bits = "+input_count_bits+"\n";

    output_count_bits = info_byte.substr(6, 2);
    result += "output_count_bits = "+output_count_bits+"\n";

    result += "Info Byte = "+info_byte+"\n";
    result += "Info Byte Hex = "+hex+"\n";


    /* Parse Version 
        "00": Parse a VarInt
        _: Parse Binary of version_bits for version
    */
    if (version_bits == "00") {
        varint_result = from_varint(compressed_transaction.substr(transaction_index));
        mtx.nVersion = std::get<0>(varint_result);
        transaction_index += std::get<1>(varint_result);
        result += "Version Hex Length = "+std::to_string(std::get<1>(varint_result))+"\n";
    } else {
        mtx.nVersion = binary_to_int("000000"+version_bits);
    }
    result += "Version = "+std::to_string(mtx.nVersion)+"\n";

    /* Parse LockTime 
        "00": Locktime is zero
        "01": Locktime is only the two least signifigant bytes(Brute force later)
        "11": Coinbase Transaction, Lock time encoded as a VarInt
    */
    if (locktime_bits == "00") {
        mtx.nLockTime = 0;
    } else if (locktime_bits == "01") {
        hex = compressed_transaction.substr(transaction_index, 4);
        mtx.nLockTime = hex_to_int(hex);
        locktime_found = false;
        transaction_index += 4;
        result += "Shortend LockTime Hex = "+hex+"\n";
    } else if (locktime_bits == "11") {
        varint_result = from_varint(compressed_transaction.substr(transaction_index));
        mtx.nLockTime = std::get<0>(varint_result);
        transaction_index += std::get<1>(varint_result);
        result += "VarInt LockTime Hex Length = "+std::to_string(std::get<1>(varint_result))+"\n";
    }

    /* Parse Input Count 
        "00": Parse a VarInt
        _: Parse Binary of input_count_bits for Input Count
    */
    if (input_count_bits == "00") {
        varint_result = from_varint(compressed_transaction.substr(transaction_index));
        input_count = std::get<0>(varint_result);
        transaction_index += std::get<1>(varint_result);
        result += "Input Count Hex Length = "+std::to_string(std::get<1>(varint_result))+"\n";
    } else {
        input_count = binary_to_int("000000"+input_count_bits);
    }
    result += "Input Count = "+std::to_string(input_count)+"\n";

     /* Parse Output Count 
        "00": Parse a VarInt
        _: Parse Binary of output_count_bits for Output Count
    */
    if (output_count_bits == "00") {
        varint_result = from_varint(compressed_transaction.substr(transaction_index));
        output_count = std::get<0>(varint_result);
        transaction_index += std::get<1>(varint_result);
        result += "Output Count Hex Length = "+std::to_string(std::get<1>(varint_result))+"\n";
    } else {
        output_count = binary_to_int("000000"+output_count_bits);
    }
    result += "Output Count = "+std::to_string(output_count)+"\n";
    result += "^^^^^^^^^INFO BYTE^^^^^^^^^\n";

    /* Parse Input Output Byte 
        "xxx": Sequence Encoding
        "xx: Input Count
        "xxx": Output Count
    */
    hex = compressed_transaction.substr(transaction_index, 2);
    transaction_index += 2;
    io_byte = hex_to_binary(hex);

    sequence_bits = io_byte.substr(0, 3);
    result += "sequence_bits = "+sequence_bits+"\n";

    input_type_bits = io_byte.substr(3, 2);
    result += "input_type_bits = "+input_type_bits+"\n";

    output_type_bits = io_byte.substr(5, 3);
    result += "output_type_bits = "+output_type_bits+"\n";

    result += "Input Output Byte = "+io_byte+"\n";
    result += "Input Output Byte Hex = "+hex+"\n";

    byte = binary_to_int("00000"+sequence_bits);

    /* Parse Sequnce 
        "001": Parse Full Sequence From VarInt, All Sequences are Identical
        "010": Up to 4 Inputs had the Sequence Encoded in the Next Byte
        "011"-"110": Sequence is Identical and encoded in the Sequnce Bits
    */ 
    switch(byte)
    {
        case 1: 
        {
            varint_result = from_varint(compressed_transaction.substr(transaction_index));
            sequence = std::get<0>(varint_result);
            transaction_index += std::get<1>(varint_result);
            break;
        }
        case 2:
        {
            hex = compressed_transaction.substr(transaction_index, 2);
            result += "Encoded Sequence Byte Hex = "+hex+"\n";
            transaction_index += 2;
            binary = hex_to_binary(hex);
            for (index = 0; index < input_count; index++) {
                byte = binary_to_int("000000"+binary.substr(transaction_index, 2));
                switch(byte)
                {
                    case 0: 
                    {
                        sequences.push_back(0x00000000);
                        break;
                    }
                    case 1: 
                    {
                        sequences.push_back(0xFFFFFFF0);
                        break;
                    }
                    case 2: 
                    {
                        sequences.push_back(0xFFFFFFFE);
                        break;
                    }
                    case 3: 
                    {
                        sequences.push_back(0xFFFFFFFF);
                        break;
                    }
                }
            }
            break;
        }
        case 3:
        {
            sequence = 0xFFFFFFF0;
            break;
        }
        case 4:
        {
            sequence = 0xFFFFFFFE;
            break;
        }
        case 5:
        {
            sequence = 0xFFFFFFFF;
            break;
        }
        case 6:
        {
            sequence = 0x00000000;
            break;
        }
        default: 
        {
            result += "FAILURE: SEQUNECE BITS ARE INCORRECT(technically impossible to reach this)";
            sequence = 0x00000000;
        }
    }

    /* Parse Input Type
        "01": Up to 4 Input Types have been Encoded in the Next Byte
    */ 
    if (input_type_bits == "01") {
        hex = compressed_transaction.substr(transaction_index, 2);
        result += "Encoded Input Type Byte Hex = "+hex+"\n";
        binary = hex_to_binary(hex);
        transaction_index += 2;
        for (index = 0; index < 4; index++) {
            input_types.push_back(binary.substr(index, 2));
        }
    }
    result += "^^^^^^^^^IO BYTE^^^^^^^^^\n";

    for (index = 0; index < input_count; index++) {
        // Clear Stack From Previous Iterations
        stack.clear();
        /* Parse Sequence 
            "000": Sequence was uncompressed, Read from VarInt
            "010": Sequence was Read Previously, Set Temp Var
        */
        if (sequence_bits == "000") {
            varint_result = from_varint(compressed_transaction.substr(transaction_index));
            sequence = std::get<0>(varint_result);
            transaction_index += std::get<1>(varint_result);
            result += "Sequence = "+std::to_string(sequence)+"\n";
        } else if (sequence_bits == "010") {
            sequence = sequences.at(index);
        }

        /* Parse Input Type 
            "00": Input Type Was Uncomrpessed Read Next Byte
            "01": Input Type Was Already Parsed, Set Temp Var
            "10": All Inputs Identical, Input is Custom Type
            "11": All Inputs Identical, Input is Compressed
        */
        byte = binary_to_int("000000"+input_type_bits);
        switch(byte)
        {
            case 0: 
            {
                hex = compressed_transaction.substr(transaction_index, 2);
                transaction_index += 2;
                input_type = hex_to_binary(hex).substr(6, 2);
                break;
            }
            case 1:
            {
                input_type = input_types.at(index);
                break;
            }
            case 2:
            {
                input_type = "00";
                break;
            }
            case 3:
            {
                input_type = "11";
                break;
            }
        }

        /* Parse TXID */
        hex = compressed_transaction.substr(transaction_index, (32*2));
        result += "TXID hex = "+hex+"\n";
        txid.SetHex(hex);

        tr = GetTransaction(nullptr, nullptr, txid, consensus_params, hash);

        if (tr == nullptr) {
            varint_result = from_varint(compressed_transaction.substr(transaction_index));
            block_height = std::get<0>(varint_result);
            transaction_index += std::get<1>(varint_result);
            result += "Block Height = "+std::to_string(block_height)+"\n";

            varint_result = from_varint(compressed_transaction.substr(transaction_index));
            block_index = std::get<0>(varint_result);
            transaction_index += std::get<1>(varint_result);
            result += "Block Index = "+std::to_string(block_index)+"\n";
            blocks = blockman->GetAllBlockIndices();
            length2 = blocks.size();
            bool block_found = false;
            for (index2 = 0; index2 < length2; index2++) {
                pindex = blocks.at(index2);
                height = pindex->nHeight;
                if (block_height == height) {
                    result += "height = "+std::to_string(height)+"\n";
                    ReadBlockFromDisk(block, pindex, consensus_params);
                    result += "Block Hash = "+pindex->GetBlockHash().GetHex()+"\n";
                    txid = (*block.vtx.at(block_index)).GetHash();
                    result += "TXID = "+txid.GetHex()+"\n";
                    block_found = true;
                }
            }
            if (!block_found) {
                result += "ISSUE: Could not find block = "+std::to_string(block_height)+"\n";
            }
        } else {
            transaction_index += 32*2;
        }


        /* Parse Vout */
        varint_result = from_varint(compressed_transaction.substr(transaction_index));
        vout_int = std::get<0>(varint_result);
        transaction_index += std::get<1>(varint_result);
        result += "Vout = "+std::to_string(vout_int)+"\n";

        /* Parse Input 
            "00": Custom Input Type
            "11": Compressed Input Type, Read Data Complete it After
        */
        if (input_type == "00") {
            /* Parse Script Length */
            varint_result = from_varint(compressed_transaction.substr(transaction_index));
            length = std::get<0>(varint_result);
            transaction_index += std::get<1>(varint_result);
            result += "Script Length = "+std::to_string(length)+"\n";

            /* Parse Script */
            hex = compressed_transaction.substr(transaction_index, length*2);
            transaction_index += length*2;
            result += "Script = "+hex+"\n";
            bytes = hex_to_bytes(hex);
            scriptSig = CScript(bytes.begin(), bytes.end());

            /* Parse Witness Count */
            varint_result = from_varint(compressed_transaction.substr(transaction_index));
            length = std::get<0>(varint_result);
            transaction_index += std::get<1>(varint_result);
            result += "Witness Script Count = "+std::to_string(length)+"\n";
            for (index2 = 0; index2 < length; index2++) {
                /* Parse Witness Length */
                varint_result = from_varint(compressed_transaction.substr(transaction_index));
                length2 = std::get<0>(varint_result);
                transaction_index += std::get<1>(varint_result);
                result += "Witness Script Length = "+std::to_string(length2)+"\n";

                /* Parse Witness Script */
                hex = compressed_transaction.substr(transaction_index, length2*2);
                transaction_index += length2*2;
                result += "Witness Script = "+hex+"\n";
                stack.push_back(hex_to_bytes(hex));
            }
        } else {
            hex = compressed_transaction.substr(transaction_index, 64*2);
            compressed_signatures.push_back(hex);
            half_finished_inputs.push_back(index);
            transaction_index += 64*2;
            result += "Compressed Signature = "+hex+"\n";
            hex = compressed_transaction.substr(transaction_index, 2);
            transaction_index += 2;
            hash_types.push_back(hex_to_int(hex));
            result += "Hash Type = "+hex+"\n";
        }

        /* Assemble CTxIn */
        outpoint = COutPoint(txid, vout_int);
        ctxin = CTxIn(outpoint, scriptSig, sequence);
        ctxin.scriptWitness.stack = stack;
        vin.push_back(ctxin);
    }
    mtx.vin = vin;
    result += "^^^^^^^^^INPUT^^^^^^^^^\n";

    for (index = 0; index < output_count; index++) {
        /* Parse Output Type 
            "000": Output Type Uncompressed, Read From Next Byte
            _: Parse Output Type From output_type_bits
        */
        if (output_type_bits == "000") {
            /* Parse Output Type */
            hex = compressed_transaction.substr(transaction_index, 2);
            transaction_index += 2;
            result += "Output Type Hex = "+hex+"\n";
            output_type = hex_to_binary(hex).substr(5, 3);
        } else {
            output_type = output_type_bits;
        }

        /* Parse Amount */
        varint_result = from_varint(compressed_transaction.substr(transaction_index));
        amount = std::get<0>(varint_result);
        transaction_index += std::get<1>(varint_result);
        result += "Amount = "+std::to_string(amount)+"\n";

        /* Parse Output 
            "001": P2PK
            "010": P2SH
            "011": P2PKH
            "100": P2WSH
            "101": P2WPKH
            "110": P2TR
            "111": Custom Script
        */
        byte = binary_to_int("00000"+output_type);
        switch(byte)
        {
            case 1: {
                hex = compressed_transaction.substr(transaction_index, 65);
                transaction_index += 65;
                result += "Script = "+hex+"\n";
                hex = "41"+hex+"ac";
                result += "Exteneded Script = "+hex+"\n";
                bytes = hex_to_bytes(hex);
                output_script = CScript(bytes.begin(), bytes.end());
                break;
            }
            case 2: {
                hex = compressed_transaction.substr(transaction_index, 40);
                transaction_index += 40;
                result += "Script = "+hex+"\n";
                hex = "a914"+hex+"87";
                result += "Exteneded Script = "+hex+"\n";
                bytes = hex_to_bytes(hex);
                output_script = CScript(bytes.begin(), bytes.end());
                break;
            }
            case 3: {
                hex = compressed_transaction.substr(transaction_index, 40);
                transaction_index += 40;
                result += "Script = "+hex+"\n";
                hex = "76a914"+hex+"88ac";
                result += "Exteneded Script = "+hex+"\n";
                bytes = hex_to_bytes(hex);
                output_script = CScript(bytes.begin(), bytes.end());
                break;
            }
            case 4: {
                hex = compressed_transaction.substr(transaction_index, 64);
                transaction_index += 64;
                result += "Script = "+hex+"\n";
                hex = "0020"+hex;
                result += "Exteneded Script = "+hex+"\n";
                bytes = hex_to_bytes(hex);
                output_script = CScript(bytes.begin(), bytes.end());
                break;
            }
            case 5: {
                hex = compressed_transaction.substr(transaction_index, 40);
                transaction_index += 40;
                result += "Script = "+hex+"\n";
                hex = "0014"+hex;
                result += "Exteneded Script = "+hex+"\n";
                bytes = hex_to_bytes(hex);
                output_script = CScript(bytes.begin(), bytes.end());
                break;
            }
            case 6: {
                hex = compressed_transaction.substr(transaction_index, 64);
                transaction_index += 64;
                result += "Script = "+hex+"\n";
                hex = "5120"+hex;
                result += "Exteneded Script = "+hex+"\n";
                bytes = hex_to_bytes(hex);
                output_script = CScript(bytes.begin(), bytes.end());
                break;
            }
            case 7:
            {
                /* Parse Script Length */
                varint_result = from_varint(compressed_transaction.substr(transaction_index));
                length = std::get<0>(varint_result);
                transaction_index += std::get<1>(varint_result);
                result += "Script Length = "+std::to_string(length)+"\n";

                /* Parse Script */
                hex = compressed_transaction.substr(transaction_index, length*2);
                transaction_index += length*2;
                result += "Script = "+hex+"\n";
                bytes = hex_to_bytes(hex);
                output_script = CScript(bytes.begin(), bytes.end());
                break;
            }
            default:
            {
                result += "FAILURE: UNCAUGHT OUTPUT TYPE;\n";
            }
        }
        vout.push_back(CTxOut(amount, output_script));
    }
    mtx.vout = vout;
    result += "^^^^^^^^^OUTPUT^^^^^^^^^\n";

    length = half_finished_inputs.size();
    for (index = 0; index < length; index++) {
        /* Complete Input Types */
        index2 = half_finished_inputs.at(index);
        result += "Half Finished Input "+std::to_string(index)+", "+std::to_string(index2)+"---------------------\n";
        CTransactionRef prev_tx = GetTransaction(NULL, NULL, mtx.vin.at(index2).prevout.hash, consensusParams, block_hash);
        CMutableTransaction prev_mtx = CMutableTransaction(*prev_tx);
        CScript script_pubkey = (*prev_tx).vout.at(mtx.vin.at(index2).prevout.n).scriptPubKey;
        CAmount amount = (*prev_tx).vout.at(mtx.vin.at(index2).prevout.n).nValue;
        result += "amount = "+std::to_string(amount)+"\n";
        result += "Scritp Pubkey = "+serialize_script(script_pubkey)+"\n";
        output_result = get_output_type((*prev_tx).vout.at(mtx.vin.at(index2).prevout.n), result);
        script_type = std::get<0>(output_result);
        byte = binary_to_int(script_type);

        /* Parse Input Type 
            "011"|"101": ECDSA Signature
            "110": Schnorr Signature
        */
        if (byte == 3 || byte == 5) {
            compact_signature = hex_to_bytes(compressed_signatures.at(index));
            for (index3 = 0; index3 < 4; index3++) {
                /* Parse the compact signature with each of the 4 recovery IDs */
                r = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, &compact_signature[0], index3);
                if (r == 1) {
                    recovered_signatures.push_back(rsig);
                }
            }
        } else if (byte == 6) {
            result += "TAPROOT INIT\n";
        } else {
            result += "ISSUE WITH INPUT SCRIPT\n";
        }

        while(true) {
            /* Parse Input 
            "011": P2PKH
            "101": P2WPKH
            "110": P2TR
            */
            if (byte == 3 ) {
                result += "P2PKH\n";
                
                /* Hash the Trasaction to generate the SIGHASH */
                result += "Hash Type = "+int_to_hex(hash_types.at(index))+"\n";
                hash = SignatureHash(script_pubkey, mtx, index2, hash_types.at(index), amount, SigVersion::BASE);
                hex = hash.GetHex();
                bytes = hex_to_bytes(hex);
                std::reverse(bytes.begin(), bytes.end());
                hex = bytes_to_hex(bytes);
                result += "message = "+hex+"\n";

                length2 = recovered_signatures.size();
                for (index3 = 0; index3 < length2; index3++) {
                    /* Run Recover to get the Pubkey for the given Recovered Signature and Message/SigHash (Fails half the time(ignore)) */
                    r = secp256k1_ecdsa_recover(ctx, &pubkey, &recovered_signatures.at(index3), &bytes[0]);
                    if (r == 1) {
                        result += "SUCCESS\n";
                        pubkeys.push_back(pubkey);
                    }
                }

                pubkey_found = false;
                length2 = pubkeys.size();
                for (index3 = 0; index3 < length2; index3++) {
                    result += "\nPUBKEY = "+std::to_string(index3)+"\n";
                    /* Serilize Compressed Pubkey */
                    std::vector<unsigned char> c_vch (33);
                    size_t c_size = 33;
                    secp256k1_ec_pubkey_serialize(ctx, &c_vch[0], &c_size, &pubkeys.at(index3), SECP256K1_EC_COMPRESSED);
                    hex = bytes_to_hex(c_vch);
                    result += "COMPRESSED public key = "+hex+"\n";
                    /* Hash Compressed Pubkey */
                    uint160 c_pubkeyHash;
                    CHash160().Write(c_vch).Finalize(c_pubkeyHash);
                    hex = c_pubkeyHash.GetHex();
                    bytes = hex_to_bytes(hex);
                    std::reverse(bytes.begin(), bytes.end());
                    hex = bytes_to_hex(bytes);
                    result += "COMPRESSED public key Hash = "+hex+"\n";
                    /* Construct Compressed ScriptPubKey */
                    hex = "76a914"+hex+"88ac";
                    result += "COMPRESSED Script Pubkey = "+hex+"\n";
                    bytes = hex_to_bytes(hex);
                    c_script_pubkey = CScript(bytes.begin(), bytes.end());
                    /* Test Scripts */
                    if (serialize_script(c_script_pubkey) == serialize_script(script_pubkey)) {
                        secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &recovered_signatures.at(index3));
                        pubkey_found = true;
                        public_key_bytes = c_vch;
                        break;
                    }

                    result += "-----------\n";

                    /* Serilize Uncompressed Pubkey */
                    std::vector<unsigned char> uc_vch (65);
                    size_t uc_size = 65;
                    secp256k1_ec_pubkey_serialize(ctx, &uc_vch[0], &uc_size, &pubkeys.at(index3), SECP256K1_EC_UNCOMPRESSED);
                    hex = bytes_to_hex(uc_vch);
                    result += "UNCOMPRESSED public key = "+hex+"\n";
                    /* Hash Uncompressed PubKey */
                    uint160 uc_pubkeyHash;
                    CHash160().Write(uc_vch).Finalize(uc_pubkeyHash);
                    hex = uc_pubkeyHash.GetHex();
                    bytes = hex_to_bytes(hex);
                    std::reverse(bytes.begin(), bytes.end());
                    hex = bytes_to_hex(bytes);
                    result += "UNCOMPRESSED public key Hash = "+hex+"\n";
                    /* Construct Uncompressed ScriptPubKey */
                    hex = "76a914"+hex+"88ac";
                    result += "UNCOMPRESSED Script Pubkey = "+hex+"\n";
                    bytes = hex_to_bytes(hex);
                    uc_script_pubkey = CScript(bytes.begin(), bytes.end());
                    /* Test Scripts */
                    if (serialize_script(uc_script_pubkey) == serialize_script(script_pubkey)) {
                        secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &recovered_signatures.at(index3));
                        pubkey_found = true;
                        public_key_bytes = uc_vch;
                        break;
                    }
                }
                if (pubkey_found) {
                    result += "FOUND\n";
                    locktime_found = true;
                    std::vector<unsigned char> sig_der (71);
                    size_t sig_der_size = 71;
                    secp256k1_ecdsa_signature_serialize_der(ctx, &sig_der[0], &sig_der_size, &sig);
                    hex = bytes_to_hex(sig_der);
                    result += "Signature = "+hex+"\n";
                    hex2 = bytes_to_hex(public_key_bytes);
                    result += "Pubkey = "+hex2+"\n";
                    length3 = hex2.length()/2;
                    result += "pubkeylen = "+std::to_string(length3)+"\n";
                    hex3 = int_to_hex(length3);
                    result += "hex0 = 48\n";
                    result += "hex1 = "+hex+"\n";
                    result += "hex2 = "+hex3+"\n";
                    result += "hex3 = "+hex2+"\n";
                    hex = "48"+hex+"01"+hex3+hex2;
                    result += "Script Signature = "+hex+"\n";
                    bytes = hex_to_bytes(hex);
                    scriptSig = CScript(bytes.begin(), bytes.end());
                    mtx.vin.at(index2).scriptSig = scriptSig;
                } else {
                    result += "FAILURE: no pubkey found\n";
                }
            } else if (byte == 5) {
                result += "V0_P2WPKH\n";
                
                /* Hash the Trasaction to generate the SIGHASH */
                std::string scriptPubKeyHash = serialize_script(script_pubkey);
                result += "test1 = "+scriptPubKeyHash+"\n";
                std::string pubkeyhash = scriptPubKeyHash.substr(4, 40);
                result += "test2 = "+pubkeyhash+"\n";
                bytes = hex_to_bytes("76a914"+pubkeyhash+"88ac");
                CScript script_code = CScript(bytes.begin(), bytes.end()); 
                result += "Script Code = "+serialize_script(script_code)+"\n"; 
                hash = SignatureHash(script_code, mtx, index2, hash_types.at(index), amount, SigVersion::WITNESS_V0);
                //TODO: Get Bytes directly.
                hex = hash.GetHex();
                bytes = hex_to_bytes(hex);
                std::reverse(bytes.begin(), bytes.end());
                hex = bytes_to_hex(bytes);
                result += "message = "+hex+"\n";

                pubkeys.clear();
                length2 = recovered_signatures.size();
                for (index3 = 0; index3 < length2; index3++) {
                    /* Run Recover to get the Pubkey for the given Recovered Signature and Message/SigHash (Fails half the time(ignore)) */
                    r = secp256k1_ecdsa_recover(ctx, &pubkey, &recovered_signatures.at(index3), &bytes[0]);
                    if (r == 1) {
                        result += "SUCCESS\n";
                        pubkeys.push_back(pubkey);
                    }
                }

                pubkey_found = false;
                length2 = pubkeys.size();
                for (index3 = 0; index3 < length2; index3++) {
                    result += "\nPUBKEY = "+std::to_string(index3)+"\n";
                    /* Serilize Compressed Pubkey */
                    std::vector<unsigned char> c_vch (33);
                    size_t c_size = 33;
                    secp256k1_ec_pubkey_serialize(ctx, &c_vch[0], &c_size, &pubkeys.at(index3), SECP256K1_EC_COMPRESSED);
                    hex = bytes_to_hex(c_vch);
                    result += "COMPRESSED public key = "+hex+"\n";
                    /* Hash Compressed Pubkey */
                    uint160 c_pubkeyHash;
                    CHash160().Write(c_vch).Finalize(c_pubkeyHash);
                    hex = c_pubkeyHash.GetHex();
                    bytes = hex_to_bytes(hex);
                    std::reverse(bytes.begin(), bytes.end());
                    hex = bytes_to_hex(bytes);
                    result += "COMPRESSED public key Hash = "+hex+"\n";
                    /* Construct Compressed ScriptPubKey */
                    hex = "0014"+hex;
                    result += "COMPRESSED Script Pubkey = "+hex+"\n";
                    bytes = hex_to_bytes(hex);
                    c_script_pubkey = CScript(bytes.begin(), bytes.end());
                    result += "test = "+serialize_script(script_pubkey)+"\n";
                    /* Test Scripts */
                    if (serialize_script(c_script_pubkey) == serialize_script(script_pubkey)) {
                        result += "index = "+std::to_string(index3)+"\n";
                        secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &recovered_signatures.at(index3));
                        pubkey_found = true;
                        public_key_bytes = c_vch;
                        break;
                    }
                }
                if (pubkey_found) {
                    result += "FOUND\n";
                    locktime_found = true;
                    std::vector<unsigned char> sig_der (70);
                    std::vector<std::vector<unsigned char>> stack;
                    size_t sig_der_size = 70;
                    secp256k1_ecdsa_signature_serialize_der(ctx, &sig_der[0], &sig_der_size, &sig);
                    sig_der.push_back(hash_types.at(index));
                    stack.push_back(sig_der);
                    stack.push_back(public_key_bytes);
                    scriptWitness.stack = stack;
                    mtx.vin.at(index2).scriptWitness = scriptWitness;
                } else {
                    result += "FAILURE: no pubkey found\n";
                }
            } else if (byte == 6) {
                result += "P2TR\n";
                stack.clear();
                std::vector<unsigned char> schnorr_signature = hex_to_bytes(compressed_signatures.at(index));
                if (!locktime_found) {
                    /* Script Execution Data Init */
                    ScriptExecutionData execdata;
                    execdata.m_annex_init = true;
                    execdata.m_annex_present = false;

                    /* Prevout Init */
                    PrecomputedTransactionData cache;
                    std::vector<CTxOut> utxos;
                    length3 = mtx.vin.size();
                    for (index3 = 0; index3 < length3; index3 ++) {
                        CTransactionRef prev_tx = GetTransaction(NULL, NULL, mtx.vin.at(index3).prevout.hash, consensusParams, block_hash);
                        // CMutableTransaction prev_mtx = CMutableTransaction(*prev_tx);
                        CScript script = (*prev_tx).vout.at(mtx.vin.at(index3).prevout.n).scriptPubKey;
                        amount = (*prev_tx).vout.at(mtx.vin.at(index3).prevout.n).nValue;
                        utxos.emplace_back(amount, script);
                    }
                    cache.Init(CTransaction(mtx), std::vector<CTxOut>{utxos}, true);

                    r = SignatureHashSchnorr(hash, execdata, mtx, index2, hash_types.at(index), SigVersion::TAPROOT, cache, MissingDataBehavior::FAIL);
                    if (!r) {
                        result += "FAILURE SCHNORR HASH\n";
                    }
                    hex = hash.GetHex();
                    result += "message = "+hex+"\n";
                    r = get_first_push_bytes(bytes, script_pubkey);
                    if (!r) {
                        result += "ISSUE: Could not get push bytes\n";
                    }
                    hex = bytes_to_hex(bytes);
                    result += "pubkey = "+hex+"\n";
                    // hex2 = serialize_script(script_pubkey).substr(4, 64);
                    // result += "pubkey = "+hex2+"\n";
                    result += "signature = "+bytes_to_hex(schnorr_signature)+"\n";
                    secp256k1_xonly_pubkey xonly_pubkey;
                    r = secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey, bytes.data());
                    if (!r) {
                        result += "FAILURE: ISSUE PUBKEY PARSE\n";
                    }
                    r = secp256k1_schnorrsig_verify(ctx, schnorr_signature.data(), hash.begin(), 32, &xonly_pubkey);
                    if (!r) {
                        result += "FAILURE: Issue verifiy\n";
                    } else {
                        locktime_found = true;
                    }
                }
                if (locktime_found) {
                    stack.clear();
                    schnorr_signature.push_back(hash_types.at(index));
                    stack.push_back(schnorr_signature);
                    mtx.vin.at(index).scriptWitness.stack = stack;
                }

            }
            /* If LockTime Has been Found Break, Otherwise add 2^16 to it and try again */
            if (locktime_found) {
                break;
            } else {
                mtx.nLockTime += pow(2, 16);
                result += "lock = "+std::to_string(mtx.nLockTime)+"\n";
            }
        }
    }
    transaction_result = mtx;
}

void CompressRawTransaction(CMutableTransaction& mtx, Chainstate& active_chainstate, std::string& transaction_result, std::string& result)
{
    /* Result */
    std::string compressed_transaction;

    /* Info Byte */
    std::string info_byte;

    /* Info bits */
    std::string version_bits;
    std::string locktime_bits;
    std::string input_count_bits;
    std::string output_count_bits;

    /* Input Ouput Byte */
    std::string io_byte;

    /* Input Output bits */
    std::string sequence_bits;
    std::string input_type_bits;
    std::string output_type_bits;

    /* Transaction Types */
    std::vector<uint32_t> sequences;
    bool coinbase;

    /* Input Output Types */
    std::tuple<std::string, std::vector<unsigned char>> output_result;
    std::tuple<std::string, std::vector<unsigned char>> input_result;
    std::vector<std::tuple<std::string, std::vector<unsigned char>>> outputs;
    std::vector<std::tuple<std::string, std::vector<unsigned char>>> inputs;

    /* Misc. Variables */
    int byte, limit, index, index2, length, length2, length3, block_height, block_index;
    Consensus::Params consensus_params;
    const CBlockIndex* pindex{nullptr};
    std::vector<unsigned char> bytes;
    std::string hex, hex2, hex3, binary;
    CMutableTransaction rmtx;
    BlockManager* blockman;
    CTransactionRef tr;
    uint256 hash;
    CBlock block;
    uint256 txid;

    /* Init Vars */
    blockman = &active_chainstate.m_blockman;

    /* Encode Version
        Encode the version as binary if its less then 4, Otherwise we'll encode the version as a VarInt later. 
    */
    switch(mtx.nVersion)
    {
        case 1: 
        {
            version_bits = "01";
            break;
        };
        case 2: 
        {
            version_bits = "10";
            break;
        };
        case 3: 
        {
            version_bits = "11";
            break;
        };
        default: 
        {
            version_bits = "00";
            break;
        };
    }

    /* Encode coinbase bool
        4294967295 is the vout associated with a coinbase transaction, Therefore minimal compression is avaible. 
    */
    switch(mtx.vin[0].prevout.n) 
    {
        case 4294967295: 
        {
            coinbase = true;
            break;
        }
        default: 
        {
            coinbase = false;
            break;
        }
    }

    // result += "coinbase = "+std::to_string(coinbase)+"\n";

    /* Encode Lock Time
        "00": If locktime is 0 enocde that in the control byte.
        "11": If locktime is non zero but this is a coinbase transaction, Then no compresion is avalibe for the locktime.
        "01": If locktime is non zero and not a coinbase transaction transmite the two least significant bytes of the locktime and we'll brute force the remaninig bytes in the decoding.
    */
    switch(mtx.nLockTime) 
    {
        case 0: 
        {
            locktime_bits = "00";
            break;
        }
        default: 
        {
            if (coinbase) {
                locktime_bits = "11";
            } else {
                locktime_bits = "01";
            }
            break;
        };
    }

    /* Encode Input Count
        Encode the Input Count as binary if its less then 4, Otherwise we'll encode the Input Count as a VarInt later. 
    */
    switch(mtx.vin.size())
    {
        case 1:
        {
            input_count_bits = "01";
            break;
        }
        case 2:
        {
            input_count_bits = "10";
            break;
        }
        case 3:
        {
            input_count_bits = "11";
            break;
        }
        default:
        {
            input_count_bits = "00";
            break;
        }
    }

    /* Encode Output Count
        Encode the Output Count as binary if its less then 4, Otherwise we'll encode the Output Count as a VarInt later. 
    */
    switch(mtx.vout.size())
    {
        case 1:
        {
            output_count_bits = "01";
            break;
        }
        case 2:
        {
            output_count_bits = "10";
            break;
        }
        case 3:
        {
            output_count_bits = "11";
            break;
        }
        default:
        {
            output_count_bits = "00";
            break;
        }
    }


    /* Encode Info Byte 
        "xx": Version Encoding
        "xx": LockTime Encoding
        "xx": Input Count
        "xx": Output Count
    */
    result += "version_bits = "+version_bits+"\n";
    result += "locktime_bits = "+locktime_bits+"\n";
    result += "input_count_bits = "+input_count_bits+"\n";
    result += "output_count_bits = "+output_count_bits+"\n";
    info_byte = version_bits;
    info_byte += locktime_bits;
    info_byte += input_count_bits;
    info_byte += output_count_bits;

    result += "Info Byte = "+info_byte+"\n";

    /* Push the Info Byte to the Result */
    hex = binary_to_hex(info_byte);
    result += "Info Byte Hex = "+hex+"\n";
    compressed_transaction += hex;

    /* Encode Version
        If the Version was not encoded in the Info bit, Encode it as a VarInt here. 
    */
    if (version_bits == "00") {
        hex = to_varint(mtx.nVersion);
        result += "Version Hex = "+hex+"\n";
        compressed_transaction += hex;
    }
    result += "Version = "+std::to_string(mtx.nVersion)+"\n";

    /* Encode LockTime
        If the locktime was not zero and this is not a coinbase transaction, Encode the two least signafigant bytes as Hex 
        If the locktime was not zero and this is a coinbase transaction, encode the LockTime as a VarInt. 
    */
    if (locktime_bits == "01") {
        limit = pow(2, 16);
        binary = std::bitset<16>(mtx.nLockTime % limit).to_string();
        /* Push the Shortend Locktime Bytes */
        hex = binary_to_hex(binary);
        result += "Shortend Locktime Hex = "+hex+"\n";
        compressed_transaction += hex;
    } else if (locktime_bits == "11") {
        /* Push the LockTime encoded as a VarInt */
        hex = to_varint(mtx.nLockTime);
        result += "VarInt Locktime Hex = "+hex+"\n";
        compressed_transaction += hex;
    }

    /* Encode Input Count 
        If the Input Count is greater then 3, then Encode the Input Count as a VarInt.
    */
    if (input_count_bits == "00") {
        /* Push the Input Count encoded as a VarInt */
        hex = to_varint(mtx.vin.size());
        result += "Input Count Hex = "+hex+"\n";
        compressed_transaction += hex;
    }
    result += "Input Count = "+std::to_string(mtx.vin.size())+"\n";

    /* Encode Output Count 
        If the Output Count is greater then 3, then Encode the Output Count as a VarInt.
    */
    if (output_count_bits == "00") {
        /* Push the Output Count encoded as a VarInt */
        hex = to_varint(mtx.vout.size());
        result += "Output Count Hex = "+hex+"\n";
        compressed_transaction += hex;
    }
    result += "Output Count = "+std::to_string(mtx.vout.size())+"\n";
    result += "^^^^^^^^^INFO BYTE^^^^^^^^^\n";

    /* Encode Squence 
        "000": Non Identical, Non Standard Sequence/Inputs more then 3. Read Sequence Before Each Input.
        "001": Identical, Non Standard Sequence. Read VarInt for Full Sequnce.
        "010": Non Identical, Standard Sequence, Inputs less then 4. Read Next Byte For Encoded Sequences.
        "011": Identical, Standard Sequence. 0xFFFFFFF0
        "100": Identical, Standard Sequence. 0xFFFFFFFE
        "101": Identical, Standard Sequence. 0xFFFFFFFF
        "110": Identical, Standard Sequence. 0x00000000
        "111": Null.
    */
    sequences.push_back(mtx.vin.at(0).nSequence);
    bool identical_sequnce = true;
    bool standard_sequence = true;
    if (sequences.at(0) != 0x00000000 || sequences.at(0) != 0xFFFFFFF0 || sequences.at(0) != 0xFFFFFFFE || sequences.at(0) != 0xFFFFFFFF) {
        standard_sequence = false;
    }
    length = mtx.vin.size();
    for (index = 1; index < length; index++) {
        if (mtx.vin.at(index).nSequence != sequences.at(0)) {
            identical_sequnce = false;
        }
        if (mtx.vin.at(index).nSequence != 0x00000000 || mtx.vin.at(index).nSequence != 0xFFFFFFF0 || mtx.vin.at(index).nSequence != 0xFFFFFFFE || mtx.vin.at(index).nSequence != 0xFFFFFFFF) {
            standard_sequence = false;
        }
        if (input_count_bits != "00") {
            sequences.push_back(mtx.vin.at(index).nSequence);
        }
    }
    if (identical_sequnce) {
        switch(sequences.at(0))
        {
            case 0xFFFFFFF0: 
            {
                sequence_bits = "011";
                break;
            }
            case 0xFFFFFFFE: 
            {
                sequence_bits = "100";
                break;
            }
            case 0xFFFFFFFF: 
            {
                sequence_bits = "101";
                break;
            }
            case 0x00000000: 
            {
                sequence_bits = "110";
                break;
            }
            default: 
            {
                sequence_bits = "001";
                break;
            }
        }
    } else {
        if (standard_sequence && input_count_bits != "00") {
            sequence_bits = "010";
        } else {
            sequence_bits = "000";
        }
    }
   
    /* Encode Input Type 
        "00": More then 3 Inputs, Non Identical Scripts, At least one Input is of Custom Type. 
        "01": Less then 4 Inputs, Non Identical Scripts, At least one Input is of Custom Type. 
        "10": Identical Script Types, Custom Script.
        "11": Identical Script Types, Legacy, Segwit, or Taproot.
    */
    std::string input_type, input_type_second;
    bool input_type_identical = true;

    input_result = get_input_type(mtx.vin.at(0), result);
    inputs.push_back(input_result);
    input_type = std::get<0>(input_result);
    length = mtx.vin.size();
    for (index = 1; index < length; index++) {
        input_result = get_input_type(mtx.vin.at(index), result);
        input_type_second = std::get<0>(input_result);
        if (input_type != input_type_second) {
            input_type_identical = false;
        }
        inputs.push_back(input_result);
    }
    if (input_type_identical && input_type == "00") {
        input_type_bits = "10";
    } else if (input_type_identical && input_type != "00") {
        input_type_bits = "11";
    } else if (!input_type_identical && input_count_bits == "00") {
        input_type_bits == "00";
    } else if (!input_type_identical && input_count_bits != "00") {
        input_type_bits = "01";
    }


    /* Encode Output Type 
        "000": Non Identical Script Types. Read Type before each Output.
        "001": Identical Output Script Types, P2PK.
        "010": Identical Output Script Types, P2SH.
        "011": Identical Output Script Types, P2PKH.
        "100": Identical Output Script Types, V0_P2WSH.
        "101": Identical Output Script Types, V0_P2WPKH.
        "110": Identical Output Script Types, P2TR.
        "111": Identical Output Script Types, Custom Script.
    */
    std::string output_type, output_type_second;
    bool output_type_identical = true;

    output_result = get_output_type(mtx.vout.at(0), result);
    outputs.push_back(output_result);
    output_type = std::get<0>(output_result);
    length = mtx.vout.size();
    for (index = 1; index < length; index++) {
        output_result = get_output_type(mtx.vout.at(index), result);
        output_type_second = std::get<0>(output_result);
        if (output_type != output_type_second) {
            output_type_identical = false;
        }
        outputs.push_back(output_result);
    }
    if (output_type_identical) {
        output_type_bits = output_type;
    } else {
        output_type_bits = "000";
    }
        
    /* Encode Input Output Byte 
        "xxx": Sequence Encoding
        "xx": Input Encoding
        "xxx": Output Encoding
    */
    result += "sequence_bits = "+sequence_bits+"\n";
    result += "input_type_bits = "+input_type_bits+"\n";
    result += "output_type_bits = "+output_type_bits+"\n";
    io_byte = sequence_bits;
    io_byte += input_type_bits;
    io_byte += output_type_bits;
    result += "Input Output Byte = "+io_byte+"\n";

    /* Push the Input Output Byte to the Result */
    hex = binary_to_hex(io_byte);
    result += "Input Output Byte Hex = "+hex+"\n";
    compressed_transaction += hex;

    /* Encode Sequence 
        "001": Identical Sequence, Non Standard, Encode as a Single VarInt
        "010": Non Identical Sequence, Standard Encoding with less the 4 inputs, Encode as a Single Byte
    */
    if (sequence_bits == "001") {
        /* Push the Sequnece VarInt for the Inputs */
        hex = to_varint(sequences.at(0));
        result += "Sequence VarInt Hex = "+hex+"\n";
        compressed_transaction += hex;
    } else if (sequence_bits == "010") {
        binary = "";
        length = sequences.size();
        for (index = 0; index < length; index++) {
            switch(sequences.at(index))
            {
                case 0x00000000: 
                {
                    binary += "00";
                    break;
                }
                case 0xFFFFFFF0: 
                {
                    binary += "01";
                    break;     
                }
                case 0xFFFFFFFE: 
                {
                    binary += "10";
                    break;     
                }
                case 0xFFFFFFFF: 
                {
                    binary += "11";
                    break;     
                }
                default: 
                {
                    exit(1);
                }
            }
        }
        length = 8-binary.length();
        for (index = 0; index < length; index++){
            binary += "00";
        }
        /* Push the Sequneces Byte for the Inputs Encoded as 2-3 bits */
        hex = binary_to_hex(binary);
        result += "Encoded Sequence Byte Hex = "+hex+"\n";
        compressed_transaction += hex;
    }

    /* Encode Input Type 
        "01": Non Identical Input Types, Less then 4 Inputs, Encode as a Singe Byte
    */
    if (input_type_bits == "01") {
        length = inputs.size();
        binary = "";
        for (index = 0; index < length; index++) {
            input_result = inputs.at(index);
            input_type = std::get<0>(input_result);
            binary += input_type;
        }
        length = 8-hex.length();
        for (index = 0; index < length; index++) {
            binary += "00";
        }

        /* Push Input Type Byte */
        hex = binary_to_hex(binary);
        result += "Encoded Input Type Byte Hex = "+hex+"\n";
        compressed_transaction += hex;
    }
    result += "^^^^^^^^^IO BYTE^^^^^^^^^\n";

    length = mtx.vin.size();
    result += "length = "+std::to_string(length)+"\n";
    for (index = 0; index < length; index++) {
        result += "index = "+std::to_string(index)+"\n";

        /* Encode Sequence 
            "000": Uncompressed Sequence, Encode VarInt
        */
        if (sequence_bits == "000") {
            /* Push Sequence */
            hex = int_to_hex(mtx.vin.at(index).nSequence);
            result += "Sequence = "+std::to_string(mtx.vin.at(index).nSequence)+"\n";
            result += "Sequence Hex = "+hex+"\n";
            compressed_transaction += hex;
        }

        /* Encode Input Type
            "00": Uncompressed Input Type, Encode Next Byte
        */
        input_result = inputs.at(index);
        input_type = std::get<0>(input_result);
        if (input_type_bits == "00") {
            /* Push Input Type */
            hex = binary_to_hex("000000"+input_type);
            result += "Input Type Hex = "+hex+"\n";
            compressed_transaction += hex;
        } 

        /* Encode TXID Block Index/Height 
            If Not CoinBase: Encode TXID as its Block Index/Height
        */
        block_index = 0xFFFFFF;
        if (!coinbase) {
            tr = GetTransaction(nullptr, nullptr, mtx.vin.at(index).prevout.hash, consensus_params, hash);
            txid = (*tr).GetHash();
            std::vector<std::shared_ptr<const CTransaction>>::iterator itr;
            {
                // const uint256& conhash = mtx.vin.at(index).prevout.hash;
                pindex = blockman->LookupBlockIndex(hash);
                block_height = pindex->nHeight;
                result += "Block Hash = "+pindex->GetBlockHash().GetHex()+"\n";
                ReadBlockFromDisk(block, pindex, consensus_params);
                length2 = block.vtx.size();
                for (index2 = 0; index2 < length2; index2++) {
                    if ((*block.vtx.at(index2)).GetHash() == txid) {
                        block_index = index2;
                    }
                }
            }
        } 

        /* Encode TXID 
            If Not CoinBase || And Block Index/Height Was Found: Encode TXID as its Block Index/Height
        */
        if (coinbase || block_index == 0xFFFFFF) {
            /* Push the TXID */
            hex = mtx.vin.at(index).prevout.hash.GetHex();
            result += "TXID hex = "+hex+"\n";
            compressed_transaction += hex;
        } else {
            /* Push Block Height */
            hex = to_varint(block_height);
            result += "Block Height Hex = "+hex+"\n";
            result += "Block Height = "+std::to_string(block_height)+"\n";
            compressed_transaction += hex;

            /* Push Block Index */
            hex = to_varint(block_index);
            result += "Block Index Hex = "+hex+"\n";
            result += "Block Index = "+std::to_string(block_index)+"\n";
            compressed_transaction += hex;
        }

        /* Push Vout */
        hex = to_varint(mtx.vin.at(index).prevout.n);
        result += "Vout = "+std::to_string(mtx.vin.at(index).prevout.n)+"\n";
        result += "VarInt Vout Hex = "+hex+"\n";
        compressed_transaction += hex;

        /* Encode Input 
            "00": Custom Input
            _: Compressed Input
        */
        byte = binary_to_int("000000"+input_type);
        if (input_type == "00") {
            hex = serialize_script(mtx.vin.at(index).scriptSig);
            length2 = hex.length()/2;
            hex2 = to_varint(length2);
            result += "Script Length = "+std::to_string(length2)+"\n";
            result += "Script Length Hex = "+hex2+"\n";
            result += "Script = "+hex+"\n";

            /* Push Script Length */
            compressed_transaction += hex2;

            /* Push Script */
            compressed_transaction += hex;

            length2 = mtx.vin.at(index).scriptWitness.stack.size();

            /* Push Witness Count */
            hex = to_varint(length2);
            result += "Witness Script Count = "+std::to_string(length2)+"\n";
            result += "Witness Script Count Hex = "+hex+"\n";
            compressed_transaction += hex;

            for (index2 = 0; index2 < length2; index2++) {

                length3 = mtx.vin.at(index).scriptWitness.stack.at(index2).size();
                result += "Witness Script Length = "+std::to_string(length3)+"\n";

                /* Push Witness Length */
                hex = to_varint(length3);
                result += "Witness Script Length Hex = "+hex+"\n";
                compressed_transaction += hex;

                /* Push Witness Script */
                hex = bytes_to_hex(mtx.vin.at(index).scriptWitness.stack.at(index2));
                result += "Witness Script = "+hex+"\n";
                compressed_transaction += hex;

            }
        } else {
            result += "LEGACY/SEGWIT/TAPROOT\n";
            input_result = inputs.at(index);
            bytes = std::get<1>(input_result);
            hex = bytes_to_hex(bytes);

            /* Push Compressed Signature */
            hex2 = hex.substr(0, 128);
            result += "Compressed Signature = "+hex2+"\n";
            compressed_transaction += hex2;

            /* Push Signature Hash Type */
            hex3 = hex.substr(128, 2);
            result += "Signature Hash Type = "+hex3+"\n";
            compressed_transaction += hex3;
        }
    }
    result += "^^^^^^^^^INPUT^^^^^^^^^\n";

    length = mtx.vout.size();
    for (index = 0; index < length; index++) {
        output_result = outputs.at(index);
        output_type = std::get<0>(output_result);

        /* Encode Output Type 
            "000": Uncompressed Output Type, Encode Next Byte
        */
        if (output_type_bits == "000") {
            /* Push Output Type */
            hex = binary_to_hex("00000"+output_type);
            result += "Output Type Hex = "+hex+"\n";
            compressed_transaction += hex;
        }

        result += "Amuont = "+std::to_string(mtx.vout.at(index).nValue)+"\n";

        /* Push Amount */
        hex = to_varint(mtx.vout.at(index).nValue);
        result += "Amount Hex = "+hex+"\n";
        compressed_transaction += hex;

        /* Encode Output 
            "111": Uncompressed Output, Custom Script
            _: Push Script Hash Minus Op Code Bytes
        */
        if (output_type == "111") {
            hex = serialize_script(mtx.vout.at(index).scriptPubKey);
            length2 = hex.length();
            result += "Script Length = "+std::to_string(length2)+"\n";

            /* Push Script Length */
            hex2 = int_to_hex(length2);
            result += "Script Length Hex = "+hex2+"\n";
            compressed_transaction += hex2;

            /* Push Script */
            result += "Script = "+hex+"\n";
            compressed_transaction += hex;
        } else {
            result += "Script Type = "+output_type+"\n";
            /* Push Script*/
            hex = bytes_to_hex(std::get<1>(output_result));
            result += "Script = "+hex+"\n";
            compressed_transaction += hex;
        }

    }
    result += "^^^^^^^^^OUTPUT^^^^^^^^^\n";



    // result += "compressed_transaction = "+compressed_transaction+"\n";
    // rmtx = DecompressRawTransaction(compressed_transaction, active_chainstate, result);
    // result += "test ste = "+rmtx.GetHash().GetHex()+"\n";
    // result += "test set = "+mtx.GetHash().GetHex()+"\n";

    // if (rmtx.nVersion != mtx.nVersion) {
    //     result += "VERSION DOES NOT MATCH: "+std::to_string(rmtx.nVersion)+" != "+std::to_string(mtx.nVersion)+"\n";
    // }
    // if (rmtx.nLockTime != mtx.nLockTime) {
    //     result += "LOCKTIME DOES NOT MATCH: "+std::to_string(rmtx.nLockTime)+" != "+std::to_string(mtx.nLockTime)+"\n";
    // }
    // bool vin_valid = true;
    // if (rmtx.vin.size() != mtx.vin.size()) {
    //     result += "    LENGTHS VARY: "+std::to_string(rmtx.vin.size())+" != "+std::to_string(mtx.vin.size())+"\n";
    //     vin_valid = false;
    // }
    // length = std::max(rmtx.vin.size(), mtx.vin.size());
    // for (index = 0; index < length; index++) {
    //     result += "    INDEX: "+std::to_string(index)+"\n";
    //     length2 = mtx.vin.size();
    //     length3 = rmtx.vin.size();
    //     if (index < length2 && index < length3) {
    //         if (rmtx.vin.at(index).prevout != mtx.vin.at(index).prevout) {
    //             if (rmtx.vin.at(index).prevout.hash != mtx.vin.at(index).prevout.hash) {
    //                 result += "        PREVOUT HASH: "+rmtx.vin.at(index).prevout.hash.GetHex()+" != "+mtx.vin.at(index).prevout.hash.GetHex()+"\n";
    //                 vin_valid = false;
    //             }
    //             if (rmtx.vin.at(index).prevout.n != mtx.vin.at(index).prevout.n) {
    //                 result += "        PREVOUT N: "+std::to_string(rmtx.vin.at(index).prevout.n)+" != "+std::to_string(mtx.vin.at(index).prevout.n)+"\n";
    //                 vin_valid = false;
    //             }
    //         }
    //         if (serialize_script(rmtx.vin.at(index).scriptSig) != serialize_script(mtx.vin.at(index).scriptSig)) {
    //             result += "    SCRIPTSIG DOES NOT MATCH: "+serialize_script(rmtx.vin.at(index).scriptSig)+" != "+serialize_script(mtx.vin.at(index).scriptSig)+"\n";
    //             vin_valid = false;
    //         }
    //         if (rmtx.vin.at(index).nSequence != mtx.vin.at(index).nSequence) {
    //             result += "    SEQUENCE DOES NOT MATCH: "+std::to_string(rmtx.vin.at(index).nSequence)+" != "+std::to_string(mtx.vin.at(index).nSequence)+"\n";
    //             vin_valid = false;
    //         }
    //         if (rmtx.vin.at(index).scriptWitness.ToString() != mtx.vin.at(index).scriptWitness.ToString()) {
    //             result += "    SCRIPTWITNESS DOES NOT MATCH: "+rmtx.vin.at(index).scriptWitness.ToString()+" != "+mtx.vin.at(index).scriptWitness.ToString()+"\n";
    //             vin_valid = false;
    //         }
    //     } else if (index < length2) {
    //         result += "    NO VIN FOR RMTX\n";
    //         vin_valid = false;
    //     } else {
    //         result += "    NO VIN FOR MXT\n";
    //         vin_valid = false;
    //     }
    // }
    // if (rmtx.vout != mtx.vout) {
    //     result += "VOUT DOES NOT MATCH:\n";
    //     if (rmtx.vout.size() != mtx.vout.size()) {
    //         result += "    LENGTHS VARY: "+std::to_string(rmtx.vout.size())+" != "+std::to_string(mtx.vout.size())+"\n";
    //     } else {

    //     }
    //     length = std::max(rmtx.vout.size(), mtx.vout.size());
    //     for (index = 0; index < length; index++) {
    //         result += "    INDEX: "+std::to_string(index)+"\n";
    //         length2 = mtx.vout.size();
    //         length3 = rmtx.vout.size();
    //         if (index < length2 && index < length3) {
    //             if (serialize_script(rmtx.vout.at(index).scriptPubKey) != serialize_script(mtx.vout.at(index).scriptPubKey)) {
    //                 result += "    SCIRPTPUBKEY DOES NOT MATCH: "+serialize_script(rmtx.vout.at(index).scriptPubKey)+" != "+serialize_script(mtx.vout.at(index).scriptPubKey)+"\n";
    //             }
    //             if (rmtx.vout.at(index).nValue != mtx.vout.at(index).nValue) {
    //                 result += "    VALUE DOES NOT MATCH: "+std::to_string(rmtx.vout.at(index).nValue)+" != "+std::to_string(mtx.vout.at(index).nValue)+"\n";
    //             }
    //         } else if (index < length2) {
    //             result += "    NO VOUT FOR RMTX\n";
    //         } else {
    //             result += "    NO VIN FOR MXT\n";
    //         }
    //     }
    // }
    // if (rmtx.nVersion == mtx.nVersion && rmtx.nLockTime == mtx.nLockTime && vin_valid && rmtx.vout == mtx.vout) {
    //     result += "COMPLETED NO PROBLEMS\n";
    // }
    // result += "---------------------R------------------------\n";
    /* result contains DEBUG info up to this point */
    // result = compressed_transaction;
    transaction_result = compressed_transaction;
}