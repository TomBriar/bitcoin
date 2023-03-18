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
#include <logging.h>
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
#include <node/context.h>
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

int binary_to_int(std::string binary)
{
	std::cout << "bintest: " << binary.size() << " >= " << floor(log2(INT_MAX))+1 << std::endl;
	if (binary.size() >= floor(log2(INT_MAX))+1) {
		throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Binary String Interpretation larger then MAX_INT");
	}
    int i_byte = 0;
    int length = binary.length();
    for (int x = 0; x < length; x++) {
        if (binary.substr(x, 1) == "1") {
            i_byte += pow(2, ((length-1)-x));
        } 
    }
    return i_byte;
}

std::string binary_to_hex(std::string binary)
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

std::string int_to_hex(int64_t byte)
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

int get_first_push_bytes(std::vector<unsigned char>& data, CScript script) 
{
    opcodetype opcodeRet;

	data.clear();
    CScriptBase::const_iterator pc = script.begin();

    while (pc < script.end()) 
    {   
        script.GetOp(pc, opcodeRet, data);
        if (data.size() > 0) {
            return 1;
        } 
    }
    return 0;
}

static int compress_signature(secp256k1_context* ctx, std::vector<unsigned char>& vchRet)
{
	std::cout << "sig to compress = " << HexStr(vchRet) << std::endl;
//TODO: if (!vchRet) return 0;
    
    unsigned char hash_type = vchRet.back();
    int length = vchRet.size()-1;
    secp256k1_ecdsa_signature sig;
    int r = secp256k1_ecdsa_signature_parse_der(ctx, &sig, &vchRet[0], length);
    if (r) {
        int r = secp256k1_ecdsa_signature_serialize_compact(ctx, &vchRet[0], &sig);
        if (r) {
            vchRet[64] = hash_type;
			vchRet.resize(65);
            return 1;
        }
    }
    return 0;
}

InputScriptType get_input_type(secp256k1_context* ctx, CTxIn input, CTransactionRef tx, std::vector<unsigned char>& vchRet)
{
    CScript scriptPubKey = (*tx).vout.at(input.prevout.n).scriptPubKey;
	
    /* P2SH and P2WSH are uncompressable */
    if (scriptPubKey.IsPayToScriptHash() || scriptPubKey.IsPayToWitnessScriptHash()) {
        std::cout << "get_input_type = P2SH|P2PWSH" << std::endl;
        return CustomInput;
    }

	if (scriptPubKey.IsPayToPublicKeyHash()) {
        std::cout << "get_input_type = Legacy" << std::endl;
		std::cout << "input.scriptSig = " << HexStr(input.scriptSig) << std::endl;
		assert(get_first_push_bytes(vchRet, input.scriptSig));
		int r =	compress_signature(ctx, vchRet);
		if (!r) return CustomInput;
		return Legacy;
	}

	if (scriptPubKey.IsPayToWitnessPublicKeyHash()) {
        std::cout << "get_input_type = Segwit" << std::endl;
		vchRet = input.scriptWitness.stack.at(0);
		int r =	compress_signature(ctx, vchRet);
		if (!r) return CustomInput;
		return Segwit;
	}

	if (scriptPubKey.IsPayToTaproot()) {
        std::cout << "get_input_type = TAPROOT" << std::endl;
		vchRet = input.scriptWitness.stack.at(0);
		return Taproot;
	}
	
	std::cout << "get_input_type = Custom Script, fall through" << std::endl;
	return CustomInput;
}


OutputScriptType get_output_type(CScript script_pubkey, std::vector<unsigned char>& vchRet)
{
	get_first_push_bytes(vchRet, script_pubkey);

	if (script_pubkey.IsPayToPublicKey()) {
		return P2PK;
	}
	if (script_pubkey.IsPayToScriptHash()) {
		return P2SH;
	}
	if (script_pubkey.IsPayToPublicKeyHash()) {
		return P2PKH;
	}
	if (script_pubkey.IsPayToWitnessPublicKeyHash()) {
		return P2WPKH;
	}
	if (script_pubkey.IsPayToWitnessScriptHash()) {
		return P2WSH;
	}
	if (script_pubkey.IsPayToTaproot()) {
		return P2TR;
	}
	return CustomOutput;
}

std::vector<unsigned char> hex_to_bytes(std::string hex) {
    int index, length;
    unsigned char byte;
    std::vector<unsigned char> r;
    length = hex.length() / 2;
    for (index = 0; index < length; index++) {
		byte = std::stoul(hex.substr(index*2, 2), nullptr, 16);
        r.push_back(byte);
    }
    return r;
}



std::string hex_to_binary(std::string hex)
{
	std::vector<unsigned char> r;
    assert(hex.length() == 2);
    int byte = std::stoul(hex, nullptr, 16);
    r.push_back(byte);
    return std::bitset<8>(byte).to_string();
}

std::vector<unsigned char> to_varint(uint64_t value)
{
	CDataStream varint_ss(SER_DISK, 0);
	varint_ss << VARINT(value);
	std::vector<std::byte> varint(varint_ss.size());
	varint_ss.read(varint);
	std::vector<unsigned char> uc_varint = reinterpret_cast<std::vector<unsigned char> &&> (varint);
	return uc_varint;
			
////std::vector<unsigned char> result;
////int index = 0;
////std::string binary = std::bitset<64>(intager).to_string();
////binary.erase(0, binary.find_first_not_of('0'));
////if (binary.length() == 0) {
////	result.push_back(0x00);
////    return result;
////}
////float fint = binary.length();
////fint /= 7;
////int varlen = ceil(fint);
////int padding = (7*varlen)-binary.length();
////if (varlen > 1) {
////	unsigned char byte = 0x80;
////	byte |=	binary_to_int(binary.substr(0, (7-padding)));
////	result.push_back(byte);

////    index += 7-padding;
////    for (int i = 1; i < varlen; i++) {
////		byte = 0;
////        if (i+1 != varlen) {
////			byte |= 0x80;
////		}
////        byte |= binary_to_int(binary.substr(index, 7));
////		result.push_back(byte);
////        index += 7;
////    }
////} else {
////    unsigned char byte = 0;
////    byte |=	binary_to_int(binary);
////	result.push_back(byte);
////}
////return result;
}

void checkSize(int size, int index) {
	std::cout << "size = " << size << std::endl;
	std::cout << "index = " << index << std::endl;
	if (size <= index || index < 0) {
		throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Compressed TX malformed or truncated");
	}
}

uint64_t from_varint(std::vector<unsigned char>& transaction_bytes, int& index) 
{
	std::vector<std::byte> b_varint = reinterpret_cast<std::vector<std::byte> &&> (transaction_bytes);
	CDataStream varint_ss(SER_DISK, 0);
	varint_ss.write(b_varint);
	uint64_t value = std::numeric_limits<uint64_t>::max();
	varint_ss >> VARINT(value);
	return value;
	
////std::string r;
////bool end = false;
////std::cout << "varint = " << std::endl;
////for (; ;) {
////	checkSize(transaction_bytes.size(), index+1);
////	unsigned char byte = transaction_bytes.at(index);
////	std::cout << "	: " << int_to_hex(byte) << std::endl;
////    index += 1;
////    std::string binary = std::bitset<8>(byte).to_string();
////    if (binary.substr(0, 1) == "0") {
////        end = true;
////    }
////    r += binary.substr(1, 7);
////    if (end) {
////        break;
////    }
////}
////return binary_to_int(r);
}
