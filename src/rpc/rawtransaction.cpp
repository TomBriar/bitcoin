// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <index/txindex.h>
#include <key_io.h>
#include <node/blockstorage.h>
#include <node/chainstate.h>
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
#include <undo.h>
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

#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>

using node::AnalyzePSBT;
using node::FindCoins;
using node::GetTransaction;
using node::NodeContext;
using node::PSBTAnalysis;
using node::ReadBlockFromDisk;
using node::UndoReadFromDisk;
using node::BlockManager;

static void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry, Chainstate& active_chainstate, const CTxUndo* txundo = nullptr, TxVerbosity verbosity = TxVerbosity::SHOW_TXID)
{
    // Call into TxToUniv() in bitcoin-common to decode the transaction hex.
    //
    // Blockchain contextual information (confirmations and blocktime) is not
    // available to code in bitcoin-common, so we query them here and push the
    // data into the returned UniValue.
    TxToUniv(tx, /*block_hash=*/uint256(), entry, /*include_hex=*/true, RPCSerializationFlags(), txundo, verbosity);

    if (!hashBlock.IsNull()) {
        LOCK(cs_main);

        entry.pushKV("blockhash", hashBlock.GetHex());
        const CBlockIndex* pindex = active_chainstate.m_blockman.LookupBlockIndex(hashBlock);
        if (pindex) {
            if (active_chainstate.m_chain.Contains(pindex)) {
                entry.pushKV("confirmations", 1 + active_chainstate.m_chain.Height() - pindex->nHeight);
                entry.pushKV("time", pindex->GetBlockTime());
                entry.pushKV("blocktime", pindex->GetBlockTime());
            }
            else
                entry.pushKV("confirmations", 0);
        }
    }
}

static std::vector<RPCResult> ScriptPubKeyDoc() {
    return
         {
             {RPCResult::Type::STR, "asm", "Disassembly of the public key script"},
             {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
             {RPCResult::Type::STR_HEX, "hex", "The raw public key script bytes, hex-encoded"},
             {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitcoin address (only if a well-defined address exists)"},
             {RPCResult::Type::STR, "type", "The type (one of: " + GetAllOutputTypes() + ")"},
         };
}

static std::vector<RPCResult> DecodeTxDoc(const std::string& txid_field_doc)
{
    return {
        {RPCResult::Type::STR_HEX, "txid", txid_field_doc},
        {RPCResult::Type::STR_HEX, "hash", "The transaction hash (differs from txid for witness transactions)"},
        {RPCResult::Type::NUM, "size", "The serialized transaction size"},
        {RPCResult::Type::NUM, "vsize", "The virtual transaction size (differs from size for witness transactions)"},
        {RPCResult::Type::NUM, "weight", "The transaction's weight (between vsize*4-3 and vsize*4)"},
        {RPCResult::Type::NUM, "version", "The version"},
        {RPCResult::Type::NUM_TIME, "locktime", "The lock time"},
        {RPCResult::Type::ARR, "vin", "",
        {
            {RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "coinbase", /*optional=*/true, "The coinbase value (only if coinbase transaction)"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "The transaction id (if not coinbase transaction)"},
                {RPCResult::Type::NUM, "vout", /*optional=*/true, "The output number (if not coinbase transaction)"},
                {RPCResult::Type::OBJ, "scriptSig", /*optional=*/true, "The script (if not coinbase transaction)",
                {
                    {RPCResult::Type::STR, "asm", "Disassembly of the signature script"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw signature script bytes, hex-encoded"},
                }},
                {RPCResult::Type::ARR, "txinwitness", /*optional=*/true, "",
                {
                    {RPCResult::Type::STR_HEX, "hex", "hex-encoded witness data (if any)"},
                }},
                {RPCResult::Type::NUM, "sequence", "The script sequence number"},
            }},
        }},
        {RPCResult::Type::ARR, "vout", "",
        {
            {RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "value", "The value in " + CURRENCY_UNIT},
                {RPCResult::Type::NUM, "n", "index"},
                {RPCResult::Type::OBJ, "scriptPubKey", "", ScriptPubKeyDoc()},
            }},
        }},
    };
}

static std::vector<RPCArg> CreateTxDoc()
{
    return {
        {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The inputs",
            {
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                    {
                        {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                        {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                        {"sequence", RPCArg::Type::NUM, RPCArg::DefaultHint{"depends on the value of the 'replaceable' and 'locktime' arguments"}, "The sequence number"},
                    },
                },
            },
        },
        {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The outputs (key-value pairs), where none of the keys are duplicated.\n"
                "That is, each address can only appear once and there can only be one 'data' object.\n"
                "For compatibility reasons, a dictionary, which holds the key-value pairs directly, is also\n"
                "                             accepted as second parameter.",
            {
                {"", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::OMITTED, "",
                    {
                        {"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "A key-value pair. The key (string) is the bitcoin address, the value (float or string) is the amount in " + CURRENCY_UNIT},
                    },
                },
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                    {
                        {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A key-value pair. The key must be \"data\", the value is hex-encoded data"},
                    },
                },
            },
        },
        {"locktime", RPCArg::Type::NUM, RPCArg::Default{0}, "Raw locktime. Non-0 value also locktime-activates inputs"},
        {"replaceable", RPCArg::Type::BOOL, RPCArg::Default{true}, "Marks this transaction as BIP125-replaceable.\n"
                "Allows this transaction to be replaced by a transaction with higher fees. If provided, it is an error if explicit sequence numbers are incompatible."},
    };
}

static RPCHelpMan getrawtransaction()
{
    return RPCHelpMan{
                "getrawtransaction",

                "By default, this call only returns a transaction if it is in the mempool. If -txindex is enabled\n"
                "and no blockhash argument is passed, it will return the transaction if it is in the mempool or any block.\n"
                "If a blockhash argument is passed, it will return the transaction if\n"
                "the specified block is available and the transaction is in that block.\n\n"
                "Hint: Use gettransaction for wallet transactions.\n\n"

                "If verbosity is 0 or omitted, returns the serialized transaction as a hex-encoded string.\n"
                "If verbosity is 1, returns a JSON Object with information about the transaction.\n"
                "If verbosity is 2, returns a JSON Object with information about the transaction, including fee and prevout information.",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                    {"verbosity|verbose", RPCArg::Type::NUM, RPCArg::Default{0}, "0 for hex-encoded data, 1 for a JSON object, and 2 for JSON object with fee and prevout"},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED_NAMED_ARG, "The block in which to look for the transaction"},
                },
                {
                    RPCResult{"if verbosity is not set or set to 0",
                         RPCResult::Type::STR, "data", "The serialized transaction as a hex-encoded string for 'txid'"
                     },
                     RPCResult{"if verbosity is set to 1",
                         RPCResult::Type::OBJ, "", "",
                         Cat<std::vector<RPCResult>>(
                         {
                             {RPCResult::Type::BOOL, "in_active_chain", /*optional=*/true, "Whether specified block is in the active chain or not (only present with explicit \"blockhash\" argument)"},
                             {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "the block hash"},
                             {RPCResult::Type::NUM, "confirmations", /*optional=*/true, "The confirmations"},
                             {RPCResult::Type::NUM_TIME, "blocktime", /*optional=*/true, "The block time expressed in " + UNIX_EPOCH_TIME},
                             {RPCResult::Type::NUM, "time", /*optional=*/true, "Same as \"blocktime\""},
                             {RPCResult::Type::STR_HEX, "hex", "The serialized, hex-encoded data for 'txid'"},
                         },
                         DecodeTxDoc(/*txid_field_doc=*/"The transaction id (same as provided)")),
                    },
                    RPCResult{"for verbosity = 2",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::ELISION, "", "Same output as verbosity = 1"},
                            {RPCResult::Type::NUM, "fee", /*optional=*/true, "transaction fee in " + CURRENCY_UNIT + ", omitted if block undo data is not available"},
                            {RPCResult::Type::ARR, "vin", "",
                            {
                                {RPCResult::Type::OBJ, "", "utxo being spent, omitted if block undo data is not available",
                                {
                                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 1"},
                                    {RPCResult::Type::OBJ, "prevout", /*optional=*/true, "Only if undo information is available)",
                                    {
                                        {RPCResult::Type::BOOL, "generated", "Coinbase or not"},
                                        {RPCResult::Type::NUM, "height", "The height of the prevout"},
                                        {RPCResult::Type::STR_AMOUNT, "value", "The value in " + CURRENCY_UNIT},
                                        {RPCResult::Type::OBJ, "scriptPubKey", "", ScriptPubKeyDoc()},
                                    }},
                                }},
                            }},
                        }},
                },
                RPCExamples{
                    HelpExampleCli("getrawtransaction", "\"mytxid\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 1")
            + HelpExampleRpc("getrawtransaction", "\"mytxid\", 1")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 0 \"myblockhash\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 1 \"myblockhash\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 2 \"myblockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);

    uint256 hash = ParseHashV(request.params[0], "parameter 1");
    const CBlockIndex* blockindex = nullptr;

    if (hash == chainman.GetParams().GenesisBlock().hashMerkleRoot) {
        // Special exception for the genesis block coinbase transaction
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved");
    }

    // Accept either a bool (true) or a num (>=0) to indicate verbosity.
    int verbosity{0};
    if (!request.params[1].isNull()) {
        if (request.params[1].isBool()) {
            verbosity = request.params[1].get_bool();
        } else {
            verbosity = request.params[1].getInt<int>();
        }
    }

    if (!request.params[2].isNull()) {
        LOCK(cs_main);

        uint256 blockhash = ParseHashV(request.params[2], "parameter 3");
        blockindex = chainman.m_blockman.LookupBlockIndex(blockhash);
        if (!blockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block hash not found");
        }
    }

    bool f_txindex_ready = false;
    if (g_txindex && !blockindex) {
        f_txindex_ready = g_txindex->BlockUntilSyncedToCurrentChain();
    }

    uint256 hash_block;
    const CTransactionRef tx = GetTransaction(blockindex, node.mempool.get(), hash, chainman.GetConsensus(), hash_block);
    if (!tx) {
        std::string errmsg;
        if (blockindex) {
            const bool block_has_data = WITH_LOCK(::cs_main, return blockindex->nStatus & BLOCK_HAVE_DATA);
            if (!block_has_data) {
                throw JSONRPCError(RPC_MISC_ERROR, "Block not available");
            }
            errmsg = "No such transaction found in the provided block";
        } else if (!g_txindex) {
            errmsg = "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries";
        } else if (!f_txindex_ready) {
            errmsg = "No such mempool transaction. Blockchain transactions are still in the process of being indexed";
        } else {
            errmsg = "No such mempool or blockchain transaction";
        }
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errmsg + ". Use gettransaction for wallet transactions.");
    }

    if (verbosity <= 0) {
        return EncodeHexTx(*tx, RPCSerializationFlags());
    }

    UniValue result(UniValue::VOBJ);
    if (blockindex) {
        LOCK(cs_main);
        result.pushKV("in_active_chain", chainman.ActiveChain().Contains(blockindex));
    }
    // If request is verbosity >= 1 but no blockhash was given, then look up the blockindex
    if (request.params[2].isNull()) {
        LOCK(cs_main);
        blockindex = chainman.m_blockman.LookupBlockIndex(hash_block);
    }
    if (verbosity == 1) {
        TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate());
        return result;
    }

    CBlockUndo blockUndo;
    CBlock block;
    const bool is_block_pruned{WITH_LOCK(cs_main, return chainman.m_blockman.IsBlockPruned(blockindex))};

    if (tx->IsCoinBase() ||
        !blockindex || is_block_pruned ||
        !(UndoReadFromDisk(blockUndo, blockindex) && ReadBlockFromDisk(block, blockindex, Params().GetConsensus()))) {
        TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate());
        return result;
    }

    CTxUndo* undoTX {nullptr};
    auto it = std::find_if(block.vtx.begin(), block.vtx.end(), [tx](CTransactionRef t){ return *t == *tx; });
    if (it != block.vtx.end()) {
        // -1 as blockundo does not have coinbase tx
        undoTX = &blockUndo.vtxundo.at(it - block.vtx.begin() - 1);
    }
    TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate(), undoTX, TxVerbosity::SHOW_DETAILS_AND_PREVOUT);
    return result;
},
    };
}

static RPCHelpMan createrawtransaction()
{
    return RPCHelpMan{"createrawtransaction",
                "\nCreate a transaction spending the given inputs and creating new outputs.\n"
                "Outputs can be addresses or data.\n"
                "Returns hex-encoded raw transaction.\n"
                "Note that the transaction's inputs are not signed, and\n"
                "it is not stored in the wallet or transmitted to the network.\n",
                CreateTxDoc(),
                RPCResult{
                    RPCResult::Type::STR_HEX, "transaction", "hex string of the transaction"
                },
                RPCExamples{
                    HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"address\\\":0.01}]\"")
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"data\\\":\\\"00010203\\\"}]\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"[{\\\"address\\\":0.01}]\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"[{\\\"data\\\":\\\"00010203\\\"}]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {
        UniValue::VARR,
        UniValueType(), // ARR or OBJ, checked later
        UniValue::VNUM,
        UniValue::VBOOL
        }, true
    );

    std::optional<bool> rbf;
    if (!request.params[3].isNull()) {
        rbf = request.params[3].get_bool();
    }
    CMutableTransaction rawTx = ConstructTransaction(request.params[0], request.params[1], request.params[2], rbf);

    return EncodeHexTx(CTransaction(rawTx));
},
    };
}

static RPCHelpMan decoderawtransaction()
{
    return RPCHelpMan{"decoderawtransaction",
                "Return a JSON object representing the serialized, hex-encoded transaction.",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hex string"},
                    {"iswitness", RPCArg::Type::BOOL, RPCArg::DefaultHint{"depends on heuristic tests"}, "Whether the transaction hex is a serialized witness transaction.\n"
                        "If iswitness is not present, heuristic tests will be used in decoding.\n"
                        "If true, only witness deserialization will be tried.\n"
                        "If false, only non-witness deserialization will be tried.\n"
                        "This boolean should reflect whether the transaction has inputs\n"
                        "(e.g. fully valid, or on-chain transactions), if known by the caller."
                    },
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    DecodeTxDoc(/*txid_field_doc=*/"The transaction id"),
                },
                RPCExamples{
                    HelpExampleCli("decoderawtransaction", "\"hexstring\"")
            + HelpExampleRpc("decoderawtransaction", "\"hexstring\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VBOOL});

    CMutableTransaction mtx;

    bool try_witness = request.params[1].isNull() ? true : request.params[1].get_bool();
    bool try_no_witness = request.params[1].isNull() ? true : !request.params[1].get_bool();

    if (!DecodeHexTx(mtx, request.params[0].get_str(), try_no_witness, try_witness)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    UniValue result(UniValue::VOBJ);
    TxToUniv(CTransaction(std::move(mtx)), /*block_hash=*/uint256(), /*entry=*/result, /*include_hex=*/false);

    return result;
},
    };
}


/* Get Input Type 
    "00": Custom Script
    "01": Legacy Script
    "10": Segwit Script
    "11": Taproot Script
*/
std::tuple<std::string, std::vector<unsigned char>> get_input_type(CTxIn input, std::string& result)
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
        result += "get_input_type = P2SH|P2PWSH\n";
        return std::make_tuple("00", vchRet);
    }
	
	/* If both scriptSig and Witness are not Null then this is a custom script */
	if (!input.scriptWitness.IsNull() && input.scriptSig.GetSigOpCount(true) != 0) {
		result += "get_input_type = Custom Script, witness and scriptsig\n";
    	return std::make_tuple("00", vchRet);
	}

    if (!input.scriptWitness.IsNull() && input.scriptSig.GetSigOpCount(true) == 0) {
        length = input.scriptWitness.stack.size();
        if (length == 1 && scriptPubKey.IsPayToTaproot()) {
            result += "get_input_type =	TAPROOT\n";
            return std::make_tuple("11", input.scriptWitness.stack.at(0));
        } else if (length == 2) {
            /* If the Witness has two entries and the first is an ECDSA Sginature then Input Type is Segwit */
            vchRet = input.scriptWitness.stack.at(0);
            test_ecdsa_result = test_ecdsa_sig(vchRet, result);
            r = std::get<0>(test_ecdsa_result);
            if (r) {
				result += "get_input_type = P2WPKH\n";
                vchRet = std::get<1>(test_ecdsa_result);
                return std::make_tuple("10", vchRet);
            }
        }
        /* Witness Can Only be ECDSA or SCHNORR signature, Custom Otherwise */
		result += "get_input_type = Custom Script, witness but not ecdsa or taproot\n";
        return std::make_tuple("00", vchRet);
    } else {
        /* If ScriptSig contains an ECDSA Signature then Input Type is Legacy. */
        CScriptBase::const_iterator pc = input.scriptSig.begin();
        if (!input.scriptSig.GetOp(pc, opcodeRet, vchRet)) {
			result += "get_input_type = Custom Script, no script sig\n";
            return std::make_tuple("00", vchRet);
        };
       
        test_ecdsa_result = test_ecdsa_sig(vchRet, result);
        r = std::get<0>(test_ecdsa_result);
        if (r) {
            vchRet = std::get<1>(test_ecdsa_result);
			result += "get_input_type = LEGACY\n";
            return std::make_tuple("01", vchRet);
        }
    }
	
	result += "get_input_type = Custom Script, fall through\n";
    return std::make_tuple("00", vchRet);
}

static RPCHelpMan compressrawtransaction()
{
    return RPCHelpMan{"compressrawtransaction",
        "Return a String representing the compressed, serialized, hex-encoded transaction.",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hex string"}
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "compressed-transaction", "The compressed, serialized, hex-encoded transaction string"
        },
        RPCExamples{
            HelpExampleCli("compressrawtransaction", "\"hexstring\"") + 
            HelpExampleRpc("compressrawtransaction", "\"hexstring\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VBOOL});

            CMutableTransaction mtx, rmtx;
            std::string result, transaction_result;
			std::vector<unsigned char> transaction_result_bytes;

            if (!DecodeHexTx(mtx, request.params[0].get_str(), true, true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }

            NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);
            Chainstate& active_chainstate = chainman.ActiveChainstate();
            active_chainstate.ForceFlushStateToDisk();
			BlockManager* blockman = &active_chainstate.m_blockman;

			unsigned char info_byte_test = 0;
			
			/* Encode Version
				Encode the version as binary if its less then 4, Otherwise we'll encode the version as a VarInt later. 
			*/
			//std::string version_bits;
			switch(mtx.nVersion)
			{
				case 1: 
				{
					info_byte_test += 1 << 1;
					//version_bits = "01";
					break;
				};
				case 2: 
				{
					info_byte_test += 1 << 0;
					//version_bits = "10";
					break;
				};
				case 3: 
				{
					info_byte_test += 1 << 0;
					info_byte_test += 1 << 1;
					//version_bits = "11";
					break;
				};
			}

			/* Encode coinbase bool
				4294967295 is the vout associated with a coinbase transaction, Therefore minimal compression is avaible. 
			*/
			bool coinbase;
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
			result += "coinbase = "+std::to_string(coinbase)+"\n";

			/* Encode Input Count
				Encode the Input Count as binary if its less then 4, Otherwise we'll encode the Input Count as a VarInt later. 
			*/
			//std::string input_count_bits;
			switch(mtx.vin.size())
			{
				case 1:
				{
					info_byte_test += 1 << 3;
					//input_count_bits = "01";
					break;
				}
				case 2:
				{
					info_byte_test += 1 << 2;
					//input_count_bits = "10";
					break;
				}
				case 3:
				{
					info_byte_test += 1 << 2;
					info_byte_test += 1 << 3;
					//input_count_bits = "11";
					break;
				}
			}

			/* Encode Output Count
				Encode the Output Count as binary if its less then 4, Otherwise we'll encode the Output Count as a VarInt later. 
			*/
			std::string output_count_bits;
			switch(mtx.vout.size())
			{
				case 1:
				{
					info_byte_test += 1 << 5;
					//output_count_bits = "01";
					break;
				}
				case 2:
				{
					info_byte_test += 1 << 4;
					//output_count_bits = "10";
					break;
				}
				case 3:
				{
					info_byte_test += 1 << 4;
					info_byte_test += 1 << 5;
					//output_count_bits = "11";
					break;
				}
			}


			/* Encode Input Type 
				"00": More then 3 Inputs, Non Identical Scripts, At least one Input is of Custom Type. 
				"01": Less then 4 Inputs, Non Identical Scripts, At least one Input is of Custom Type. 
				"10": Identical Script Types, Custom Script.
				"11": Identical Script Types, Legacy, Segwit, or Taproot.
			*/
			std::vector<std::tuple<std::string, std::vector<unsigned char>>> inputs;
			std::string input_type_bits, input_type, input_type_second;

			if (!coinbase) {
				bool input_type_identical = true;
				std::tuple<std::string, std::vector<unsigned char>> input_result = get_input_type(mtx.vin.at(0), result);
				inputs.push_back(input_result);
				input_type = std::get<0>(input_result);
				result += "input_type = "+input_type+"\n";
				int input_length = mtx.vin.size();
				for (int input_index = 1; input_index < input_length; input_index++) {
					input_result = get_input_type(mtx.vin.at(input_index), result);
					std::string input_type_second = std::get<0>(input_result);
					result += "input_type = "+input_type_second+"\n";
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
					input_type_bits = "00";
				} else if (!input_type_identical && input_count_bits != "00") {
					input_type_bits = "01";
				}
			} else {
				input_type_bits = "10";
				input_type = "00";
			}


			/* Encode Lock Time
				"00": If locktime is 0 enocde that in the control byte.
				"11": If locktime is non zero but this is a coinbase transaction, or if this is a custom input input only transaction, Then no compresion is avaible for the locktime.
				"01": If locktime is non zero and not a coinbase transaction transmite the two least significant bytes of the locktime and we'll brute force the remaninig bytes in the decoding.
			*/
			result += "Locktime = "+std::to_string(mtx.nLockTime)+"\n";
			std::string locktime_bits;
			switch(mtx.nLockTime) 
			{
				case 0: 
				{
					locktime_bits = "00";
					break;
				}
				default: 
				{
					if (coinbase || input_type_bits == "10") {
						locktime_bits = "11";
					} else {
						locktime_bits = "01";
					}
					break;
				};
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
			std::string info_byte = version_bits;
			info_byte += locktime_bits;
			info_byte += input_count_bits;
			info_byte += output_count_bits;

			result += "Info Byte = "+info_byte+"\n";

			/* Push the Info Byte to the Result */
			std::string hex = binary_to_hex(info_byte);
			result += "Info Byte Hex = "+hex+"\n";
			std::string compressed_transaction = hex;

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
				int limit = pow(2, 16);
				std::string binary = std::bitset<16>(mtx.nLockTime % limit).to_string();
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
			std::vector<uint32_t> sequences;
			bool identical_sequnce = true;
			bool standard_sequence = true;
			std::string sequence_bits;

			sequences.push_back(mtx.vin.at(0).nSequence);
			if (sequences.at(0) != 0x00000000 || sequences.at(0) != 0xFFFFFFF0 || sequences.at(0) != 0xFFFFFFFE || sequences.at(0) != 0xFFFFFFFF) {
				standard_sequence = false;
			}
			int input_length = mtx.vin.size();
			for (int input_index = 1; input_index < input_length; input_index++) {
				if (mtx.vin.at(input_index).nSequence != sequences.at(0)) {
					identical_sequnce = false;
				}
				if (mtx.vin.at(input_index).nSequence != 0x00000000 || mtx.vin.at(input_index).nSequence != 0xFFFFFFF0 || mtx.vin.at(input_index).nSequence != 0xFFFFFFFE || mtx.vin.at(input_index).nSequence != 0xFFFFFFFF) {
					standard_sequence = false;
				}
				if (input_count_bits != "00") {
					sequences.push_back(mtx.vin.at(input_index).nSequence);
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
			std::vector<std::tuple<std::string, std::vector<unsigned char>>> outputs;
			std::tuple<std::string, std::vector<unsigned char>> output_result;
			std::string output_type, output_type_second, output_type_bits;
			bool output_type_identical = true;

			output_result = get_output_type(mtx.vout.at(0), result);
			outputs.push_back(output_result);
			output_type = std::get<0>(output_result);
			int output_length = mtx.vout.size();
			for (int output_index = 1; output_index < output_length; output_index++) {
				output_result = get_output_type(mtx.vout.at(output_index), result);
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
			std::string io_byte = sequence_bits;
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
				std::string binary = "";
				int sequence_length = sequences.size();
				for (int sequence_index = 0; sequence_index < sequence_length; sequence_index++) {
					switch(sequences.at(sequence_index))
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
				int binary_length = 8-binary.length();
				for (int binary_index = 0; binary_index < binary_length; binary_index++){
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
				std::string binary = "";
				int input_length = inputs.size();
				for (int input_index = 0; input_index < input_length; input_index++) {
					std::tuple<std::string, std::vector<unsigned char>> input_result = inputs.at(input_index);
					input_type = std::get<0>(input_result);
					result += "input_type("+std::to_string(input_index)+") = "+input_type+"\n";
					binary += input_type;
				}
				int binary_length = 8-hex.length();
				for (int binary_index = 0; binary_index < binary_length; binary_index++) {
					binary += "00";
				}

				/* Push Input Type Byte */
				hex = binary_to_hex(binary);
				result += "Encoded Input Type Byte Hex = "+hex+"\n";
				compressed_transaction += hex;
			}
			result += "^^^^^^^^^IO BYTE^^^^^^^^^\n";
			

			/* Encode Coinbase Byte 
				"x": Coinbase Encoding
			*/
			std::string coinbase_bits = std::to_string(coinbase);
			result += "coinbase_bits = "+std::to_string(coinbase)+"\n";
			std::string cb_byte = coinbase_bits;
			cb_byte += "0000000";

			/* Push the CB Byte to the Result */
			hex = binary_to_hex(cb_byte);
			result += "CB Byte Hex = "+hex+"\n";
			compressed_transaction += hex;


			result += "^^^^^^^^^CB BYTE^^^^^^^^^^\n";
			input_length = mtx.vin.size();
			result += "length = "+std::to_string(input_length)+"\n";
			for (int input_index = 0; input_index < input_length; input_index++) {
				result += "---index = "+std::to_string(input_index)+"\n";

				/* Encode Sequence 
					"000": Uncompressed Sequence, Encode VarInt
				*/
				if (sequence_bits == "000") {
					/* Push Sequence */
					hex = to_varint(mtx.vin.at(input_index).nSequence);
					result += "Sequence = "+std::to_string(mtx.vin.at(input_index).nSequence)+"\n";
					result += "Sequence Hex = "+hex+"\n";
					compressed_transaction += hex;
				}

				/* Encode Input Type
					"00": Uncompressed Input Type, Encode Next Byte
				*/
				if (input_type_bits == "00") {
					std::tuple<std::string, std::vector<unsigned char>> input_result = inputs.at(input_index);
					input_type = std::get<0>(input_result);
					/* Push Input Type */
					hex = binary_to_hex("000000"+input_type);
					result += "Input Type Hex = "+hex+"\n";
					compressed_transaction += hex;
				} 
				if (!coinbase) {
					/* Encode TXID Block Index/Height 
						If Not CoinBase: Encode TXID as its Block Index/Height
					*/
					Consensus::Params consensus_params;
					uint256 hash;
					CTransactionRef tr = GetTransaction(nullptr, nullptr, mtx.vin.at(input_index).prevout.hash, consensus_params, hash);
					uint256 txid;
					txid = (*tr).GetHash();
					std::vector<std::shared_ptr<const CTransaction>>::iterator itr;
					const CBlockIndex* pindex{nullptr};
					pindex = blockman->LookupBlockIndex(hash);
					int block_height = pindex->nHeight;
					result += "Block Hash = "+pindex->GetBlockHash().GetHex()+"\n";
					CBlock block;
					ReadBlockFromDisk(block, pindex, consensus_params);
					bool txid_found = false;
					int blocks_length = block.vtx.size();
					for (int blocks_index = 0; blocks_index < blocks_length; blocks_index++) {
						if ((*block.vtx.at(blocks_index)).GetHash() == txid) {
							txid_found = true;
							int block_index = blocks_index;

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
							break;
						}
					}
					/* Encode TXID 
						If Block Index/Height Was Found: Encode TXID as its Block Index/Height
					*/
					if (!txid_found) {
						/* Push the TXID */
						hex = mtx.vin.at(input_index).prevout.hash.GetHex();
						result += "Full TXID hex = "+hex+"\n";
						compressed_transaction += hex;
					}

					/* Push Vout */
					hex = to_varint(mtx.vin.at(input_index).prevout.n);
					result += "Vout = "+std::to_string(mtx.vin.at(input_index).prevout.n)+"\n";
					result += "VarInt Vout Hex = "+hex+"\n";
					compressed_transaction += hex;
				}

				/* Encode Input 
					"00": Custom Input
					_: Compressed Input
				*/
				if (input_type == "00") {
					hex = serialize_script(mtx.vin.at(input_index).scriptSig);
					int script_length = hex.length()/2;
					std::string hex2 = to_varint(script_length);
					result += "Script Length = "+std::to_string(script_length)+"\n";
					result += "Script Length Hex = "+hex2+"\n";
					result += "Script = "+hex+"\n";

					/* Push Script Length */
					compressed_transaction += hex2;

					/* Push Script */
					compressed_transaction += hex;

					int witness_count = mtx.vin.at(input_index).scriptWitness.stack.size();

					/* Push Witness Count */
					hex = to_varint(witness_count);
					result += "Witness Script Count = "+std::to_string(witness_count)+"\n";
					result += "Witness Script Count Hex = "+hex+"\n";
					compressed_transaction += hex;
					for (int witnesses_index = 0; witnesses_index < witness_count; witnesses_index++) {

						int witness_length = mtx.vin.at(input_index).scriptWitness.stack.at(witnesses_index).size();
						result += "Witness Script Length = "+std::to_string(witness_length)+"\n";

						/* Push Witness Length */
						hex = to_varint(witness_length);
						result += "Witness Script Length Hex = "+hex+"\n";
						compressed_transaction += hex;

						/* Push Witness Script */
						hex = bytes_to_hex(mtx.vin.at(input_index).scriptWitness.stack.at(witnesses_index));
						result += "Witness Script = "+hex+"\n";
						compressed_transaction += hex;

					}
				} else {
					result += "LEGACY/SEGWIT/TAPROOT\n";
					std::tuple<std::string, std::vector<unsigned char>> input_result = inputs.at(input_index);
					std::vector<unsigned char> bytes;
					bytes = std::get<1>(input_result);
					hex = bytes_to_hex(bytes);

					/* Push Compressed Signature */
					std::string hex2 = hex.substr(0, 128);
					result += "Compressed Signature = "+hex2+"\n";
					compressed_transaction += hex2;

					/* Push Signature Hash Type */
					std::string hex3 = hex.substr(128, 2);
					if (hex3 == "") {
						hex3 = "00";
					}
					result += "Signature Hash Type = "+hex3+"\n";
					compressed_transaction += hex3;
				}
			}
			result += "^^^^^^^^^INPUT^^^^^^^^^\n";
			output_length = mtx.vout.size();
			for (int output_index = 0; output_index < output_length; output_index++) {
				output_result = outputs.at(output_index);
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

				result += "Amuont = "+std::to_string(mtx.vout.at(output_index).nValue)+"\n";

				/* Push Amount */
				hex = to_varint(mtx.vout.at(output_index).nValue);
				result += "Amount Hex = "+hex+"\n";
				compressed_transaction += hex;

				/* Encode Output 
					"111": Uncompressed Output, Custom Script
					_: Push Script Hash Minus Op Code Bytes
				*/
				result += "Extended Script = "+serialize_script(mtx.vout.at(output_index).scriptPubKey)+"\n";
				if (output_type == "111") {
					hex = serialize_script(mtx.vout.at(output_index).scriptPubKey);
					int script_length = hex.length();
					result += "Script Length = "+std::to_string(script_length)+"\n";

					/* Push Script Length */
					std::string hex2 = int_to_hex(script_length);
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
			result += "--------------------R--------------------\n";
			return compressed_transaction+"|"+result;
        }
    };
}

static RPCHelpMan decompressrawtransaction()
{
    return RPCHelpMan{"decompressrawtransaction",
        "Return a String representing the decompressed, serialized, hex-encoded transaction.",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hex string"}
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "decompressed-transaction", "The decompressed, serialized, hex-encoded transaction string"
        },
        RPCExamples{
            HelpExampleCli("decompressrawtransaction", "\"hexstring\"") + 
            HelpExampleRpc("decompressrawtransaction", "\"hexstring\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VBOOL});

            CMutableTransaction mtx, rmtx;
            std::string result, transaction_result;

            NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);
            Chainstate& active_chainstate = chainman.ActiveChainstate();
            active_chainstate.ForceFlushStateToDisk();
			BlockManager* blockman = &active_chainstate.m_blockman;

			std::string compressed_transaction = request.params[0].get_str();

			result += "---------------------------------------------------\n";
			result += "compressed transaction = "+compressed_transaction+"\n";

			/* Init Vars */
			secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
			int transaction_index = 0;
			bool locktime_found = true;

			/* Parse Info Byte 
				"xx": Version Encoding
				"xx": LockTime Encoding
				"xx: Input Count
				"xx": Output Count
			*/
			std::string hex = compressed_transaction.substr(transaction_index, 2);
			transaction_index += 2;
			std::string info_byte = hex_to_binary(hex);

			std::string version_bits = info_byte.substr(0, 2);
			result += "version_bits = "+version_bits+"\n";

			std::string locktime_bits = info_byte.substr(2, 2);
			result += "locktime_bits = "+locktime_bits+"\n";

			std::string input_count_bits = info_byte.substr(4, 2);
			result += "input_count_bits = "+input_count_bits+"\n";

			std::string output_count_bits = info_byte.substr(6, 2);
			result += "output_count_bits = "+output_count_bits+"\n";

			result += "Info Byte = "+info_byte+"\n";
			result += "Info Byte Hex = "+hex+"\n";


			/* Parse Version 
				"00": Parse a VarInt
				_: Parse Binary of version_bits for version
			*/
			if (version_bits == "00") {
				std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
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
				std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
				mtx.nLockTime = std::get<0>(varint_result);
				transaction_index += std::get<1>(varint_result);
				result += "VarInt LockTime Hex Length = "+std::to_string(std::get<1>(varint_result))+"\n";
			}

			/* Parse Input Count 
				"00": Parse a VarInt
				_: Parse Binary of input_count_bits for Input Count
			*/
			int input_count;
			if (input_count_bits == "00") {
				std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
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
			int output_count;
			if (output_count_bits == "00") {
				std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
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
			std::string io_byte = hex_to_binary(hex);

			std::string sequence_bits = io_byte.substr(0, 3);
			result += "sequence_bits = "+sequence_bits+"\n";

			std::string input_type_bits = io_byte.substr(3, 2);
			result += "input_type_bits = "+input_type_bits+"\n";

			std::string output_type_bits = io_byte.substr(5, 3);
			result += "output_type_bits = "+output_type_bits+"\n";

			result += "Input Output Byte = "+io_byte+"\n";
			result += "Input Output Byte Hex = "+hex+"\n";

			int byte = binary_to_int("00000"+sequence_bits);

			/* Parse Sequnce 
				"000": Non Identical Sequences, Read Sequence Before Each Input
				"001": Parse Full Sequence From VarInt, All Sequences are Identical
				"010": Up to 4 Inputs had the Sequence Encoded in the Next Byte
				"011"-"110": Sequence is Identical and encoded in the Sequnce Bits
			*/ 
			std::vector<uint32_t> sequences;
			uint32_t sequence;
			result += "byte = "+std::to_string(byte)+"\n";
			switch(byte)
			{
				case 0:
				{
					break;
				}
				case 1: 
				{
					std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
					sequence = std::get<0>(varint_result);
					transaction_index += std::get<1>(varint_result);
					break;
				}
				case 2:
				{
					hex = compressed_transaction.substr(transaction_index, 2);
					result += "Encoded Sequence Byte Hex = "+hex+"\n";
					transaction_index += 2;
					std::string binary = hex_to_binary(hex);
					for (int input_index = 0; input_index < input_count; input_index++) {
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
			std::vector<std::string> input_types;
			if (input_type_bits == "01") {
				hex = compressed_transaction.substr(transaction_index, 2);
				result += "Encoded Input Type Byte Hex = "+hex+"\n";
				std::string binary = hex_to_binary(hex);
				transaction_index += 2;
				for (int input_type_index = 0; input_type_index < 4; input_type_index++) {
					result += "input_type("+std::to_string(input_type_index)+") = "+binary.substr(input_type_index, 2)+"\n";
					input_types.push_back(binary.substr(input_type_index, 2));
				}
			}
			result += "^^^^^^^^^IO BYTE^^^^^^^^^\n";
			/* Parse Coinbase Byte 
				"x": Coinbase Encoding
			*/
			hex = compressed_transaction.substr(transaction_index, 2);
			transaction_index += 2;
			std::string binary = hex_to_binary(hex);

			std::string coinbase_bits = binary.substr(0, 1);
			result += "coinbase_bits = "+coinbase_bits+"\n";

			/* Parse Coinbase */
			bool coinbase = binary_to_int("0000000"+coinbase_bits);

			result += "^^^^^^^^^CB BYTE^^^^^^^^^^\n";
		 	std::vector<int> half_finished_inputs, hash_types;
			std::vector<std::string> compressed_signatures;
			std::vector<CTxIn> vin;
			for (int input_index = 0; input_index < input_count; input_index++) {
				result += "---index = "+std::to_string(input_index)+"\n";
				// Clear Stack From Previous Iterations
				/* Parse Sequence 
					"000": Sequence was uncompressed, Read from VarInt
					"010": Sequence was Read Previously, Set Temp Var
				*/
				if (sequence_bits == "000") {
					std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
					sequence = std::get<0>(varint_result);
					transaction_index += std::get<1>(varint_result);
					result += "Sequence = "+std::to_string(sequence)+"\n";
				} else if (sequence_bits == "010") {
					sequence = sequences.at(input_index);
				}

				/* Parse Input Type 
					"00": Input Type Was Uncomrpessed Read Next Byte
					"01": Input Type Was Already Parsed, Set Temp Var
					"10": All Inputs Identical, Input is Custom Type
					"11": All Inputs Identical, Input is Compressed
				*/
				std::string input_type;
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
						input_type = input_types.at(input_index);
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
				int vout_int;
				uint256 txid;
				CScript scriptSig;
				if (!coinbase) {
					/* Parse TXID */
					hex = compressed_transaction.substr(transaction_index, (32*2));
					result += "TXID hex = "+hex+"\n";
					txid.SetHex(hex);

					Consensus::Params consensus_params;
					uint256 hash;
					CTransactionRef tr = GetTransaction(nullptr, nullptr, txid, consensus_params, hash);

					if (tr == nullptr) {
						result += "FAILURE\n";
						std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
						int block_height = std::get<0>(varint_result);
						transaction_index += std::get<1>(varint_result);
						result += "Block Height = "+std::to_string(block_height)+"\n";

						varint_result = from_varint(compressed_transaction.substr(transaction_index));
						int block_index = std::get<0>(varint_result);
						transaction_index += std::get<1>(varint_result);
						result += "Block Index = "+std::to_string(block_index)+"\n";
						std::vector<CBlockIndex*> blocks;
						blocks = blockman->GetAllBlockIndices();
						int blocks_length = blocks.size();
						bool block_found = false;
						for (int blocks_index = 0; blocks_index < blocks_length; blocks_index++) {
							const CBlockIndex* pindex{nullptr};
							pindex = blocks.at(blocks_index);
							int height = pindex->nHeight;
							if (block_height == height) {
								result += "height = "+std::to_string(height)+"\n";
								CBlock block;
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
					std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
					vout_int = std::get<0>(varint_result);
					transaction_index += std::get<1>(varint_result);
					result += "Vout = "+std::to_string(vout_int)+"\n";
				} else {
					txid.SetHex("0x00");
					vout_int = 4294967295;
				}
				
				result += "input_type = "+input_type+"\n";
				/* Parse Input 
					"00": Custom Input Type
					"11": Compressed Input Type, Read Data Complete it After
				*/
				std::vector<std::vector<unsigned char>> stack;
				if (input_type == "00") {
					/* Parse Script Length */
					std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
					int script_length = std::get<0>(varint_result);
					transaction_index += std::get<1>(varint_result);
					result += "Script Length = "+std::to_string(script_length)+"\n";

					/* Parse Script */
					hex = compressed_transaction.substr(transaction_index, script_length*2);
					transaction_index += script_length*2;
					result += "Script = "+hex+"\n";
					std::vector<unsigned char> bytes = hex_to_bytes(hex);
					scriptSig = CScript(bytes.begin(), bytes.end());

					/* Parse Witness Count */
					varint_result = from_varint(compressed_transaction.substr(transaction_index));
					int witness_count = std::get<0>(varint_result);
					transaction_index += std::get<1>(varint_result);
					result += "Witness Script Count = "+std::to_string(witness_count)+"\n";
					for (int witnesses_index = 0; witnesses_index < witness_count; witnesses_index++) {
						/* Parse Witness Length */
						std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
						int witness_script_length = std::get<0>(varint_result);
						transaction_index += std::get<1>(varint_result);
						result += "Witness Script Length = "+std::to_string(witness_script_length)+"\n";

						/* Parse Witness Script */
						hex = compressed_transaction.substr(transaction_index, witness_script_length*2);
						transaction_index += witness_script_length*2;
						result += "Witness Script = "+hex+"\n";
						stack.push_back(hex_to_bytes(hex));
					}
				} else {
					hex = compressed_transaction.substr(transaction_index, 64*2);
					compressed_signatures.push_back(hex);
					half_finished_inputs.push_back(input_index);
					transaction_index += 64*2;
					result += "Compressed Signature = "+hex+"\n";
					hex = compressed_transaction.substr(transaction_index, 2);
					transaction_index += 2;
					hash_types.push_back(hex_to_int(hex));
					result += "Hash Type = "+hex+"\n";
				}

				/* Assemble CTxIn */
				COutPoint outpoint;
				outpoint = COutPoint(txid, vout_int);
				CTxIn ctxin = CTxIn(outpoint, scriptSig, sequence);
				ctxin.scriptWitness.stack = stack;
				vin.push_back(ctxin);
			}
			mtx.vin = vin;
			result += "^^^^^^^^^INPUT^^^^^^^^^\n";
			std::vector<CTxOut> vout;
			for (int output_index = 0; output_index < output_count; output_index++) {
				/* Parse Output Type 
					"000": Output Type Uncompressed, Read From Next Byte
					_: Parse Output Type From output_type_bits
				*/
				std::string output_type;
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
				std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
				CAmount amount = std::get<0>(varint_result);
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
				CScript output_script;
				byte = binary_to_int("00000"+output_type);
				switch(byte)
				{
					case 1: {
						hex = compressed_transaction.substr(transaction_index, 65*2);
						transaction_index += 65*2;
						result += "Script = "+hex+"\n";
						hex = "41"+hex+"ac";
						result += "Exteneded Script = "+hex+"\n";
						std::vector<unsigned char> bytes = hex_to_bytes(hex);
						output_script = CScript(bytes.begin(), bytes.end());
						break;
					}
					case 2: {
						hex = compressed_transaction.substr(transaction_index, 40);
						transaction_index += 40;
						result += "Script = "+hex+"\n";
						hex = "a914"+hex+"87";
						result += "Exteneded Script = "+hex+"\n";
						std::vector<unsigned char> bytes = hex_to_bytes(hex);
						output_script = CScript(bytes.begin(), bytes.end());
						break;
					}
					case 3: {
						hex = compressed_transaction.substr(transaction_index, 40);
						transaction_index += 40;
						result += "Script = "+hex+"\n";
						hex = "76a914"+hex+"88ac";
						result += "Exteneded Script = "+hex+"\n";
						std::vector<unsigned char> bytes = hex_to_bytes(hex);
						output_script = CScript(bytes.begin(), bytes.end());
						break;
					}
					case 4: {
						hex = compressed_transaction.substr(transaction_index, 64);
						transaction_index += 64;
						result += "Script = "+hex+"\n";
						hex = "0020"+hex;
						result += "Exteneded Script = "+hex+"\n";
						std::vector<unsigned char> bytes = hex_to_bytes(hex);
						output_script = CScript(bytes.begin(), bytes.end());
						break;
					}
					case 5: {
						hex = compressed_transaction.substr(transaction_index, 40);
						transaction_index += 40;
						result += "Script = "+hex+"\n";
						hex = "0014"+hex;
						result += "Exteneded Script = "+hex+"\n";
						std::vector<unsigned char> bytes = hex_to_bytes(hex);
						output_script = CScript(bytes.begin(), bytes.end());
						break;
					}
					case 6: {
						hex = compressed_transaction.substr(transaction_index, 64);
						transaction_index += 64;
						result += "Script = "+hex+"\n";
						hex = "5120"+hex;
						result += "Exteneded Script = "+hex+"\n";
						std::vector<unsigned char> bytes = hex_to_bytes(hex);
						output_script = CScript(bytes.begin(), bytes.end());
						break;
					}
					case 7:
					{
						/* Parse Script Length */
						std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
						int script_length = std::get<0>(varint_result);
						transaction_index += std::get<1>(varint_result);
						result += "Script Length = "+std::to_string(script_length)+"\n";

						/* Parse Script */
						hex = compressed_transaction.substr(transaction_index, script_length*2);
						transaction_index += script_length*2;
						result += "Script = "+hex+"\n";
						std::vector<unsigned char> bytes = hex_to_bytes(hex);
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

			int partial_inputs_length = half_finished_inputs.size();
			for (int partial_inputs_index = 0; partial_inputs_index < partial_inputs_length; partial_inputs_index++) {
				/* Complete Input Types */
				int input_index = half_finished_inputs.at(partial_inputs_index);
				result += "Half Finished Input "+std::to_string(partial_inputs_index)+", "+std::to_string(input_index)+"---------------------\n";
				uint256 block_hash;
				Consensus::Params consensusParams;
				CTransactionRef prev_tx = GetTransaction(NULL, NULL, mtx.vin.at(input_index).prevout.hash, consensusParams, block_hash);
				CMutableTransaction prev_mtx = CMutableTransaction(*prev_tx);
				CScript script_pubkey = (*prev_tx).vout.at(mtx.vin.at(input_index).prevout.n).scriptPubKey;
				CAmount amount = (*prev_tx).vout.at(mtx.vin.at(input_index).prevout.n).nValue;
				result += "amount = "+std::to_string(amount)+"\n";
				result += "Scritp Pubkey = "+serialize_script(script_pubkey)+"\n";
				std::tuple<std::string, std::vector<unsigned char>> output_result = get_output_type((*prev_tx).vout.at(mtx.vin.at(input_index).prevout.n), result);
				std::string script_type = std::get<0>(output_result);
				byte = binary_to_int(script_type);

				/* Parse Input Type 
					"011"|"101": ECDSA Signature
					"110": Schnorr Signature
				*/
				std::vector<secp256k1_ecdsa_recoverable_signature> recovered_signatures;
				secp256k1_ecdsa_recoverable_signature rsig;
				if (byte == 3 || byte == 5) {
					result += "ECDSA\n";
					std::vector<unsigned char> compact_signature = hex_to_bytes(compressed_signatures.at(partial_inputs_index));
					for (int recovery_index = 0; recovery_index < 4; recovery_index++) {
						/* Parse the compact signature with each of the 4 recovery IDs */
						int r = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, &compact_signature[0], recovery_index);
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
					std::vector<secp256k1_pubkey> pubkeys;
					std::vector<unsigned char> public_key_bytes;
					if (byte == 3 ) {
						result += "P2PKH\n";
						
						/* Hash the Trasaction to generate the SIGHASH */
						result += "Hash Type = "+int_to_hex(hash_types.at(partial_inputs_index))+"\n";
						uint256 hash = SignatureHash(script_pubkey, mtx, input_index, hash_types.at(partial_inputs_index), amount, SigVersion::BASE);
						hex = hash.GetHex();
						std::vector<unsigned char> bytes;
						bytes = hex_to_bytes(hex);
						std::reverse(bytes.begin(), bytes.end());
						hex = bytes_to_hex(bytes);
						result += "message = "+hex+"\n";
						int recovered_signatures_length = recovered_signatures.size();
						for (int recovered_signatures_index = 0; recovered_signatures_index < recovered_signatures_length; recovered_signatures_index++) {
							/* Run Recover to get the Pubkey for the given Recovered Signature and Message/SigHash (Fails half the time(ignore)) */
							secp256k1_pubkey pubkey;
							int r = secp256k1_ecdsa_recover(ctx, &pubkey, &recovered_signatures.at(recovered_signatures_index), &bytes[0]);
							if (r == 1) {
								result += "SUCCESS\n";
								pubkeys.push_back(pubkey);
							}
						}
						int pubkeys_length = pubkeys.size();
						secp256k1_ecdsa_signature sig;
						bool pubkey_found = false;
						for (int pubkeys_index = 0; pubkeys_index < pubkeys_length; pubkeys_index++) {
							result += "\nPUBKEY = "+std::to_string(pubkeys_index)+"\n";
							/* Serilize Compressed Pubkey */
							std::vector<unsigned char> c_vch (33);
							size_t c_size = 33;
							secp256k1_ec_pubkey_serialize(ctx, &c_vch[0], &c_size, &pubkeys.at(pubkeys_index), SECP256K1_EC_COMPRESSED);
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
							CScript c_script_pubkey = CScript(bytes.begin(), bytes.end());
							/* Test Scripts */
							if (serialize_script(c_script_pubkey) == serialize_script(script_pubkey)) {
								secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &recovered_signatures.at(pubkeys_index));
								pubkey_found = true;
								public_key_bytes = c_vch;
								break;
							}

							result += "-----------\n";

							/* Serilize Uncompressed Pubkey */
							std::vector<unsigned char> uc_vch (65);
							size_t uc_size = 65;
							secp256k1_ec_pubkey_serialize(ctx, &uc_vch[0], &uc_size, &pubkeys.at(pubkeys_index), SECP256K1_EC_UNCOMPRESSED);
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
							CScript uc_script_pubkey = CScript(bytes.begin(), bytes.end());
							/* Test Scripts */
							if (serialize_script(uc_script_pubkey) == serialize_script(script_pubkey)) {
								secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &recovered_signatures.at(pubkeys_index));
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
							result += "Sig Length = "+std::to_string(sig_der_size)+"\n";
							std::string hex = int_to_hex(sig_der_size+1);
							hex += bytes_to_hex(sig_der, sig_der_size);
							hex += int_to_hex(hash_types.at(partial_inputs_index));
							std::string hex2 = bytes_to_hex(public_key_bytes);
							int pubkey_length = hex2.length()/2;
							hex += int_to_hex(pubkey_length);
							hex += hex2;
							result += "Script Signature = "+hex+"\n";
							bytes = hex_to_bytes(hex);
							CScript scriptSig = CScript(bytes.begin(), bytes.end());
							mtx.vin.at(input_index).scriptSig = scriptSig;
						} else {
							result += "FAILURE: no pubkey found\n";
						}
					} else if (byte == 5) {
						result += "V0_P2WPKH\n";
						/* Hash the Trasaction to generate the SIGHASH */
						secp256k1_ecdsa_signature sig;
						std::string scriptPubKeyHash = serialize_script(script_pubkey);
						std::string pubkeyhash = scriptPubKeyHash.substr(4, 40);
						std::vector<unsigned char> bytes;
						bytes = hex_to_bytes("76a914"+pubkeyhash+"88ac");
						CScript script_code = CScript(bytes.begin(), bytes.end()); 
						result += "Script Code = "+serialize_script(script_code)+"\n"; 
						uint256 hash = SignatureHash(script_code, mtx, input_index, hash_types.at(partial_inputs_index), amount, SigVersion::WITNESS_V0);
						//TODO: Get Bytes directly.
						hex = hash.GetHex();
						bytes = hex_to_bytes(hex);
						std::reverse(bytes.begin(), bytes.end());
						hex = bytes_to_hex(bytes);
						result += "message = "+hex+"\n";

						pubkeys.clear();
						int recovered_signatures_length = recovered_signatures.size();
						for (int recovered_signatures_index = 0; recovered_signatures_index < recovered_signatures_length; recovered_signatures_index++) {
							/* Run Recover to get the Pubkey for the given Recovered Signature and Message/SigHash (Fails half the time(ignore)) */
							secp256k1_pubkey pubkey;
							int r = secp256k1_ecdsa_recover(ctx, &pubkey, &recovered_signatures.at(recovered_signatures_index), &bytes[0]);
							if (r == 1) {
								result += "SUCCESS\n";
								pubkeys.push_back(pubkey);
							}
						}

						bool pubkey_found = false;
						int pubkeys_length = pubkeys.size();
						for (int pubkeys_index = 0; pubkeys_index < pubkeys_length; pubkeys_index++) {
							result += "\nPUBKEY = "+std::to_string(pubkeys_index)+"\n";
							/* Serilize Compressed Pubkey */
							std::vector<unsigned char> c_vch (33);
							size_t c_size = 33;
							secp256k1_ec_pubkey_serialize(ctx, &c_vch[0], &c_size, &pubkeys.at(pubkeys_index), SECP256K1_EC_COMPRESSED);
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
							CScript c_script_pubkey = CScript(bytes.begin(), bytes.end());
							/* Test Scripts */
							if (serialize_script(c_script_pubkey) == serialize_script(script_pubkey)) {
								result += "index = "+std::to_string(pubkeys_index)+"\n";
								secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &recovered_signatures.at(pubkeys_index));
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
							sig_der.push_back(hash_types.at(partial_inputs_index));
							stack.push_back(sig_der);
							stack.push_back(public_key_bytes);
							CScriptWitness scriptWitness;
							scriptWitness.stack = stack;
							result += "INSERTING "+std::to_string(input_index)+"\n";
							mtx.vin.at(input_index).scriptWitness = scriptWitness;
						} else {
							result += "FAILURE: no pubkey found\n";
						}
					} else if (byte == 6) {
						result += "P2TR\n";
						std::vector<unsigned char> schnorr_signature = hex_to_bytes(compressed_signatures.at(partial_inputs_index));
						if (!locktime_found) {
							/* Script Execution Data Init */
							ScriptExecutionData execdata;
							execdata.m_annex_init = true;
							execdata.m_annex_present = false;

							/* Prevout Init */
							PrecomputedTransactionData cache;
							std::vector<CTxOut> utxos;
							int input_length = mtx.vin.size();
							for (int input_index_2 = 0; input_index_2 < input_length; input_index_2++) {
								uint256 block_hash;
								CTransactionRef prev_tx = GetTransaction(NULL, NULL, mtx.vin.at(input_index_2).prevout.hash, consensusParams, block_hash);
								// CMutableTransaction prev_mtx = CMutableTransaction(*prev_tx);
								CScript script = (*prev_tx).vout.at(mtx.vin.at(input_index_2).prevout.n).scriptPubKey;
								result += "prevout script = "+serialize_script(script)+"\n";
								amount = (*prev_tx).vout.at(mtx.vin.at(input_index_2).prevout.n).nValue;
								result += "amount = "+std::to_string(amount)+"\n";
								utxos.emplace_back(amount, script);
							}
							cache.Init(CTransaction(mtx), std::vector<CTxOut>{utxos}, true);
							result += "Locktime = "+std::to_string(mtx.nLockTime)+"\n";
							uint256 hash;
							int r = SignatureHashSchnorr(hash, execdata, mtx, input_index, hash_types.at(partial_inputs_index), SigVersion::TAPROOT, cache, MissingDataBehavior::FAIL);
							if (!r) {
								result += "FAILURE SCHNORR HASH\n";
							}
							hex = hash.GetHex();
							result += "message = "+hex+"\n";
							std::vector<unsigned char> bytes;
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
							std::vector<std::vector<unsigned char>> stack;
							if (hash_types.at(partial_inputs_index) != 0x00) {
								schnorr_signature.push_back(hash_types.at(partial_inputs_index));	
							}
							stack.push_back(schnorr_signature);
							result += "INSERTING "+std::to_string(input_index)+"\n";
							mtx.vin.at(input_index).scriptWitness.stack = stack;
						}

					}
					/* If LockTime Has been Found Break, Otherwise add 2^16 to it and try again */
					if (locktime_found) {
						result += "LOCKTIME FOUND\n";
						break;
					} else {
						mtx.nLockTime += pow(2, 16);
						result += "lock = "+std::to_string(mtx.nLockTime)+"\n";
					}
				}
			}
			result += "------------------------R---------------------------\n";
			CTransactionRef tx = MakeTransactionRef(CTransaction(mtx));
        	return EncodeHexTx(*tx, RPCSerializationFlags())+"|"+result;
        }
    };
}




static RPCHelpMan decodescript()
{
    return RPCHelpMan{
        "decodescript",
        "\nDecode a hex-encoded script.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded script"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "asm", "Script public key"},
                {RPCResult::Type::STR, "desc", "Inferred descriptor for the script"},
                {RPCResult::Type::STR, "type", "The output type (e.g. " + GetAllOutputTypes() + ")"},
                {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitcoin address (only if a well-defined address exists)"},
                {RPCResult::Type::STR, "p2sh", /*optional=*/true,
                 "address of P2SH script wrapping this redeem script (not returned for types that should not be wrapped)"},
                {RPCResult::Type::OBJ, "segwit", /*optional=*/true,
                 "Result of a witness script public key wrapping this redeem script (not returned for types that should not be wrapped)",
                 {
                     {RPCResult::Type::STR, "asm", "String representation of the script public key"},
                     {RPCResult::Type::STR_HEX, "hex", "Hex string of the script public key"},
                     {RPCResult::Type::STR, "type", "The type of the script public key (e.g. witness_v0_keyhash or witness_v0_scripthash)"},
                     {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitcoin address (only if a well-defined address exists)"},
                     {RPCResult::Type::STR, "desc", "Inferred descriptor for the script"},
                     {RPCResult::Type::STR, "p2sh-segwit", "address of the P2SH script wrapping this witness redeem script"},
                 }},
            },
        },
        RPCExamples{
            HelpExampleCli("decodescript", "\"hexstring\"")
          + HelpExampleRpc("decodescript", "\"hexstring\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VSTR});

    UniValue r(UniValue::VOBJ);
    CScript script;
    if (request.params[0].get_str().size() > 0){
        std::vector<unsigned char> scriptData(ParseHexV(request.params[0], "argument"));
        script = CScript(scriptData.begin(), scriptData.end());
    } else {
        // Empty scripts are valid
    }
    ScriptToUniv(script, /*out=*/r, /*include_hex=*/false, /*include_address=*/true);

    std::vector<std::vector<unsigned char>> solutions_data;
    const TxoutType which_type{Solver(script, solutions_data)};

    const bool can_wrap{[&] {
        switch (which_type) {
        case TxoutType::MULTISIG:
        case TxoutType::NONSTANDARD:
        case TxoutType::PUBKEY:
        case TxoutType::PUBKEYHASH:
        case TxoutType::WITNESS_V0_KEYHASH:
        case TxoutType::WITNESS_V0_SCRIPTHASH:
            // Can be wrapped if the checks below pass
            break;
        case TxoutType::NULL_DATA:
        case TxoutType::SCRIPTHASH:
        case TxoutType::WITNESS_UNKNOWN:
        case TxoutType::WITNESS_V1_TAPROOT:
            // Should not be wrapped
            return false;
        } // no default case, so the compiler can warn about missing cases
        if (!script.HasValidOps() || script.IsUnspendable()) {
            return false;
        }
        for (CScript::const_iterator it{script.begin()}; it != script.end();) {
            opcodetype op;
            CHECK_NONFATAL(script.GetOp(it, op));
            if (op == OP_CHECKSIGADD || IsOpSuccess(op)) {
                return false;
            }
        }
        return true;
    }()};

    if (can_wrap) {
        r.pushKV("p2sh", EncodeDestination(ScriptHash(script)));
        // P2SH and witness programs cannot be wrapped in P2WSH, if this script
        // is a witness program, don't return addresses for a segwit programs.
        const bool can_wrap_P2WSH{[&] {
            switch (which_type) {
            case TxoutType::MULTISIG:
            case TxoutType::PUBKEY:
            // Uncompressed pubkeys cannot be used with segwit checksigs.
            // If the script contains an uncompressed pubkey, skip encoding of a segwit program.
                for (const auto& solution : solutions_data) {
                    if ((solution.size() != 1) && !CPubKey(solution).IsCompressed()) {
                        return false;
                    }
                }
                return true;
            case TxoutType::NONSTANDARD:
            case TxoutType::PUBKEYHASH:
                // Can be P2WSH wrapped
                return true;
            case TxoutType::NULL_DATA:
            case TxoutType::SCRIPTHASH:
            case TxoutType::WITNESS_UNKNOWN:
            case TxoutType::WITNESS_V0_KEYHASH:
            case TxoutType::WITNESS_V0_SCRIPTHASH:
            case TxoutType::WITNESS_V1_TAPROOT:
                // Should not be wrapped
                return false;
            } // no default case, so the compiler can warn about missing cases
            NONFATAL_UNREACHABLE();
        }()};
        if (can_wrap_P2WSH) {
            UniValue sr(UniValue::VOBJ);
            CScript segwitScr;
            if (which_type == TxoutType::PUBKEY) {
                segwitScr = GetScriptForDestination(WitnessV0KeyHash(Hash160(solutions_data[0])));
            } else if (which_type == TxoutType::PUBKEYHASH) {
                segwitScr = GetScriptForDestination(WitnessV0KeyHash(uint160{solutions_data[0]}));
            } else {
                // Scripts that are not fit for P2WPKH are encoded as P2WSH.
                segwitScr = GetScriptForDestination(WitnessV0ScriptHash(script));
            }
            ScriptToUniv(segwitScr, /*out=*/sr, /*include_hex=*/true, /*include_address=*/true);
            sr.pushKV("p2sh-segwit", EncodeDestination(ScriptHash(segwitScr)));
            r.pushKV("segwit", sr);
        }
    }

    return r;
},
    };
}

static RPCHelpMan combinerawtransaction()
{
    return RPCHelpMan{"combinerawtransaction",
                "\nCombine multiple partially signed transactions into one transaction.\n"
                "The combined transaction may be another partially signed transaction or a \n"
                "fully signed transaction.",
                {
                    {"txs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The hex strings of partially signed transactions",
                        {
                            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A hex-encoded raw transaction"},
                        },
                        },
                },
                RPCResult{
                    RPCResult::Type::STR, "", "The hex-encoded raw transaction with signature(s)"
                },
                RPCExamples{
                    HelpExampleCli("combinerawtransaction", R"('["myhex1", "myhex2", "myhex3"]')")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{

    UniValue txs = request.params[0].get_array();
    std::vector<CMutableTransaction> txVariants(txs.size());

    for (unsigned int idx = 0; idx < txs.size(); idx++) {
        if (!DecodeHexTx(txVariants[idx], txs[idx].get_str())) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed for tx %d. Make sure the tx has at least one input.", idx));
        }
    }

    if (txVariants.empty()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transactions");
    }

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CMutableTransaction mergedTx(txVariants[0]);

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        NodeContext& node = EnsureAnyNodeContext(request.context);
        const CTxMemPool& mempool = EnsureMemPool(node);
        ChainstateManager& chainman = EnsureChainman(node);
        LOCK2(cs_main, mempool.cs);
        CCoinsViewCache &viewChain = chainman.ActiveChainstate().CoinsTip();
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : mergedTx.vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mergedTx);
    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++) {
        CTxIn& txin = mergedTx.vin[i];
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent()) {
            throw JSONRPCError(RPC_VERIFY_ERROR, "Input not found or already spent");
        }
        SignatureData sigdata;

        // ... and merge in other signatures:
        for (const CMutableTransaction& txv : txVariants) {
            if (txv.vin.size() > i) {
                sigdata.MergeSignatureData(DataFromTransaction(txv, i, coin.out));
            }
        }
        ProduceSignature(DUMMY_SIGNING_PROVIDER, MutableTransactionSignatureCreator(mergedTx, i, coin.out.nValue, 1), coin.out.scriptPubKey, sigdata);

        UpdateInput(txin, sigdata);
    }

    return EncodeHexTx(CTransaction(mergedTx));
},
    };
}

static RPCHelpMan signrawtransactionwithkey()
{
    return RPCHelpMan{"signrawtransactionwithkey",
                "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
                "The second argument is an array of base58-encoded private\n"
                "keys that will be the only keys used to sign the transaction.\n"
                "The third optional argument (may be null) is an array of previous transaction outputs that\n"
                "this transaction depends on but may not yet be in the block chain.\n",
                {
                    {"hexstring", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction hex string"},
                    {"privkeys", RPCArg::Type::ARR, RPCArg::Optional::NO, "The base58-encoded private keys for signing",
                        {
                            {"privatekey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "private key in base58-encoding"},
                        },
                        },
                    {"prevtxs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED_NAMED_ARG, "The previous dependent transaction outputs",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                    {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "script key"},
                                    {"redeemScript", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "(required for P2SH) redeem script"},
                                    {"witnessScript", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "(required for P2WSH or P2SH-P2WSH) witness script"},
                                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "(required for Segwit inputs) the amount spent"},
                                },
                                },
                        },
                        },
                    {"sighashtype", RPCArg::Type::STR, RPCArg::Default{"DEFAULT for Taproot, ALL otherwise"}, "The signature hash type. Must be one of:\n"
            "       \"DEFAULT\"\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\"\n"
                    },
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hex", "The hex-encoded raw transaction with signature(s)"},
                        {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                        {RPCResult::Type::ARR, "errors", /*optional=*/true, "Script verification errors (if there are any)",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "txid", "The hash of the referenced, previous transaction"},
                                {RPCResult::Type::NUM, "vout", "The index of the output to spent and used as input"},
                                {RPCResult::Type::ARR, "witness", "",
                                {
                                    {RPCResult::Type::STR_HEX, "witness", ""},
                                }},
                                {RPCResult::Type::STR_HEX, "scriptSig", "The hex-encoded signature script"},
                                {RPCResult::Type::NUM, "sequence", "Script sequence number"},
                                {RPCResult::Type::STR, "error", "Verification or signing error related to the input"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("signrawtransactionwithkey", "\"myhex\" \"[\\\"key1\\\",\\\"key2\\\"]\"")
            + HelpExampleRpc("signrawtransactionwithkey", "\"myhex\", \"[\\\"key1\\\",\\\"key2\\\"]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VARR, UniValue::VARR, UniValue::VSTR}, true);

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.");
    }

    FillableSigningProvider keystore;
    const UniValue& keys = request.params[1].get_array();
    for (unsigned int idx = 0; idx < keys.size(); ++idx) {
        UniValue k = keys[idx];
        CKey key = DecodeSecret(k.get_str());
        if (!key.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
        }
        keystore.AddKey(key);
    }

    // Fetch previous transactions (inputs):
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : mtx.vin) {
        coins[txin.prevout]; // Create empty map entry keyed by prevout.
    }
    NodeContext& node = EnsureAnyNodeContext(request.context);
    FindCoins(node, coins);

    // Parse the prevtxs array
    ParsePrevouts(request.params[2], &keystore, coins);

    UniValue result(UniValue::VOBJ);
    SignTransaction(mtx, &keystore, coins, request.params[3], result);
    return result;
},
    };
}

const RPCResult decodepsbt_inputs{
    RPCResult::Type::ARR, "inputs", "",
    {
        {RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::OBJ, "non_witness_utxo", /*optional=*/true, "Decoded network transaction for non-witness UTXOs",
            {
                {RPCResult::Type::ELISION, "",""},
            }},
            {RPCResult::Type::OBJ, "witness_utxo", /*optional=*/true, "Transaction output for witness UTXOs",
            {
                {RPCResult::Type::NUM, "amount", "The value in " + CURRENCY_UNIT},
                {RPCResult::Type::OBJ, "scriptPubKey", "",
                {
                    {RPCResult::Type::STR, "asm", "Disassembly of the public key script"},
                    {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw public key script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
                    {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitcoin address (only if a well-defined address exists)"},
                }},
            }},
            {RPCResult::Type::OBJ_DYN, "partial_signatures", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "pubkey", "The public key and signature that corresponds to it."},
            }},
            {RPCResult::Type::STR, "sighash", /*optional=*/true, "The sighash type to be used"},
            {RPCResult::Type::OBJ, "redeem_script", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the redeem script"},
                {RPCResult::Type::STR_HEX, "hex", "The raw redeem script bytes, hex-encoded"},
                {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
            }},
            {RPCResult::Type::OBJ, "witness_script", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the witness script"},
                {RPCResult::Type::STR_HEX, "hex", "The raw witness script bytes, hex-encoded"},
                {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
            }},
            {RPCResult::Type::ARR, "bip32_derivs", /*optional=*/true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "pubkey", "The public key with the derivation path as the value."},
                    {RPCResult::Type::STR, "master_fingerprint", "The fingerprint of the master key"},
                    {RPCResult::Type::STR, "path", "The path"},
                }},
            }},
            {RPCResult::Type::OBJ, "final_scriptSig", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the final signature script"},
                {RPCResult::Type::STR_HEX, "hex", "The raw final signature script bytes, hex-encoded"},
            }},
            {RPCResult::Type::ARR, "final_scriptwitness", /*optional=*/true, "",
            {
                {RPCResult::Type::STR_HEX, "", "hex-encoded witness data (if any)"},
            }},
            {RPCResult::Type::OBJ_DYN, "ripemd160_preimages", /*optional=*/ true, "",
            {
                {RPCResult::Type::STR, "hash", "The hash and preimage that corresponds to it."},
            }},
            {RPCResult::Type::OBJ_DYN, "sha256_preimages", /*optional=*/ true, "",
            {
                {RPCResult::Type::STR, "hash", "The hash and preimage that corresponds to it."},
            }},
            {RPCResult::Type::OBJ_DYN, "hash160_preimages", /*optional=*/ true, "",
            {
                {RPCResult::Type::STR, "hash", "The hash and preimage that corresponds to it."},
            }},
            {RPCResult::Type::OBJ_DYN, "hash256_preimages", /*optional=*/ true, "",
            {
                {RPCResult::Type::STR, "hash", "The hash and preimage that corresponds to it."},
            }},
            {RPCResult::Type::STR_HEX, "taproot_key_path_sig", /*optional=*/ true, "hex-encoded signature for the Taproot key path spend"},
            {RPCResult::Type::ARR, "taproot_script_path_sigs", /*optional=*/ true, "",
            {
                {RPCResult::Type::OBJ, "signature", /*optional=*/ true, "The signature for the pubkey and leaf hash combination",
                {
                    {RPCResult::Type::STR, "pubkey", "The x-only pubkey for this signature"},
                    {RPCResult::Type::STR, "leaf_hash", "The leaf hash for this signature"},
                    {RPCResult::Type::STR, "sig", "The signature itself"},
                }},
            }},
            {RPCResult::Type::ARR, "taproot_scripts", /*optional=*/ true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "script", "A leaf script"},
                    {RPCResult::Type::NUM, "leaf_ver", "The version number for the leaf script"},
                    {RPCResult::Type::ARR, "control_blocks", "The control blocks for this script",
                    {
                        {RPCResult::Type::STR_HEX, "control_block", "A hex-encoded control block for this script"},
                    }},
                }},
            }},
            {RPCResult::Type::ARR, "taproot_bip32_derivs", /*optional=*/ true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "pubkey", "The x-only public key this path corresponds to"},
                    {RPCResult::Type::STR, "master_fingerprint", "The fingerprint of the master key"},
                    {RPCResult::Type::STR, "path", "The path"},
                    {RPCResult::Type::ARR, "leaf_hashes", "The hashes of the leaves this pubkey appears in",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The hash of a leaf this pubkey appears in"},
                    }},
                }},
            }},
            {RPCResult::Type::STR_HEX, "taproot_internal_key", /*optional=*/ true, "The hex-encoded Taproot x-only internal key"},
            {RPCResult::Type::STR_HEX, "taproot_merkle_root", /*optional=*/ true, "The hex-encoded Taproot merkle root"},
            {RPCResult::Type::OBJ_DYN, "unknown", /*optional=*/ true, "The unknown input fields",
            {
                {RPCResult::Type::STR_HEX, "key", "(key-value pair) An unknown key-value pair"},
            }},
            {RPCResult::Type::ARR, "proprietary", /*optional=*/true, "The input proprietary map",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "identifier", "The hex string for the proprietary identifier"},
                    {RPCResult::Type::NUM, "subtype", "The number for the subtype"},
                    {RPCResult::Type::STR_HEX, "key", "The hex for the key"},
                    {RPCResult::Type::STR_HEX, "value", "The hex for the value"},
                }},
            }},
        }},
    }
};

const RPCResult decodepsbt_outputs{
    RPCResult::Type::ARR, "outputs", "",
    {
        {RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::OBJ, "redeem_script", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the redeem script"},
                {RPCResult::Type::STR_HEX, "hex", "The raw redeem script bytes, hex-encoded"},
                {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
            }},
            {RPCResult::Type::OBJ, "witness_script", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the witness script"},
                {RPCResult::Type::STR_HEX, "hex", "The raw witness script bytes, hex-encoded"},
                {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
            }},
            {RPCResult::Type::ARR, "bip32_derivs", /*optional=*/true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "pubkey", "The public key this path corresponds to"},
                    {RPCResult::Type::STR, "master_fingerprint", "The fingerprint of the master key"},
                    {RPCResult::Type::STR, "path", "The path"},
                }},
            }},
            {RPCResult::Type::STR_HEX, "taproot_internal_key", /*optional=*/ true, "The hex-encoded Taproot x-only internal key"},
            {RPCResult::Type::ARR, "taproot_tree", /*optional=*/ true, "The tuples that make up the Taproot tree, in depth first search order",
            {
                {RPCResult::Type::OBJ, "tuple", /*optional=*/ true, "A single leaf script in the taproot tree",
                {
                    {RPCResult::Type::NUM, "depth", "The depth of this element in the tree"},
                    {RPCResult::Type::NUM, "leaf_ver", "The version of this leaf"},
                    {RPCResult::Type::STR, "script", "The hex-encoded script itself"},
                }},
            }},
            {RPCResult::Type::ARR, "taproot_bip32_derivs", /*optional=*/ true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "pubkey", "The x-only public key this path corresponds to"},
                    {RPCResult::Type::STR, "master_fingerprint", "The fingerprint of the master key"},
                    {RPCResult::Type::STR, "path", "The path"},
                    {RPCResult::Type::ARR, "leaf_hashes", "The hashes of the leaves this pubkey appears in",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The hash of a leaf this pubkey appears in"},
                    }},
                }},
            }},
            {RPCResult::Type::OBJ_DYN, "unknown", /*optional=*/true, "The unknown output fields",
            {
                {RPCResult::Type::STR_HEX, "key", "(key-value pair) An unknown key-value pair"},
            }},
            {RPCResult::Type::ARR, "proprietary", /*optional=*/true, "The output proprietary map",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "identifier", "The hex string for the proprietary identifier"},
                    {RPCResult::Type::NUM, "subtype", "The number for the subtype"},
                    {RPCResult::Type::STR_HEX, "key", "The hex for the key"},
                    {RPCResult::Type::STR_HEX, "value", "The hex for the value"},
                }},
            }},
        }},
    }
};

static RPCHelpMan decodepsbt()
{
    return RPCHelpMan{
        "decodepsbt",
        "Return a JSON object representing the serialized, base64-encoded partially signed Bitcoin transaction.",
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "The PSBT base64 string"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::OBJ, "tx", "The decoded network-serialized unsigned transaction.",
                        {
                            {RPCResult::Type::ELISION, "", "The layout is the same as the output of decoderawtransaction."},
                        }},
                        {RPCResult::Type::ARR, "global_xpubs", "",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "xpub", "The extended public key this path corresponds to"},
                                {RPCResult::Type::STR_HEX, "master_fingerprint", "The fingerprint of the master key"},
                                {RPCResult::Type::STR, "path", "The path"},
                            }},
                        }},
                        {RPCResult::Type::NUM, "psbt_version", "The PSBT version number. Not to be confused with the unsigned transaction version"},
                        {RPCResult::Type::ARR, "proprietary", "The global proprietary map",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "identifier", "The hex string for the proprietary identifier"},
                                {RPCResult::Type::NUM, "subtype", "The number for the subtype"},
                                {RPCResult::Type::STR_HEX, "key", "The hex for the key"},
                                {RPCResult::Type::STR_HEX, "value", "The hex for the value"},
                            }},
                        }},
                        {RPCResult::Type::OBJ_DYN, "unknown", "The unknown global fields",
                        {
                             {RPCResult::Type::STR_HEX, "key", "(key-value pair) An unknown key-value pair"},
                        }},
                        decodepsbt_inputs,
                        decodepsbt_outputs,
                        {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The transaction fee paid if all UTXOs slots in the PSBT have been filled."},
                    }
                },
                RPCExamples{
                    HelpExampleCli("decodepsbt", "\"psbt\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VSTR});

    // Unserialize the transactions
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    UniValue result(UniValue::VOBJ);

    // Add the decoded tx
    UniValue tx_univ(UniValue::VOBJ);
    TxToUniv(CTransaction(*psbtx.tx), /*block_hash=*/uint256(), /*entry=*/tx_univ, /*include_hex=*/false);
    result.pushKV("tx", tx_univ);

    // Add the global xpubs
    UniValue global_xpubs(UniValue::VARR);
    for (std::pair<KeyOriginInfo, std::set<CExtPubKey>> xpub_pair : psbtx.m_xpubs) {
        for (auto& xpub : xpub_pair.second) {
            std::vector<unsigned char> ser_xpub;
            ser_xpub.assign(BIP32_EXTKEY_WITH_VERSION_SIZE, 0);
            xpub.EncodeWithVersion(ser_xpub.data());

            UniValue keypath(UniValue::VOBJ);
            keypath.pushKV("xpub", EncodeBase58Check(ser_xpub));
            keypath.pushKV("master_fingerprint", HexStr(Span<unsigned char>(xpub_pair.first.fingerprint, xpub_pair.first.fingerprint + 4)));
            keypath.pushKV("path", WriteHDKeypath(xpub_pair.first.path));
            global_xpubs.push_back(keypath);
        }
    }
    result.pushKV("global_xpubs", global_xpubs);

    // PSBT version
    result.pushKV("psbt_version", static_cast<uint64_t>(psbtx.GetVersion()));

    // Proprietary
    UniValue proprietary(UniValue::VARR);
    for (const auto& entry : psbtx.m_proprietary) {
        UniValue this_prop(UniValue::VOBJ);
        this_prop.pushKV("identifier", HexStr(entry.identifier));
        this_prop.pushKV("subtype", entry.subtype);
        this_prop.pushKV("key", HexStr(entry.key));
        this_prop.pushKV("value", HexStr(entry.value));
        proprietary.push_back(this_prop);
    }
    result.pushKV("proprietary", proprietary);

    // Unknown data
    UniValue unknowns(UniValue::VOBJ);
    for (auto entry : psbtx.unknown) {
        unknowns.pushKV(HexStr(entry.first), HexStr(entry.second));
    }
    result.pushKV("unknown", unknowns);

    // inputs
    CAmount total_in = 0;
    bool have_all_utxos = true;
    UniValue inputs(UniValue::VARR);
    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        const PSBTInput& input = psbtx.inputs[i];
        UniValue in(UniValue::VOBJ);
        // UTXOs
        bool have_a_utxo = false;
        CTxOut txout;
        if (!input.witness_utxo.IsNull()) {
            txout = input.witness_utxo;

            UniValue o(UniValue::VOBJ);
            ScriptToUniv(txout.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);

            UniValue out(UniValue::VOBJ);
            out.pushKV("amount", ValueFromAmount(txout.nValue));
            out.pushKV("scriptPubKey", o);

            in.pushKV("witness_utxo", out);

            have_a_utxo = true;
        }
        if (input.non_witness_utxo) {
            txout = input.non_witness_utxo->vout[psbtx.tx->vin[i].prevout.n];

            UniValue non_wit(UniValue::VOBJ);
            TxToUniv(*input.non_witness_utxo, /*block_hash=*/uint256(), /*entry=*/non_wit, /*include_hex=*/false);
            in.pushKV("non_witness_utxo", non_wit);

            have_a_utxo = true;
        }
        if (have_a_utxo) {
            if (MoneyRange(txout.nValue) && MoneyRange(total_in + txout.nValue)) {
                total_in += txout.nValue;
            } else {
                // Hack to just not show fee later
                have_all_utxos = false;
            }
        } else {
            have_all_utxos = false;
        }

        // Partial sigs
        if (!input.partial_sigs.empty()) {
            UniValue partial_sigs(UniValue::VOBJ);
            for (const auto& sig : input.partial_sigs) {
                partial_sigs.pushKV(HexStr(sig.second.first), HexStr(sig.second.second));
            }
            in.pushKV("partial_signatures", partial_sigs);
        }

        // Sighash
        if (input.sighash_type != std::nullopt) {
            in.pushKV("sighash", SighashToStr((unsigned char)*input.sighash_type));
        }

        // Redeem script and witness script
        if (!input.redeem_script.empty()) {
            UniValue r(UniValue::VOBJ);
            ScriptToUniv(input.redeem_script, /*out=*/r);
            in.pushKV("redeem_script", r);
        }
        if (!input.witness_script.empty()) {
            UniValue r(UniValue::VOBJ);
            ScriptToUniv(input.witness_script, /*out=*/r);
            in.pushKV("witness_script", r);
        }

        // keypaths
        if (!input.hd_keypaths.empty()) {
            UniValue keypaths(UniValue::VARR);
            for (auto entry : input.hd_keypaths) {
                UniValue keypath(UniValue::VOBJ);
                keypath.pushKV("pubkey", HexStr(entry.first));

                keypath.pushKV("master_fingerprint", strprintf("%08x", ReadBE32(entry.second.fingerprint)));
                keypath.pushKV("path", WriteHDKeypath(entry.second.path));
                keypaths.push_back(keypath);
            }
            in.pushKV("bip32_derivs", keypaths);
        }

        // Final scriptSig and scriptwitness
        if (!input.final_script_sig.empty()) {
            UniValue scriptsig(UniValue::VOBJ);
            scriptsig.pushKV("asm", ScriptToAsmStr(input.final_script_sig, true));
            scriptsig.pushKV("hex", HexStr(input.final_script_sig));
            in.pushKV("final_scriptSig", scriptsig);
        }
        if (!input.final_script_witness.IsNull()) {
            UniValue txinwitness(UniValue::VARR);
            for (const auto& item : input.final_script_witness.stack) {
                txinwitness.push_back(HexStr(item));
            }
            in.pushKV("final_scriptwitness", txinwitness);
        }

        // Ripemd160 hash preimages
        if (!input.ripemd160_preimages.empty()) {
            UniValue ripemd160_preimages(UniValue::VOBJ);
            for (const auto& [hash, preimage] : input.ripemd160_preimages) {
                ripemd160_preimages.pushKV(HexStr(hash), HexStr(preimage));
            }
            in.pushKV("ripemd160_preimages", ripemd160_preimages);
        }

        // Sha256 hash preimages
        if (!input.sha256_preimages.empty()) {
            UniValue sha256_preimages(UniValue::VOBJ);
            for (const auto& [hash, preimage] : input.sha256_preimages) {
                sha256_preimages.pushKV(HexStr(hash), HexStr(preimage));
            }
            in.pushKV("sha256_preimages", sha256_preimages);
        }

        // Hash160 hash preimages
        if (!input.hash160_preimages.empty()) {
            UniValue hash160_preimages(UniValue::VOBJ);
            for (const auto& [hash, preimage] : input.hash160_preimages) {
                hash160_preimages.pushKV(HexStr(hash), HexStr(preimage));
            }
            in.pushKV("hash160_preimages", hash160_preimages);
        }

        // Hash256 hash preimages
        if (!input.hash256_preimages.empty()) {
            UniValue hash256_preimages(UniValue::VOBJ);
            for (const auto& [hash, preimage] : input.hash256_preimages) {
                hash256_preimages.pushKV(HexStr(hash), HexStr(preimage));
            }
            in.pushKV("hash256_preimages", hash256_preimages);
        }

        // Taproot key path signature
        if (!input.m_tap_key_sig.empty()) {
            in.pushKV("taproot_key_path_sig", HexStr(input.m_tap_key_sig));
        }

        // Taproot script path signatures
        if (!input.m_tap_script_sigs.empty()) {
            UniValue script_sigs(UniValue::VARR);
            for (const auto& [pubkey_leaf, sig] : input.m_tap_script_sigs) {
                const auto& [xonly, leaf_hash] = pubkey_leaf;
                UniValue sigobj(UniValue::VOBJ);
                sigobj.pushKV("pubkey", HexStr(xonly));
                sigobj.pushKV("leaf_hash", HexStr(leaf_hash));
                sigobj.pushKV("sig", HexStr(sig));
                script_sigs.push_back(sigobj);
            }
            in.pushKV("taproot_script_path_sigs", script_sigs);
        }

        // Taproot leaf scripts
        if (!input.m_tap_scripts.empty()) {
            UniValue tap_scripts(UniValue::VARR);
            for (const auto& [leaf, control_blocks] : input.m_tap_scripts) {
                const auto& [script, leaf_ver] = leaf;
                UniValue script_info(UniValue::VOBJ);
                script_info.pushKV("script", HexStr(script));
                script_info.pushKV("leaf_ver", leaf_ver);
                UniValue control_blocks_univ(UniValue::VARR);
                for (const auto& control_block : control_blocks) {
                    control_blocks_univ.push_back(HexStr(control_block));
                }
                script_info.pushKV("control_blocks", control_blocks_univ);
                tap_scripts.push_back(script_info);
            }
            in.pushKV("taproot_scripts", tap_scripts);
        }

        // Taproot bip32 keypaths
        if (!input.m_tap_bip32_paths.empty()) {
            UniValue keypaths(UniValue::VARR);
            for (const auto& [xonly, leaf_origin] : input.m_tap_bip32_paths) {
                const auto& [leaf_hashes, origin] = leaf_origin;
                UniValue path_obj(UniValue::VOBJ);
                path_obj.pushKV("pubkey", HexStr(xonly));
                path_obj.pushKV("master_fingerprint", strprintf("%08x", ReadBE32(origin.fingerprint)));
                path_obj.pushKV("path", WriteHDKeypath(origin.path));
                UniValue leaf_hashes_arr(UniValue::VARR);
                for (const auto& leaf_hash : leaf_hashes) {
                    leaf_hashes_arr.push_back(HexStr(leaf_hash));
                }
                path_obj.pushKV("leaf_hashes", leaf_hashes_arr);
                keypaths.push_back(path_obj);
            }
            in.pushKV("taproot_bip32_derivs", keypaths);
        }

        // Taproot internal key
        if (!input.m_tap_internal_key.IsNull()) {
            in.pushKV("taproot_internal_key", HexStr(input.m_tap_internal_key));
        }

        // Write taproot merkle root
        if (!input.m_tap_merkle_root.IsNull()) {
            in.pushKV("taproot_merkle_root", HexStr(input.m_tap_merkle_root));
        }

        // Proprietary
        if (!input.m_proprietary.empty()) {
            UniValue proprietary(UniValue::VARR);
            for (const auto& entry : input.m_proprietary) {
                UniValue this_prop(UniValue::VOBJ);
                this_prop.pushKV("identifier", HexStr(entry.identifier));
                this_prop.pushKV("subtype", entry.subtype);
                this_prop.pushKV("key", HexStr(entry.key));
                this_prop.pushKV("value", HexStr(entry.value));
                proprietary.push_back(this_prop);
            }
            in.pushKV("proprietary", proprietary);
        }

        // Unknown data
        if (input.unknown.size() > 0) {
            UniValue unknowns(UniValue::VOBJ);
            for (auto entry : input.unknown) {
                unknowns.pushKV(HexStr(entry.first), HexStr(entry.second));
            }
            in.pushKV("unknown", unknowns);
        }

        inputs.push_back(in);
    }
    result.pushKV("inputs", inputs);

    // outputs
    CAmount output_value = 0;
    UniValue outputs(UniValue::VARR);
    for (unsigned int i = 0; i < psbtx.outputs.size(); ++i) {
        const PSBTOutput& output = psbtx.outputs[i];
        UniValue out(UniValue::VOBJ);
        // Redeem script and witness script
        if (!output.redeem_script.empty()) {
            UniValue r(UniValue::VOBJ);
            ScriptToUniv(output.redeem_script, /*out=*/r);
            out.pushKV("redeem_script", r);
        }
        if (!output.witness_script.empty()) {
            UniValue r(UniValue::VOBJ);
            ScriptToUniv(output.witness_script, /*out=*/r);
            out.pushKV("witness_script", r);
        }

        // keypaths
        if (!output.hd_keypaths.empty()) {
            UniValue keypaths(UniValue::VARR);
            for (auto entry : output.hd_keypaths) {
                UniValue keypath(UniValue::VOBJ);
                keypath.pushKV("pubkey", HexStr(entry.first));
                keypath.pushKV("master_fingerprint", strprintf("%08x", ReadBE32(entry.second.fingerprint)));
                keypath.pushKV("path", WriteHDKeypath(entry.second.path));
                keypaths.push_back(keypath);
            }
            out.pushKV("bip32_derivs", keypaths);
        }

        // Taproot internal key
        if (!output.m_tap_internal_key.IsNull()) {
            out.pushKV("taproot_internal_key", HexStr(output.m_tap_internal_key));
        }

        // Taproot tree
        if (!output.m_tap_tree.empty()) {
            UniValue tree(UniValue::VARR);
            for (const auto& [depth, leaf_ver, script] : output.m_tap_tree) {
                UniValue elem(UniValue::VOBJ);
                elem.pushKV("depth", (int)depth);
                elem.pushKV("leaf_ver", (int)leaf_ver);
                elem.pushKV("script", HexStr(script));
                tree.push_back(elem);
            }
            out.pushKV("taproot_tree", tree);
        }

        // Taproot bip32 keypaths
        if (!output.m_tap_bip32_paths.empty()) {
            UniValue keypaths(UniValue::VARR);
            for (const auto& [xonly, leaf_origin] : output.m_tap_bip32_paths) {
                const auto& [leaf_hashes, origin] = leaf_origin;
                UniValue path_obj(UniValue::VOBJ);
                path_obj.pushKV("pubkey", HexStr(xonly));
                path_obj.pushKV("master_fingerprint", strprintf("%08x", ReadBE32(origin.fingerprint)));
                path_obj.pushKV("path", WriteHDKeypath(origin.path));
                UniValue leaf_hashes_arr(UniValue::VARR);
                for (const auto& leaf_hash : leaf_hashes) {
                    leaf_hashes_arr.push_back(HexStr(leaf_hash));
                }
                path_obj.pushKV("leaf_hashes", leaf_hashes_arr);
                keypaths.push_back(path_obj);
            }
            out.pushKV("taproot_bip32_derivs", keypaths);
        }

        // Proprietary
        if (!output.m_proprietary.empty()) {
            UniValue proprietary(UniValue::VARR);
            for (const auto& entry : output.m_proprietary) {
                UniValue this_prop(UniValue::VOBJ);
                this_prop.pushKV("identifier", HexStr(entry.identifier));
                this_prop.pushKV("subtype", entry.subtype);
                this_prop.pushKV("key", HexStr(entry.key));
                this_prop.pushKV("value", HexStr(entry.value));
                proprietary.push_back(this_prop);
            }
            out.pushKV("proprietary", proprietary);
        }

        // Unknown data
        if (output.unknown.size() > 0) {
            UniValue unknowns(UniValue::VOBJ);
            for (auto entry : output.unknown) {
                unknowns.pushKV(HexStr(entry.first), HexStr(entry.second));
            }
            out.pushKV("unknown", unknowns);
        }

        outputs.push_back(out);

        // Fee calculation
        if (MoneyRange(psbtx.tx->vout[i].nValue) && MoneyRange(output_value + psbtx.tx->vout[i].nValue)) {
            output_value += psbtx.tx->vout[i].nValue;
        } else {
            // Hack to just not show fee later
            have_all_utxos = false;
        }
    }
    result.pushKV("outputs", outputs);
    if (have_all_utxos) {
        result.pushKV("fee", ValueFromAmount(total_in - output_value));
    }

    return result;
},
    };
}

static RPCHelpMan combinepsbt()
{
    return RPCHelpMan{"combinepsbt",
                "\nCombine multiple partially signed Bitcoin transactions into one transaction.\n"
                "Implements the Combiner role.\n",
                {
                    {"txs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The base64 strings of partially signed transactions",
                        {
                            {"psbt", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A base64 string of a PSBT"},
                        },
                        },
                },
                RPCResult{
                    RPCResult::Type::STR, "", "The base64-encoded partially signed transaction"
                },
                RPCExamples{
                    HelpExampleCli("combinepsbt", R"('["mybase64_1", "mybase64_2", "mybase64_3"]')")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VARR}, true);

    // Unserialize the transactions
    std::vector<PartiallySignedTransaction> psbtxs;
    UniValue txs = request.params[0].get_array();
    if (txs.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Parameter 'txs' cannot be empty");
    }
    for (unsigned int i = 0; i < txs.size(); ++i) {
        PartiallySignedTransaction psbtx;
        std::string error;
        if (!DecodeBase64PSBT(psbtx, txs[i].get_str(), error)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
        }
        psbtxs.push_back(psbtx);
    }

    PartiallySignedTransaction merged_psbt;
    const TransactionError error = CombinePSBTs(merged_psbt, psbtxs);
    if (error != TransactionError::OK) {
        throw JSONRPCTransactionError(error);
    }

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << merged_psbt;
    return EncodeBase64(ssTx);
},
    };
}

static RPCHelpMan finalizepsbt()
{
    return RPCHelpMan{"finalizepsbt",
                "Finalize the inputs of a PSBT. If the transaction is fully signed, it will produce a\n"
                "network serialized transaction which can be broadcast with sendrawtransaction. Otherwise a PSBT will be\n"
                "created which has the final_scriptSig and final_scriptWitness fields filled for inputs that are complete.\n"
                "Implements the Finalizer and Extractor roles.\n",
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "A base64 string of a PSBT"},
                    {"extract", RPCArg::Type::BOOL, RPCArg::Default{true}, "If true and the transaction is complete,\n"
            "                             extract and return the complete transaction in normal network serialization instead of the PSBT."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "psbt", /*optional=*/true, "The base64-encoded partially signed transaction if not extracted"},
                        {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "The hex-encoded network transaction if extracted"},
                        {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("finalizepsbt", "\"psbt\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VBOOL}, true);

    // Unserialize the transactions
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    bool extract = request.params[1].isNull() || (!request.params[1].isNull() && request.params[1].get_bool());

    CMutableTransaction mtx;
    bool complete = FinalizeAndExtractPSBT(psbtx, mtx);

    UniValue result(UniValue::VOBJ);
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    std::string result_str;

    if (complete && extract) {
        ssTx << mtx;
        result_str = HexStr(ssTx);
        result.pushKV("hex", result_str);
    } else {
        ssTx << psbtx;
        result_str = EncodeBase64(ssTx.str());
        result.pushKV("psbt", result_str);
    }
    result.pushKV("complete", complete);

    return result;
},
    };
}

static RPCHelpMan createpsbt()
{
    return RPCHelpMan{"createpsbt",
                "\nCreates a transaction in the Partially Signed Transaction format.\n"
                "Implements the Creator role.\n",
                CreateTxDoc(),
                RPCResult{
                    RPCResult::Type::STR, "", "The resulting raw transaction (base64-encoded string)"
                },
                RPCExamples{
                    HelpExampleCli("createpsbt", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"data\\\":\\\"00010203\\\"}]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{

    RPCTypeCheck(request.params, {
        UniValue::VARR,
        UniValueType(), // ARR or OBJ, checked later
        UniValue::VNUM,
        UniValue::VBOOL,
        }, true
    );

    std::optional<bool> rbf;
    if (!request.params[3].isNull()) {
        rbf = request.params[3].get_bool();
    }
    CMutableTransaction rawTx = ConstructTransaction(request.params[0], request.params[1], request.params[2], rbf);

    // Make a blank psbt
    PartiallySignedTransaction psbtx;
    psbtx.tx = rawTx;
    for (unsigned int i = 0; i < rawTx.vin.size(); ++i) {
        psbtx.inputs.push_back(PSBTInput());
    }
    for (unsigned int i = 0; i < rawTx.vout.size(); ++i) {
        psbtx.outputs.push_back(PSBTOutput());
    }

    // Serialize the PSBT
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << psbtx;

    return EncodeBase64(ssTx);
},
    };
}

static RPCHelpMan converttopsbt()
{
    return RPCHelpMan{"converttopsbt",
                "\nConverts a network serialized transaction to a PSBT. This should be used only with createrawtransaction and fundrawtransaction\n"
                "createpsbt and walletcreatefundedpsbt should be used for new applications.\n",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex string of a raw transaction"},
                    {"permitsigdata", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, any signatures in the input will be discarded and conversion\n"
                            "                              will continue. If false, RPC will fail if any signatures are present."},
                    {"iswitness", RPCArg::Type::BOOL, RPCArg::DefaultHint{"depends on heuristic tests"}, "Whether the transaction hex is a serialized witness transaction.\n"
                        "If iswitness is not present, heuristic tests will be used in decoding.\n"
                        "If true, only witness deserialization will be tried.\n"
                        "If false, only non-witness deserialization will be tried.\n"
                        "This boolean should reflect whether the transaction has inputs\n"
                        "(e.g. fully valid, or on-chain transactions), if known by the caller."
                    },
                },
                RPCResult{
                    RPCResult::Type::STR, "", "The resulting raw transaction (base64-encoded string)"
                },
                RPCExamples{
                            "\nCreate a transaction\n"
                            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"data\\\":\\\"00010203\\\"}]\"") +
                            "\nConvert the transaction to a PSBT\n"
                            + HelpExampleCli("converttopsbt", "\"rawtransaction\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VBOOL, UniValue::VBOOL}, true);

    // parse hex string from parameter
    CMutableTransaction tx;
    bool permitsigdata = request.params[1].isNull() ? false : request.params[1].get_bool();
    bool witness_specified = !request.params[2].isNull();
    bool iswitness = witness_specified ? request.params[2].get_bool() : false;
    const bool try_witness = witness_specified ? iswitness : true;
    const bool try_no_witness = witness_specified ? !iswitness : true;
    if (!DecodeHexTx(tx, request.params[0].get_str(), try_no_witness, try_witness)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    // Remove all scriptSigs and scriptWitnesses from inputs
    for (CTxIn& input : tx.vin) {
        if ((!input.scriptSig.empty() || !input.scriptWitness.IsNull()) && !permitsigdata) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Inputs must not have scriptSigs and scriptWitnesses");
        }
        input.scriptSig.clear();
        input.scriptWitness.SetNull();
    }

    // Make a blank psbt
    PartiallySignedTransaction psbtx;
    psbtx.tx = tx;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        psbtx.inputs.push_back(PSBTInput());
    }
    for (unsigned int i = 0; i < tx.vout.size(); ++i) {
        psbtx.outputs.push_back(PSBTOutput());
    }

    // Serialize the PSBT
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << psbtx;

    return EncodeBase64(ssTx);
},
    };
}

static RPCHelpMan utxoupdatepsbt()
{
    return RPCHelpMan{"utxoupdatepsbt",
            "\nUpdates all segwit inputs and outputs in a PSBT with data from output descriptors, the UTXO set or the mempool.\n",
            {
                {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "A base64 string of a PSBT"},
                {"descriptors", RPCArg::Type::ARR, RPCArg::Optional::OMITTED_NAMED_ARG, "An array of either strings or objects", {
                    {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "An object with an output descriptor and extra information", {
                         {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "An output descriptor"},
                         {"range", RPCArg::Type::RANGE, RPCArg::Default{1000}, "Up to what index HD chains should be explored (either end or [begin,end])"},
                    }},
                }},
            },
            RPCResult {
                    RPCResult::Type::STR, "", "The base64-encoded partially signed transaction with inputs updated"
            },
            RPCExamples {
                HelpExampleCli("utxoupdatepsbt", "\"psbt\"")
            },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VARR}, true);

    // Unserialize the transactions
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    // Parse descriptors, if any.
    FlatSigningProvider provider;
    if (!request.params[1].isNull()) {
        auto descs = request.params[1].get_array();
        for (size_t i = 0; i < descs.size(); ++i) {
            EvalDescriptorStringOrObject(descs[i], provider);
        }
    }
    // We don't actually need private keys further on; hide them as a precaution.
    HidingSigningProvider public_provider(&provider, /*hide_secret=*/true, /*hide_origin=*/false);

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        NodeContext& node = EnsureAnyNodeContext(request.context);
        const CTxMemPool& mempool = EnsureMemPool(node);
        ChainstateManager& chainman = EnsureChainman(node);
        LOCK2(cs_main, mempool.cs);
        CCoinsViewCache &viewChain = chainman.ActiveChainstate().CoinsTip();
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : psbtx.tx->vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    // Fill the inputs
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        PSBTInput& input = psbtx.inputs.at(i);

        if (input.non_witness_utxo || !input.witness_utxo.IsNull()) {
            continue;
        }

        const Coin& coin = view.AccessCoin(psbtx.tx->vin[i].prevout);

        if (IsSegWitOutput(provider, coin.out.scriptPubKey)) {
            input.witness_utxo = coin.out;
        }

        // Update script/keypath information using descriptor data.
        // Note that SignPSBTInput does a lot more than just constructing ECDSA signatures
        // we don't actually care about those here, in fact.
        SignPSBTInput(public_provider, psbtx, i, &txdata, /*sighash=*/1);
    }

    // Update script/keypath information using descriptor data.
    for (unsigned int i = 0; i < psbtx.tx->vout.size(); ++i) {
        UpdatePSBTOutput(public_provider, psbtx, i);
    }

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << psbtx;
    return EncodeBase64(ssTx);
},
    };
}

static RPCHelpMan joinpsbts()
{
    return RPCHelpMan{"joinpsbts",
            "\nJoins multiple distinct PSBTs with different inputs and outputs into one PSBT with inputs and outputs from all of the PSBTs\n"
            "No input in any of the PSBTs can be in more than one of the PSBTs.\n",
            {
                {"txs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The base64 strings of partially signed transactions",
                    {
                        {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "A base64 string of a PSBT"}
                    }}
            },
            RPCResult {
                    RPCResult::Type::STR, "", "The base64-encoded partially signed transaction"
            },
            RPCExamples {
                HelpExampleCli("joinpsbts", "\"psbt\"")
            },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VARR}, true);

    // Unserialize the transactions
    std::vector<PartiallySignedTransaction> psbtxs;
    UniValue txs = request.params[0].get_array();

    if (txs.size() <= 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "At least two PSBTs are required to join PSBTs.");
    }

    uint32_t best_version = 1;
    uint32_t best_locktime = 0xffffffff;
    for (unsigned int i = 0; i < txs.size(); ++i) {
        PartiallySignedTransaction psbtx;
        std::string error;
        if (!DecodeBase64PSBT(psbtx, txs[i].get_str(), error)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
        }
        psbtxs.push_back(psbtx);
        // Choose the highest version number
        if (static_cast<uint32_t>(psbtx.tx->nVersion) > best_version) {
            best_version = static_cast<uint32_t>(psbtx.tx->nVersion);
        }
        // Choose the lowest lock time
        if (psbtx.tx->nLockTime < best_locktime) {
            best_locktime = psbtx.tx->nLockTime;
        }
    }

    // Create a blank psbt where everything will be added
    PartiallySignedTransaction merged_psbt;
    merged_psbt.tx = CMutableTransaction();
    merged_psbt.tx->nVersion = static_cast<int32_t>(best_version);
    merged_psbt.tx->nLockTime = best_locktime;

    // Merge
    for (auto& psbt : psbtxs) {
        for (unsigned int i = 0; i < psbt.tx->vin.size(); ++i) {
            if (!merged_psbt.AddInput(psbt.tx->vin[i], psbt.inputs[i])) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Input %s:%d exists in multiple PSBTs", psbt.tx->vin[i].prevout.hash.ToString(), psbt.tx->vin[i].prevout.n));
            }
        }
        for (unsigned int i = 0; i < psbt.tx->vout.size(); ++i) {
            merged_psbt.AddOutput(psbt.tx->vout[i], psbt.outputs[i]);
        }
        for (auto& xpub_pair : psbt.m_xpubs) {
            if (merged_psbt.m_xpubs.count(xpub_pair.first) == 0) {
                merged_psbt.m_xpubs[xpub_pair.first] = xpub_pair.second;
            } else {
                merged_psbt.m_xpubs[xpub_pair.first].insert(xpub_pair.second.begin(), xpub_pair.second.end());
            }
        }
        merged_psbt.unknown.insert(psbt.unknown.begin(), psbt.unknown.end());
    }

    // Generate list of shuffled indices for shuffling inputs and outputs of the merged PSBT
    std::vector<int> input_indices(merged_psbt.inputs.size());
    std::iota(input_indices.begin(), input_indices.end(), 0);
    std::vector<int> output_indices(merged_psbt.outputs.size());
    std::iota(output_indices.begin(), output_indices.end(), 0);

    // Shuffle input and output indices lists
    Shuffle(input_indices.begin(), input_indices.end(), FastRandomContext());
    Shuffle(output_indices.begin(), output_indices.end(), FastRandomContext());

    PartiallySignedTransaction shuffled_psbt;
    shuffled_psbt.tx = CMutableTransaction();
    shuffled_psbt.tx->nVersion = merged_psbt.tx->nVersion;
    shuffled_psbt.tx->nLockTime = merged_psbt.tx->nLockTime;
    for (int i : input_indices) {
        shuffled_psbt.AddInput(merged_psbt.tx->vin[i], merged_psbt.inputs[i]);
    }
    for (int i : output_indices) {
        shuffled_psbt.AddOutput(merged_psbt.tx->vout[i], merged_psbt.outputs[i]);
    }
    shuffled_psbt.unknown.insert(merged_psbt.unknown.begin(), merged_psbt.unknown.end());

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << shuffled_psbt;
    return EncodeBase64(ssTx);
},
    };
}

static RPCHelpMan analyzepsbt()
{
    return RPCHelpMan{"analyzepsbt",
            "\nAnalyzes and provides information about the current status of a PSBT and its inputs\n",
            {
                {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "A base64 string of a PSBT"}
            },
            RPCResult {
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::ARR, "inputs", /*optional=*/true, "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::BOOL, "has_utxo", "Whether a UTXO is provided"},
                            {RPCResult::Type::BOOL, "is_final", "Whether the input is finalized"},
                            {RPCResult::Type::OBJ, "missing", /*optional=*/true, "Things that are missing that are required to complete this input",
                            {
                                {RPCResult::Type::ARR, "pubkeys", /*optional=*/true, "",
                                {
                                    {RPCResult::Type::STR_HEX, "keyid", "Public key ID, hash160 of the public key, of a public key whose BIP 32 derivation path is missing"},
                                }},
                                {RPCResult::Type::ARR, "signatures", /*optional=*/true, "",
                                {
                                    {RPCResult::Type::STR_HEX, "keyid", "Public key ID, hash160 of the public key, of a public key whose signature is missing"},
                                }},
                                {RPCResult::Type::STR_HEX, "redeemscript", /*optional=*/true, "Hash160 of the redeemScript that is missing"},
                                {RPCResult::Type::STR_HEX, "witnessscript", /*optional=*/true, "SHA256 of the witnessScript that is missing"},
                            }},
                            {RPCResult::Type::STR, "next", /*optional=*/true, "Role of the next person that this input needs to go to"},
                        }},
                    }},
                    {RPCResult::Type::NUM, "estimated_vsize", /*optional=*/true, "Estimated vsize of the final signed transaction"},
                    {RPCResult::Type::STR_AMOUNT, "estimated_feerate", /*optional=*/true, "Estimated feerate of the final signed transaction in " + CURRENCY_UNIT + "/kvB. Shown only if all UTXO slots in the PSBT have been filled"},
                    {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The transaction fee paid. Shown only if all UTXO slots in the PSBT have been filled"},
                    {RPCResult::Type::STR, "next", "Role of the next person that this psbt needs to go to"},
                    {RPCResult::Type::STR, "error", /*optional=*/true, "Error message (if there is one)"},
                }
            },
            RPCExamples {
                HelpExampleCli("analyzepsbt", "\"psbt\"")
            },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VSTR});

    // Unserialize the transaction
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    PSBTAnalysis psbta = AnalyzePSBT(psbtx);

    UniValue result(UniValue::VOBJ);
    UniValue inputs_result(UniValue::VARR);
    for (const auto& input : psbta.inputs) {
        UniValue input_univ(UniValue::VOBJ);
        UniValue missing(UniValue::VOBJ);

        input_univ.pushKV("has_utxo", input.has_utxo);
        input_univ.pushKV("is_final", input.is_final);
        input_univ.pushKV("next", PSBTRoleName(input.next));

        if (!input.missing_pubkeys.empty()) {
            UniValue missing_pubkeys_univ(UniValue::VARR);
            for (const CKeyID& pubkey : input.missing_pubkeys) {
                missing_pubkeys_univ.push_back(HexStr(pubkey));
            }
            missing.pushKV("pubkeys", missing_pubkeys_univ);
        }
        if (!input.missing_redeem_script.IsNull()) {
            missing.pushKV("redeemscript", HexStr(input.missing_redeem_script));
        }
        if (!input.missing_witness_script.IsNull()) {
            missing.pushKV("witnessscript", HexStr(input.missing_witness_script));
        }
        if (!input.missing_sigs.empty()) {
            UniValue missing_sigs_univ(UniValue::VARR);
            for (const CKeyID& pubkey : input.missing_sigs) {
                missing_sigs_univ.push_back(HexStr(pubkey));
            }
            missing.pushKV("signatures", missing_sigs_univ);
        }
        if (!missing.getKeys().empty()) {
            input_univ.pushKV("missing", missing);
        }
        inputs_result.push_back(input_univ);
    }
    if (!inputs_result.empty()) result.pushKV("inputs", inputs_result);

    if (psbta.estimated_vsize != std::nullopt) {
        result.pushKV("estimated_vsize", (int)*psbta.estimated_vsize);
    }
    if (psbta.estimated_feerate != std::nullopt) {
        result.pushKV("estimated_feerate", ValueFromAmount(psbta.estimated_feerate->GetFeePerK()));
    }
    if (psbta.fee != std::nullopt) {
        result.pushKV("fee", ValueFromAmount(*psbta.fee));
    }
    result.pushKV("next", PSBTRoleName(psbta.next));
    if (!psbta.error.empty()) {
        result.pushKV("error", psbta.error);
    }

    return result;
},
    };
}

void RegisterRawTransactionRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"rawtransactions", &getrawtransaction},
        {"rawtransactions", &createrawtransaction},
        {"rawtransactions", &decoderawtransaction},
        {"rawtransactions", &compressrawtransaction},
        {"rawtransactions", &decompressrawtransaction},
        {"rawtransactions", &decodescript},
        {"rawtransactions", &combinerawtransaction},
        {"rawtransactions", &signrawtransactionwithkey},
        {"rawtransactions", &decodepsbt},
        {"rawtransactions", &combinepsbt},
        {"rawtransactions", &finalizepsbt},
        {"rawtransactions", &createpsbt},
        {"rawtransactions", &converttopsbt},
        {"rawtransactions", &utxoupdatepsbt},
        {"rawtransactions", &joinpsbts},
        {"rawtransactions", &analyzepsbt},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
