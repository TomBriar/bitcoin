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

            if (!DecodeHexTx(mtx, request.params[0].get_str(), true, true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }

            NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);
            Chainstate& active_chainstate = chainman.ActiveChainstate();
            active_chainstate.ForceFlushStateToDisk();
			BlockManager* blockman = &active_chainstate.m_blockman;


			std::vector<unsigned char> transaction_result_bytes;
			unsigned char input_byte = 0;
			
			/* Encode Version
				if version < 4: Encode Version Directly
				else: Encode VarInt Later
			*/
			switch(mtx.nVersion)
			{
				case 1: 
				{
					input_byte |= 0x01;
					break;
				};
				case 2: 
				{
					input_byte |= 0x02;
					break;
				};
				case 3: 
				{
					input_byte |= 0x03;
					break;
				};
			}

			/* Encode Coinbase Bool
				if vout is 4294967295: vout signifies this is a coinbase transaction
				else: false
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

			/* Encode Input Count
				if input_count < 4: Encode Input Count Directly
				else: Encode Input Count VarInt Later
			*/
			int input_count = mtx.vin.size();
			switch(input_count)
			{
				case 1:
				{
					input_byte |= 0x04;
					break;
				}
				case 2:
				{
					input_byte |= 0x08;
					break;
				}
				case 3:
				{
					input_byte |= 0x0c;
					break;
				}
			}

			/* Encode Input Type 
				0x00: More then 3 Inputs, Non Identical Scripts, At least one Input is of Custom Type. 
				0x10: Less then 4 Inputs, Non Identical Scripts, At least one Input is of Custom Type. 
				0x20: Identical Script Types, Custom Script.
				0x30: Identical Script Types, Legacy, Segwit, or Taproot.
			*/
			std::vector<std::tuple<InputScriptType, std::vector<unsigned char>>> inputs;

    		if (!coinbase) {
    			bool input_type_identical = true;
				std::vector<unsigned char> input_bytes;
    			InputScriptType input_type = get_input_type(mtx.vin.at(0), input_bytes, result);
    			inputs.push_back(std::make_tuple(input_type, input_bytes));

    			int input_length = mtx.vin.size();
    			for (int input_index = 1; input_index < input_length; input_index++) {
					std::vector<unsigned char> input_bytes_x;
    				InputScriptType input_type_x = get_input_type(mtx.vin.at(input_index), input_bytes_x, result);
    				if (input_type != input_type_x) {
    					input_type_identical = false;
    				}
    				inputs.push_back(std::make_tuple(input_type_x, input_bytes_x));
    			}
				if (input_type_identical && input_type == CustomInput) {
					input_byte |= 0x10;
    			} else if (input_type_identical && input_type != CustomInput) {
					input_byte |= 0x30;
    			} else if (!input_type_identical && input_count < 3) {
					input_byte |= 0x20;
    			}
    		} else {
				result += "Input Byte = "+int_to_hex(input_byte)+"\n";
				input_byte |= 0x20;
				std::vector<unsigned char> input_bytes;
				inputs.push_back(std::make_tuple(CustomInput, input_bytes));
    		}
			result += "Input Byte = "+int_to_hex(input_byte)+"\n";

    		/* Encode Lock Time
    			0xc0: If locktime is 0
    			0x80: If locktime is not zero and at least one input type is not Custom then only Encode Half the locktime.
    			0x00: If locktime is non zero and not a coinbase transaction transmite the two least significant bytes of the locktime and we'll brute force the remaninig bytes in the decoding.
    		*/
    		std::string locktime_bits;
    		if (mtx.nLockTime > 0) {
				if (!coinbase && ((input_byte & 12) >> 2) != 2) {
					input_byte |= 0x80;
				}
    		} else {
				input_byte |= 0xc0;
			}

    		/* Push Input Byte 
    			"xx": Version Encoding
    			"xx": Input Count
				"xx": Input Type
    			"xx": LockTime Encoding
    		*/
			result += "Input Byte = "+int_to_hex(input_byte)+"\n";
			transaction_result_bytes.push_back(input_byte);

			unsigned char output_byte = 0;

			/* Encode Squence 
				0x00: Non Identical, Non Standard Sequence/Inputs more then 3. Read Sequence Before Each Input.
				0x01: Identical, Non Standard Sequence. Read VarInt for Full Sequnce.
				0x02: Non Identical, Standard Sequence, Inputs less then 4. Read Next Byte For Encoded Sequences.
				0x03: Identical, Standard Sequence. 0xFFFFFFF0
				0x04: Identical, Standard Sequence. 0xFFFFFFFE
				0x05: Identical, Standard Sequence. 0xFFFFFFFF
				0x06: Identical, Standard Sequence. 0x00000000
			*/
			std::vector<uint32_t> sequences;
			bool identical_sequnce = true;
			bool standard_sequence = true;

			sequences.push_back(mtx.vin.at(0).nSequence);
			if (sequences.at(0) != 0x00 && sequences.at(0) != SEQUENCE_F0 && sequences.at(0) != SEQUENCE_FE && sequences.at(0) != SEQUENCE_FF) {
				standard_sequence = false;
			}
			int input_length = mtx.vin.size();
			for (int input_index = 1; input_index < input_length; input_index++) {
				if (mtx.vin.at(input_index).nSequence != sequences.at(0)) {
					identical_sequnce = false;
				}
				if (mtx.vin.at(input_index).nSequence != 0x00 && mtx.vin.at(input_index).nSequence != SEQUENCE_F0 && mtx.vin.at(input_index).nSequence != SEQUENCE_FE && mtx.vin.at(input_index).nSequence != SEQUENCE_FF) {
					standard_sequence = false;
				}
				if (!(input_byte & 0x30)) {
					sequences.push_back(mtx.vin.at(input_index).nSequence);
				}
			}
			if (identical_sequnce) {
				switch(sequences.at(0))
				{
					case SEQUENCE_F0: 
					{
						output_byte |= 0x06;
						break;
					}
					case SEQUENCE_FE: 
					{
						output_byte |= 0x01;
						break;
					}
					case SEQUENCE_FF: 
					{
						output_byte |= 0x05;
						break;
					}
					case 0x00: 
					{
						output_byte |= 0x03;
						break;
					}
					default: 
					{
						output_byte |= 0x04;
						break;
					}
				}
			} else {
				if (standard_sequence && input_byte & 0x30) {
					output_byte |= 0x02;
				}
			}

			/* Encode Output Count
				if output_count < 4: Encode Output Count Directly
				else: Encode Output Count VarInt Later
				
			*/
			int output_count = mtx.vout.size();
			switch(output_count)
			{
				case 1:
				{
					output_byte |= 0x08;
					break;
				}
				case 2:
				{
					output_byte |= 0x10;
					break;
				}
				case 3:
				{
					output_byte |= 0x18;
					break;
				}
			}

			/* Encode Output Type 
				If each output type is identical encode it in the output byte,
				Otherwise 000 and read type before each output.
			*/
			std::vector<std::tuple<OutputScriptType, std::vector<unsigned char>>> outputs;
			bool output_type_identical = true;

			std::vector<unsigned char> output_bytes;
			OutputScriptType output_type = get_output_type(mtx.vout.at(0).scriptPubKey, output_bytes, result);
			outputs.push_back(std::make_tuple(output_type, output_bytes));
			int output_length = mtx.vout.size();
			for (int output_index = 1; output_index < output_length; output_index++) {
				std::vector<unsigned char> output_bytes_x;
				OutputScriptType output_type_x = get_output_type(mtx.vout.at(output_index).scriptPubKey, output_bytes_x, result);
				if (output_type != output_type_x) {
					output_type_identical = false;
				}
				outputs.push_back(std::make_tuple(output_type_x, output_bytes_x));
			}
			if (output_type_identical) {
				output_byte ^= output_type << 5;
			}

    		/* Push Output Byte 
    			"xxx": Sequence
				"xx": Output Count
    			"xxx": Output type
    		*/
			transaction_result_bytes.push_back(output_byte);
			result += "Output Byte = "+int_to_hex(output_byte)+"\n";

			/* Push Coinbase Byte 
				"x": Coinbase Encoding
			*/
			unsigned char coinbase_byte = 0;
			if (coinbase) coinbase_byte |= 0x01;
			result += "Coinbase Byte = "+int_to_hex(coinbase_byte)+"\n";
			transaction_result_bytes.push_back(coinbase_byte);

			/* Push Version VarInt
				If the Version was not encoded in the Info bit, Encode it as a VarInt here. 
			*/
			if (!(input_byte & 0x03)) { 
				std::vector<unsigned char> version_varint = to_varint(mtx.nVersion);
				result += "Version VarInt = "+HexStr(version_varint)+"\n";
				transaction_result_bytes.insert(transaction_result_bytes.end(), version_varint.begin(), version_varint.end());
			}

    		/* Push Input Count 
    			If the Input Count is greater then 3, then Encode the Input Count as a VarInt.
    		*/
    		if (!(input_byte & 0x0c)) {
    			std::vector<unsigned char> input_count_varint = to_varint(mtx.vin.size());
    			result += "Input Count VarInt = "+HexStr(input_count_varint)+"\n";
				transaction_result_bytes.insert(transaction_result_bytes.end(), input_count_varint.begin(), input_count_varint.end());
    		}

			/* Push Input Type 
				"01": Non Identical Input Types, Less then 4 Inputs, Encode as a Singe Byte
			*/
			if (((input_byte & 0x30) >> 2) == 0x01) {
				unsigned char input_type_byte = 0;

				int input_length = inputs.size();
				for (int input_index = 0; input_index < input_length; input_index++) {
					std::tuple<InputScriptType, std::vector<unsigned char>> input_tuple = inputs.at(input_index);
					InputScriptType input_type = std::get<0>(input_tuple);
					input_type_byte |= input_type << (6-input_index);
				}

				result += "Input Type Byte = "+int_to_hex(input_type_byte)+"\n";
				transaction_result_bytes.push_back(input_type_byte);
			}

    		/* Push LockTime
    			If the locktime was not zero and this is not a coinbase transaction, Encode the two least signafigant bytes as Hex 
    			If the locktime was not zero and this is a coinbase transaction, encode the LockTime as a VarInt. 
    		*/
    		if ((input_byte & 0xc0) == 0x01) {
    			int twobytelimit = pow(2, 16);
    			int bytelimit = pow(2, 8);
    			unsigned char first_half = (mtx.nLockTime % twobytelimit) >> 8;
    			unsigned char second_half = mtx.nLockTime % bytelimit;
    			result += "Shortend Locktime = "+int_to_hex(first_half)+int_to_hex(second_half)+"\n";
				transaction_result_bytes.push_back(first_half);
				transaction_result_bytes.push_back(second_half);
    		} else if ((input_byte & 0xc0) == 0x03) {
    			std::vector<unsigned char> locktime_varint = to_varint(mtx.nLockTime);
    			result += "Locktime VarInt = "+HexStr(locktime_varint)+"\n";
				transaction_result_bytes.insert(transaction_result_bytes.end(), locktime_varint.begin(), locktime_varint.end());
    		}

			/* Push Sequence 
				"001": Identical Sequence, Non Standard, Encode as a Single VarInt
				"010": Non Identical Sequence, Standard Encoding with less the 4 inputs, Encode as a Single Byte
			*/
			if ((output_byte & 0x07) == 0x01) {
				/* Push the Sequnece VarInt for the Inputs */
				std::vector<unsigned char> sequence_varint = to_varint(sequences.at(0));
				result += "Sequence VarInt = "+HexStr(sequence_varint)+"\n";
				transaction_result_bytes.insert(transaction_result_bytes.end(), sequence_varint.begin(), sequence_varint.end());
			} else if ((output_byte & 0x07) == 0x02) {
				unsigned char sequence_byte;
				int sequence_length = sequences.size();
				for (int sequence_index = 0; sequence_index < sequence_length; sequence_index++) {
					switch(sequences.at(sequence_index))
					{
						case SEQUENCE_F0: 
						{
							sequence_byte |= 1 << (sequence_index*2);
							break;     
						}
						case SEQUENCE_FE: 
						{
							sequence_byte |= 1 << ((sequence_index*2)+1);
							break;     
						}
						case SEQUENCE_FF: 
						{
							sequence_byte |= 1 << ((sequence_index*2)+1);
							sequence_byte |= 1 << ((sequence_index*2));
							break;     
						}
					}
				}
				result += "Sequence Byte = "+int_to_hex(sequence_byte)+"\n";
				transaction_result_bytes.push_back(sequence_byte);
			}

			/* Push Output Count 
				If the Output Count is greater then 3, then Encode the Output Count as a VarInt.
			*/
			if (!(output_byte & 0x18)) {
				std::vector<unsigned char> output_count_varint = to_varint(mtx.vout.size());
				result += "Output Count VarInt = "+HexStr(output_count_varint)+"\n";
				transaction_result_bytes.insert(transaction_result_bytes.end(), output_count_varint.begin(), output_count_varint.end());
			}
			
		
			result += "^^^^^^^^^^^^^BYTES^^^^^^^^^^^^^^\n";

    		input_length = mtx.vin.size();
    		for (int input_index = 0; input_index < input_length; input_index++) {
    			result += "Input Index = "+std::to_string(input_index)+"\n";

    			/* Push Sequence 
    				"000": Uncompressed Sequence, Encode VarInt
    			*/
				if ((output_byte & 0x07) == 0x00) {
    				std::vector<unsigned char> sequence_varint = to_varint(mtx.vin.at(input_index).nSequence);
					result += "Sequence VarInt = "+HexStr(sequence_varint)+"\n";
					transaction_result_bytes.insert(transaction_result_bytes.end(), sequence_varint.begin(), sequence_varint.end());
    			}

   				std::tuple<InputScriptType, std::vector<unsigned char>> input_result = inputs.at(input_index);
				InputScriptType input_type = std::get<0>(input_result);
				std::vector<unsigned char> input_script = std::get<1>(input_result);

    			/* Push Input Type */
				if (!(input_byte & 0x30)) {
    				result += "Input Type = "+std::to_string(input_type)+"\n";
					transaction_result_bytes.push_back(input_type);
    			} 

    			bool txid_found = false;
    			if (!coinbase) {
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
    				int blocks_length = block.vtx.size();
    				for (int blocks_index = 0; blocks_index < blocks_length; blocks_index++) {
    					if ((*block.vtx.at(blocks_index)).GetHash() == txid) {
    						txid_found = true;
    						int block_index = blocks_index;

    						/* Push Block Height */
    						std::vector<unsigned char> block_height_varint = to_varint(block_height);
    						result += "Block Height VarInt = "+HexStr(block_height_varint)+"\n";
							transaction_result_bytes.insert(transaction_result_bytes.end(), block_height_varint.begin(), block_height_varint.end());

    						/* Push Block Index */
    						std::vector<unsigned char> block_index_varint = to_varint(block_index);
    						result += "Block Index VarInt = "+HexStr(block_index_varint)+"\n";
							transaction_result_bytes.insert(transaction_result_bytes.end(), block_index_varint.begin(), block_index_varint.end());
    						break;
    					}
    				}
    			}

				if (!txid_found && !coinbase) {
					/* Push TXID */
					std::vector<unsigned char> txid;
					std::string hex = mtx.vin.at(input_index).prevout.hash.GetHex();
					result = "Original Hex = "+hex+"\n";
					int length = hex.length()/2;
					for (int i = 0; i < length; i++) {
						txid.push_back(strtol(hex.substr(i*2, 2).c_str(), NULL, 16));
					}
					//TODO: get bytes directly?
					result = "TXID Hex = "+HexStr(txid)+"\n";
					transaction_result_bytes.insert(transaction_result_bytes.end(), txid.begin(), txid.end());
				}
				if (!coinbase) {
					/* Push Vout */
					result += "Vout = "+std::to_string(mtx.vin.at(input_index).prevout.n)+"\n";
					std::vector<unsigned char> vout_varint = to_varint(mtx.vin.at(input_index).prevout.n);
					result += "Vout VarInt = "+HexStr(vout_varint)+"\n";
					transaction_result_bytes.insert(transaction_result_bytes.end(), vout_varint.begin(), vout_varint.end());
				}

    			/* Push Input 
    				"00": Custom Input
    				_: Compressed Input
    			*/
    			if (input_type == CustomInput) {
					//TODO: get bytes directly?
    				CScript script = mtx.vin.at(input_index).scriptSig;
    				int script_length = script.size();
    				std::vector<unsigned char> script_length_varint = to_varint(script_length);

					/* Push Script Length */
					result += "Script Length VarInt = "+HexStr(script_length_varint)+"\n";
					transaction_result_bytes.insert(transaction_result_bytes.end(), script_length_varint.begin(), script_length_varint.end());

					/* Push Script */
					result += "Script = "+HexStr(script)+"\n";
					transaction_result_bytes.insert(transaction_result_bytes.end(), script.begin(), script.end());

    				int witness_count = mtx.vin.at(input_index).scriptWitness.stack.size();
    				std::vector<unsigned char> witness_count_varint = to_varint(witness_count);

					/* Push Witness Count */
					result += "Witness Count VarInt = "+HexStr(witness_count_varint)+"\n";
					transaction_result_bytes.insert(transaction_result_bytes.end(), witness_count_varint.begin(), witness_count_varint.end());

    				for (int witnesses_index = 0; witnesses_index < witness_count; witnesses_index++) {
    					int witness_length = mtx.vin.at(input_index).scriptWitness.stack.at(witnesses_index).size();
    					std::vector<unsigned char> witness_length_varint = to_varint(witness_length);
    					std::vector<unsigned char> witness = mtx.vin.at(input_index).scriptWitness.stack.at(witnesses_index);

    					/* Push Witness Length */
						result += "Witness Length VarInt = "+HexStr(witness_length_varint)+"\n";
						transaction_result_bytes.insert(transaction_result_bytes.end(), witness_length_varint.begin(), witness_length_varint.end());

    					/* Push Witness */
						result += "Witness = "+HexStr(witness)+"\n";
						transaction_result_bytes.insert(transaction_result_bytes.end(), witness.begin(), witness.end());

    				}
    			} else {
    				result += "Signature = "+HexStr(input_script)+"\n";
					transaction_result_bytes.insert(transaction_result_bytes.end(), input_script.begin(), input_script.end());
    			}
    		}
    		result += "^^^^^^^^^INPUT^^^^^^^^^\n";

    		for (int output_index = 0; output_index < output_count; output_index++) {
    			OutputScriptType output_type = std::get<0>(outputs.at(output_index));
    			std::vector<unsigned char> output_bytes = std::get<1>(outputs.at(output_index));

    			/* Push Output Type 
    				"000": Uncompressed Output Type, Encode Next Byte
    			*/
    			if ((output_byte & 0xe0) == 0x00) {
    				result += "Output Type = "+int_to_hex(output_type)+"\n";
					transaction_result_bytes.push_back(output_type);
    			}

    			/* Push Amount */
			 	result += "Amount = "+std::to_string(mtx.vout.at(output_index).nValue)+"\n";
    			std::vector<unsigned char> amount_varint = to_varint(mtx.vout.at(output_index).nValue);
    			result += "Amount Hex VarInt = "+HexStr(amount_varint)+"\n";
				transaction_result_bytes.insert(transaction_result_bytes.end(), amount_varint.begin(), amount_varint.end());

    			/* Encode Output 
    				"001": Uncompressed Output, Custom Script
    				_: Push Script Hash Minus Op Code Bytes
    			*/
    			if ((output_byte & 0xe0) >> 5 == 0x01) {
    				CScript script = mtx.vout.at(output_index).scriptPubKey;
    				int script_length = script.size();
    				std::vector<unsigned char> script_length_varint = to_varint(script_length);

    				/* Push Script Length */
    				result += "Script Length VarInt = "+HexStr(script_length_varint)+"\n";
					transaction_result_bytes.insert(transaction_result_bytes.end(), script_length_varint.begin(), script_length_varint.end());

    				/* Push Script */
    				result += "Script = "+HexStr(script)+"\n";
					transaction_result_bytes.insert(transaction_result_bytes.end(), script.begin(), script.end());
    			} else {
    				/* Push Script */
    				result += "Script = "+HexStr(output_bytes)+"\n";
					transaction_result_bytes.insert(transaction_result_bytes.end(), output_bytes.begin(), output_bytes.end());
    			}
    		}
    		result += "^^^^^^^^^OUTPUT^^^^^^^^^\n";

			/* Transaction
				"xx"  : Input Byte
				"xx"  : Output Byte
				"xx"  : Coinbase Byte
				"?"   : Version VarInt      if (Input Byte & 0x03 == 0x00)
				"?"   : Input Count VarInt  if (Input Byte & 0x0c == 0x00)
				"xx"  : Input Type Byte     if (Input Byte & 0x30 == 0x01)
				"xxxx": LockTime Shortend   if (Input Byte & 0xc0 == 0x01)
				"?"   : LockTime VarInt     if (Input Byte & 0xc0 == 0x03)
				"?"   : Sequence VarInt     if (Output Byte & 0x07 == 0x01)
				"xx"  : Sequence Byte       if (Output Byte & 0x07 == 0x02)
				"?"   : Output Count VarInt if (Output Byte & 0x18 == 0x00)
				for each input {
					"?"        : Sequence VarInt          if (Output Byte & 0x07 == 0x00)
					"xx"       : Input Type Byte          if (Input Byte & 0x30 == 0x00)
					"?"        : TXID Block Height VarInt if (!coinbase)
					"?"        : TXID Block Index VarInt  if (!coinbase)
					"32 bytes" : TXID                     if (coinbase)
					"?"        : Signature Script Length VarInt if (input_type == CustomInput)
					"?"        : Signature Script               if (input_type == CustomInput)
					"?"        : Witness Count                  if (input_type == CustomInput)
					for each witness {
						"?" : Witness Length VarInt if (input_type == CustomInput)
						"?" : Witness               if (input_type == CustomInput)
					}
					"65 bytes" : Signature Script         if (input_type != CustomInput)
				}
				for each output {
					"xx"       : Output Type Byte         if (Output Byte & 0x07 == 0x00)
					"?"        : Amount VarInt
					"?"        : Script Length VarInt     if (output_type == CustomOutput)
					"?"        : Script                   
				}
			*/
			result += "compressed_transaction = |"+HexStr(transaction_result_bytes);
			return result;
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

			CMutableTransaction mtx;

			NodeContext& node = EnsureAnyNodeContext(request.context);
			ChainstateManager& chainman = EnsureChainman(node);
			Chainstate& active_chainstate = chainman.ActiveChainstate();
			active_chainstate.ForceFlushStateToDisk();
			BlockManager* blockman = &active_chainstate.m_blockman;

			std::string result;

			std::string compressed_transaction = request.params[0].get_str();
			std::vector<unsigned char> transaction_bytes = hex_to_bytes(compressed_transaction);
			result += "compressed_transaction = "+HexStr(transaction_bytes)+"\n";
			
			result += "transaction = ";
			int length = transaction_bytes.size();
			for (int i = 0; i < length; i++) {
				result += std::to_string(i)+": "+int_to_hex(transaction_bytes.at(i))+", ";
			}
			result += ";\n";

			int index =	0;

    		/* parse Input Byte 
    			"xx": Version Encoding
    			"xx": Input Count
				"xx": Input Type
    			"xx": LockTime Encoding
    		*/
			unsigned char input_byte = transaction_bytes.at(index);
			result += "Input Byte = "+int_to_hex(input_byte)+"\n";
			index += 1;
			
			/* Parse Version
				0x01-0x03: Version Encoded Directly
				0x00: Version Encoded As VarInt
			*/
			unsigned char version_byte = input_byte & 0x03;
			if (version_byte != 0x00) {
				mtx.nVersion = version_byte;
			}

			/* Parse Input Count
				0x01-0x03: Input Count Directly
				0x00: Input Count Encoded As VarInt
			*/
			unsigned char input_count_byte = (input_byte & 0x0d) >> 2;

			/* Parse Input Type 
				0x00: More then 3 Inputs, Non Identical Script Types.
				0x01: Less then 4 Inputs, Non Identical Script Types.
				0x02: Identical Script Types, Custom Script.
				0x03: Identical Script Types, Legacy, Segwit, or Taproot.
			*/
			unsigned char input_type_byte = (input_byte & 0x30) >> 4;
			result += "input_type_byte = "+int_to_hex(input_type_byte)+"\n";

    		/* Parse Lock Time
				0x03: Locktime 0
				0x02: Locktime Encoded 2 LSBytes
				0x00: Locktime Encoded As VarInt
    		*/
			unsigned char locktime_byte = (input_byte & 0xc0) >> 6;

    		/* Parse Output Byte 
    			"xxx": Sequence
				"xx": Output Count
    			"xxx": Output type
    		*/
			unsigned char output_byte = transaction_bytes.at(index);
			result += "Output Byte = "+int_to_hex(output_byte)+"\n";
			index += 1;

			/* Parse Squence 
				0x00: Non Identical, Non Standard Sequence/Inputs more then 3. Read Sequence Before Each Input.
				0x01: Identical, Non Standard Sequence. Read VarInt for Full Sequnce.
				0x02: Non Identical, Standard Sequence, Inputs less then 4. Read Next Byte For Encoded Sequences.
				0x03: Identical, Standard Sequence. 0xFFFFFFF0
				0x04: Identical, Standard Sequence. 0xFFFFFFFE
				0x05: Identical, Standard Sequence. 0xFFFFFFFF
				0x06: Identical, Standard Sequence. 0x00000000
				0x07: Null.
			*/
			unsigned char sequence_byte = (output_byte & 0x07);
			long int sequence;
			if (sequence_byte == 0x03) {
				sequence = SEQUENCE_F0;
			} else if (sequence_byte == 0x04) {
				sequence = SEQUENCE_FE;
			} else if (sequence_byte == 0x05) {
				sequence = SEQUENCE_FF;
			} else if (sequence_byte == 0x06) {
				sequence = 0x00;
			}

			/* Parse Output Count
				0x01-0x03: Output Count
				0x00: Output Count VarInt
			*/
			unsigned char output_count_byte = (output_byte & 0x18) >> 3; 

			/* Parse Output Type 
				0x01-0x07: Output Script Type
				0x00: Custom Output
			*/
			unsigned char output_type_byte = (output_byte & 0xE0) >> 5; 

    		/* Parse Coinbase Byte 
    			"0x01": Coinbase
    		*/
			unsigned char coinbase_byte = transaction_bytes.at(index);
			index += 1;

			/* Parse Version VarInt
				0x01-0x03: Version Encoded Drectly
				0x00: Version Encoded As VarInt.
			*/
			if (!version_byte) { 
				mtx.nVersion = from_varint(transaction_bytes, index, result);
			}

    		/* Parse Input Count 
				0x01-0x03: Input Count Encoded Drectly
				0x00: Input Count Encoded As VarInt.
    		*/
    		if (!input_count_byte) {
				input_count_byte = from_varint(transaction_bytes, index, result);
    		}

    		/* Parse Input Type 
    			0x01: Up To Four Input Types Encoded As A Single Byte.
    		*/
			unsigned char input_type_encoded_byte = 0;
    		if (input_type_byte == 0x01) {
				input_type_encoded_byte = transaction_bytes.at(index);
				index += 1;
    		}

    		/* Parse LockTime
				0x01: Shortend LockTime Encoded In Two Bytes.
				0x03: LockTime Encoded As VarInt.
    		*/
			std::tuple<unsigned char, unsigned char> shortend_locktime;
    		if (locktime_byte == 0x01) {
				shortend_locktime = std::make_tuple(transaction_bytes.at(index), transaction_bytes.at(index+1));
				index += 2;
    		} else if ((input_byte & 0xc0) == 0x03) {
				mtx.nLockTime = from_varint(transaction_bytes, index, result);
    		}

    		/* Parse Sequence 
    			0x01: Sequence Encoded as VarInt
				0x02: Sequence Encoded Byte
    		*/
			unsigned char sequence_encoded_byte;
    		if (sequence_byte == 0x01) {
				sequence = from_varint(transaction_bytes, index, result);
    		} else if (sequence_byte == 0x02) {
				sequence_encoded_byte = transaction_bytes.at(index);
				index += 1;
    		}

    		/* Parse Output Count 
				0x01-0x03: Output Count Encoded Drectly
				0x00: Output Count Encoded as VarInt
    		*/
    		if (!output_count_byte) {
				output_count_byte = from_varint(transaction_bytes, index, result);
    		}
    		
    		result += "^^^^^^^^^^^^^BYTES^^^^^^^^^^^^^^\n";
			std::vector<unsigned char> half_finished_inputs, hash_types;
			std::vector<std::vector<unsigned char>> compressed_signatures;
			std::vector<CTxIn> vin;
			for (int input_index = 0; input_index < input_count_byte; input_index++) {
				result += "---index = "+std::to_string(input_index)+"\n";
				/* Parse Sequence 
					0x00: Sequence VarInt
					0x02: Sequence Encoded Byte
				*/
				if (!sequence_byte) {
					sequence = from_varint(transaction_bytes, index, result);
				} else if (sequence_byte == 0x02) {
					unsigned char sequence_encoding = (sequence_encoded_byte & (0x03 << input_index)) >> input_index;
					if (sequence_encoding == 0x00) {
						sequence = 0x00; 
					} else if (sequence_encoding == 0x01) {
						sequence = SEQUENCE_F0;
					} else if (sequence_encoding == 0x02) {
						sequence = SEQUENCE_FE;
					} else if (sequence_encoding == 0x03) {
						sequence = SEQUENCE_FF;
					}
				}

				/* Parse Input Type 
					0x00: Input Type Was Uncomrpessed Read Next Byte
					0x01: Input Type Was Already Parsed, Set Temp Var
					0x02: All Inputs Identical, Input is Custom Type
					0x03: All Inputs Identical, Input is Compressed
				*/
				bool custom_input_type = false;
				if (input_type_byte == 0x00) {
					custom_input_type = !transaction_bytes.at(index);
					index += 1;
				} else if (input_type_byte == 0x01) {
					custom_input_type = !((input_type_encoded_byte & (0x03 << input_index)) >> input_index);
				} else if (input_type_byte == 0x02) {
					custom_input_type = true;
				}
				result += "custom_input_type = "+std::to_string(custom_input_type)+"\n";

				int vout;
				uint256 txid;
				if (!coinbase_byte) {
					/* Parse TXID */
					std::vector<unsigned char> txid_bytes(32);
					copy(transaction_bytes.begin()+index, transaction_bytes.begin()+index+32+1, txid_bytes.begin());
					//TODO: set bytes directly
					txid.SetHex(HexStr(txid_bytes));
					result += "TXID = "+txid.GetHex()+"\n";

					Consensus::Params consensus_params;
					uint256 hash;
					CTransactionRef tr = GetTransaction(nullptr, nullptr, txid, consensus_params, hash);

					if (tr == nullptr) {
						long int block_height = from_varint(transaction_bytes, index, result);
						long int block_index = from_varint(transaction_bytes, index, result);

						result += "Block Height = "+std::to_string(block_height)+"\n";
						result += "Block Index = "+std::to_string(block_index)+"\n";

						std::vector<CBlockIndex*> blocks;
						blocks = blockman->GetAllBlockIndices();
						int blocks_length = blocks.size();
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
								CTransactionRef tr = GetTransaction(nullptr, nullptr, txid, consensus_params, hash);
								if (tr == nullptr) {
									result += "Could not find txid\n";
									return result;
								}
								result += "TXID = "+txid.GetHex()+"\n";
							}
						}
					} else {
						index += 32;
					}

					/* Parse Vout */
					vout = from_varint(transaction_bytes, index, result);
				} else {
					txid.SetHex("0x00");
					vout = 4294967295;
				}
				result += "Vout = "+std::to_string(vout)+"\n";
				
				/* Parse Input 
					0x00: Custom Input Type
					0x01-0x11: Compressed Input Type, Read Data Complete it After
				*/
				std::vector<std::vector<unsigned char>> stack;
				CScript script;
				if (custom_input_type) {
					/* Parse Script Length */
					int script_length = from_varint(transaction_bytes, index, result);
					result += "Script Length = "+std::to_string(script_length)+"\n";

					/* Parse Script */
					std::vector<unsigned char> script_bytes(script_length);
					copy(transaction_bytes.begin()+index, transaction_bytes.begin()+index+script_length+1, script_bytes.begin());
					index += script_length;
					result += "Script = "+HexStr(script_bytes)+"\n";
					script = CScript(script_bytes.begin(), script_bytes.end());

					/* Parse Witness Count */
					int witness_count = from_varint(transaction_bytes, index, result);
					result += "Witness Script Count = "+std::to_string(witness_count)+"\n";

					for (int witnesses_index = 0; witnesses_index < witness_count; witnesses_index++) {

						/* Parse Witness Length */
						int witness_script_length = from_varint(transaction_bytes, index, result);
						result += "Witness Script Length = "+std::to_string(witness_script_length)+"\n";

						/* Parse Witness Script */
						std::vector<unsigned char> witness_script_bytes(script_length);
						copy(transaction_bytes.begin()+index, transaction_bytes.begin()+index+witness_script_length+1, witness_script_bytes.begin());
						index += witness_script_length;
						result += "Witness Script = "+HexStr(witness_script_bytes)+"\n";
						stack.push_back(witness_script_bytes);
					}
				} else {
					result += "Indexc = "+std::to_string(index)+"\n";
					std::vector<unsigned char> compressed_signature(64);
					copy(transaction_bytes.begin()+index, transaction_bytes.begin()+index+64+1, compressed_signature.begin());
					result += "Compressed Signature = "+HexStr(compressed_signature)+"\n";
					index += 64;
					result += "Indexc = "+std::to_string(index)+"\n";
					unsigned char sig_hash_type = transaction_bytes.at(index);
					result += "Hash Type = "+int_to_hex(sig_hash_type)+"\n";
					index += 1;
					compressed_signatures.push_back(compressed_signature);
					half_finished_inputs.push_back(input_index);
					hash_types.push_back(sig_hash_type);
				}

    				/* Assemble CTxIn */
    				COutPoint outpoint;
    				outpoint = COutPoint(txid, vout);
    				CTxIn ctxin = CTxIn(outpoint, script, sequence);
    				ctxin.scriptWitness.stack = stack;
    				vin.push_back(ctxin);
			}
			mtx.vin = vin;
			result += "^^^^^^^^^^^^^^^^^^^^INPUT^^^^^^^^^^^^^^^^^^\n";

			std::vector<CTxOut> vout;
			for (int output_index = 0; output_index < output_count_byte; output_index++) {
				/* Parse Output Type 
					0x00: Output Type Encoded In Next Byte
					0x01-0x07: Type Encoded Directly
				*/
				unsigned char output_type;
				if (!output_type_byte) {
					/* Parse Output Type */
					output_type = transaction_bytes.at(index);
					index += 1;
				} else {
					output_type = output_type_byte;
				}
				result += "Output Type = "+int_to_hex(output_type)+"\n";

				/* Parse Amount */
				result += "Index = "+std::to_string(index)+"\n";
				result += "Index = "+int_to_hex(transaction_bytes.at(index))+"\n";
				CAmount amount = from_varint(transaction_bytes, index, result);
				result += "Amount = "+std::to_string(amount)+"\n";

				/* Parse Output 
					0x01: Custom Script
					0x02: P2PK
					0x03: P2SH
					0x04: P2PKH
					0x05: P2WSH
					0x06: P2WPKH
					0x07: P2TR
				*/
				CScript output_script;
				if (output_type == 0x01) {
					/* Parse Script Length */
					int script_length = from_varint(transaction_bytes, index, result);
					result += "Script Length = "+std::to_string(script_length)+"\n";

					/* Parse Script */
					std::vector<unsigned char> script_bytes(script_length);
					copy(transaction_bytes.begin()+index, transaction_bytes.begin()+index+script_length+1, script_bytes.begin());
					index += script_length;
					output_script = CScript(script_bytes.begin(), script_bytes.end());
				} else if (output_type == 0x02) {
					std::vector<unsigned char> script_bytes(67);
					script_bytes[0] = 0x41;
					copy(transaction_bytes.begin()+index, transaction_bytes.begin()+index+65+1, script_bytes.begin()+1);
					index += 65;
					script_bytes[66] =	0xac;
					output_script = CScript(script_bytes.begin(), script_bytes.end());
				} else if (output_type == 0x03) {
					std::vector<unsigned char> script_bytes(23);
					script_bytes[0] =0xa9;
					script_bytes[1] = 0x14;
					copy(transaction_bytes.begin()+index, transaction_bytes.begin()+index+20+1, script_bytes.begin()+2);
					index += 20;
					script_bytes[22] =	0x87;
					output_script = CScript(script_bytes.begin(), script_bytes.end());
				} else if (output_type == 0x04) {
					std::vector<unsigned char> script_bytes(25);
					script_bytes[0] = 0x76;
					script_bytes[1] = 0xa9;
					script_bytes[2] = 0x14;
					copy(transaction_bytes.begin()+index, transaction_bytes.begin()+index+20+1, script_bytes.begin()+3);
					index += 20;
					script_bytes[23] =	0x88;
					script_bytes[24] =	0xac;
					output_script = CScript(script_bytes.begin(), script_bytes.end());
				} else if (output_type == 0x05) {
					std::vector<unsigned char> script_bytes(34);
					script_bytes[0] = 0x00;
					script_bytes[1] = 0x20;
					copy(transaction_bytes.begin()+index, transaction_bytes.begin()+index+32+1, script_bytes.begin()+2);
					index += 32;
					output_script = CScript(script_bytes.begin(), script_bytes.end());
				} else if (output_type == 0x06) {
					std::vector<unsigned char> script_bytes(22);
					script_bytes[0] = 0x00;
					script_bytes[1] = 0x14;
					copy(transaction_bytes.begin()+index, transaction_bytes.begin()+index+20+1, script_bytes.begin()+2);
					index += 20;
					output_script = CScript(script_bytes.begin(), script_bytes.end());
				} else if (output_type == 0x07) {
					std::vector<unsigned char> script_bytes(34);
					script_bytes[0] = 0x51;
					script_bytes[1] = 0x20;
					copy(transaction_bytes.begin()+index, transaction_bytes.begin()+index+32+1, script_bytes.begin()+2);
					index += 32;
					output_script = CScript(script_bytes.begin(), script_bytes.end());
				}
				result += "Output Script = "+HexStr(output_script)+"\n";
				vout.push_back(CTxOut(amount, output_script));
			}
			mtx.vout = vout;
			result += "^^^^^^^^^OUTPUT^^^^^^^^^\n";

			secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
			int partial_inputs_length = half_finished_inputs.size();
			for (int partial_inputs_index = 0; partial_inputs_index < partial_inputs_length; partial_inputs_index++) {
				int input_index = half_finished_inputs.at(partial_inputs_index);
				result += "Half Finished Input "+std::to_string(partial_inputs_index)+", "+std::to_string(input_index)+"---------------------\n";

				uint256 block_hash;
				Consensus::Params consensusParams;
				CTransactionRef prev_tx = GetTransaction(NULL, NULL, mtx.vin.at(input_index).prevout.hash, consensusParams, block_hash);
				CMutableTransaction prev_mtx = CMutableTransaction(*prev_tx);
				CScript script_pubkey = (*prev_tx).vout.at(mtx.vin.at(input_index).prevout.n).scriptPubKey;
				CAmount amount = (*prev_tx).vout.at(mtx.vin.at(input_index).prevout.n).nValue;
				std::vector<unsigned char> output_bytes;
				OutputScriptType prev_output_type = get_output_type(script_pubkey, output_bytes, result);

				result += "Script Pubkey = "+HexStr(script_pubkey)+"\n";
				result += "Amount = "+std::to_string(amount)+"\n";

				std::vector<secp256k1_ecdsa_recoverable_signature> recovered_signatures;
				secp256k1_ecdsa_recoverable_signature rsig;
				if (prev_output_type == P2PKH || prev_output_type == P2WPKH) {
					result += "ECDSA\n";
					std::vector<unsigned char> compact_signature = compressed_signatures.at(partial_inputs_index);
					for (int recovery_index = 0; recovery_index < 4; recovery_index++) {
						/* Parse the compact signature with each of the 4 recovery IDs */
						int r = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, &compact_signature[0], recovery_index);
						if (r == 1) {
							recovered_signatures.push_back(rsig);
						}
					}
				}

				bool locktime_found = true;
				if (locktime_byte == 0x01) {
					locktime_found = false;
				}
				bool first = true;
				while(!locktime_found || first) {
					first = false;
	
					std::vector<std::tuple<secp256k1_pubkey, secp256k1_ecdsa_recoverable_signature>> pairs;
					std::vector<unsigned char> public_key_bytes;
					if (prev_output_type == P2PKH) {
						
						/* Hash the Trasaction to generate the SIGHASH */
						result += "Hash Type = "+int_to_hex(hash_types.at(partial_inputs_index))+"\n";
						uint256 hash = SignatureHash(script_pubkey, mtx, input_index, hash_types.at(partial_inputs_index), amount, SigVersion::BASE);
						//TODO: get bytes directly
						std::string hex = hash.GetHex();
						std::vector<unsigned char> message = hex_to_bytes(hex);
						std::reverse(message.begin(), message.end());
						result += "message = "+HexStr(message)+"\n";
						
						/* Dervive Sig Public Key Pairs */
						int recovered_signatures_length = recovered_signatures.size();
						for (int recovered_signatures_index = 0; recovered_signatures_index < recovered_signatures_length; recovered_signatures_index++) {
							/* Run Recover to get the Pubkey for the given Recovered Signature and Message/SigHash (Fails half the time(ignore)) */
							secp256k1_pubkey pubkey;
							int r = secp256k1_ecdsa_recover(ctx, &pubkey, &recovered_signatures.at(recovered_signatures_index), &message[0]);
							if (r == 1) {
								pairs.push_back(std::make_tuple(pubkey, recovered_signatures.at(recovered_signatures_index)));
							}
						}

						secp256k1_ecdsa_signature sig;
						bool pubkey_found = false;
						int pairs_length = pairs.size();
						for (int pairs_index = 0; pairs_index < pairs_length; pairs_index++) {
							secp256k1_pubkey pubkey = std::get<0>(pairs.at(pairs_index));
							secp256k1_ecdsa_recoverable_signature recoverable_signature = std::get<1>(pairs.at(pairs_index));

							/* Serilize Compressed Pubkey */
							std::vector<unsigned char> compressed_pubkey (33);
							size_t c_size = 33;
							secp256k1_ec_pubkey_serialize(ctx, &compressed_pubkey[0], &c_size, &pubkey, SECP256K1_EC_COMPRESSED);
							result += "COMPRESSED public key = "+HexStr(compressed_pubkey)+"\n";

							/* Hash Compressed Pubkey */
							uint160 c_pubkeyHash;
							CHash160().Write(compressed_pubkey).Finalize(c_pubkeyHash);
							std::vector<unsigned char> hashed_compressed_pubkey(20);
							copy(c_pubkeyHash.begin(), c_pubkeyHash.end(), hashed_compressed_pubkey.begin());
							std::reverse(hashed_compressed_pubkey.begin(), hashed_compressed_pubkey.end());
							result += "COMPRESSED public key Hash = "+HexStr(hashed_compressed_pubkey)+"\n";

							/* Construct Compressed ScriptPubKey */
							std::vector<unsigned char> compressed_script_bytes(25);
							compressed_script_bytes[0] = 0x76;
							compressed_script_bytes[1] = 0xa9;
							compressed_script_bytes[2] = 0x14;
							copy(hashed_compressed_pubkey.begin(), hashed_compressed_pubkey.end(), compressed_script_bytes.begin()+3);
							compressed_script_bytes[23] = 0x88;
							compressed_script_bytes[24] = 0xac;
							result += "COMPRESSED Script Pubkey = "+HexStr(compressed_script_bytes)+"\n";
							CScript compressed_script_pubkey = CScript(compressed_script_bytes.begin(),	compressed_script_bytes.end());

							/* Test Scripts */
							if (compressed_script_pubkey == script_pubkey) {
								result += "COMPRESSED matches\n";
								secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &recoverable_signature);
								pubkey_found = true;
								public_key_bytes = compressed_pubkey;
								break;
							}

							result += "-----------\n";

							/* Serilize Uncompressed Pubkey */
							std::vector<unsigned char> uncompressed_pubkey (65);
							size_t uc_size = 65;
							secp256k1_ec_pubkey_serialize(ctx, &uncompressed_pubkey[0], &uc_size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
							result += "UNCOMPRESSED public key = "+HexStr(uncompressed_pubkey)+"\n";

							/* Hash Uncompressed PubKey */
							uint160 uc_pubkeyHash;
							CHash160().Write(uncompressed_pubkey).Finalize(uc_pubkeyHash);
							//TODO: get bytes directly
							hex = uc_pubkeyHash.GetHex();
							std::vector<unsigned char> hashed_uncompressed_pubkey = hex_to_bytes(hex);
							std::reverse(hashed_uncompressed_pubkey.begin(), hashed_uncompressed_pubkey.end());
							result += "UNCOMPRESSED public key Hash = "+hex+"\n";

							/* Construct Uncompressed ScriptPubKey */
							std::vector<unsigned char> uncompressed_script_bytes(25);
							uncompressed_script_bytes[0] = 0x76;
							uncompressed_script_bytes[1] = 0xa9;
							uncompressed_script_bytes[2] = 0x14;
							copy(hashed_uncompressed_pubkey.begin(), hashed_uncompressed_pubkey.end(), uncompressed_script_bytes.begin()+3);
							uncompressed_script_bytes[23] = 0x88;
							uncompressed_script_bytes[24] = 0xac;
							result += "UNCOMPRESSED Script Pubkey = "+HexStr(uncompressed_pubkey)+"\n";
							CScript uncompressed_script_pubkey = CScript(uncompressed_script_bytes.begin(),	uncompressed_script_bytes.end());

							/* Test Scripts */
							if (uncompressed_script_pubkey == script_pubkey) {
								secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &recoverable_signature);
								pubkey_found = true;
								public_key_bytes = uncompressed_pubkey;
								break;
							}
						}
						if (pubkey_found) {
							result += "FOUND\n";
							locktime_found = true;
							std::vector<unsigned char> sig_der (71);
							size_t sig_der_size = 71;
							secp256k1_ecdsa_signature_serialize_der(ctx, &sig_der[0], &sig_der_size, &sig);
							sig_der_size += 1;
							std::vector<unsigned char> signature (sig_der_size+1+1+public_key_bytes.size());
							signature[0] = sig_der_size;
							copy(sig_der.begin(), sig_der.end(), signature.begin()+1);
							result += "Sig hash type = "+std::to_string(hash_types.at(partial_inputs_index))+"\n";
							signature[sig_der_size] = hash_types.at(partial_inputs_index);
							signature[sig_der_size+1] = public_key_bytes.size();
							result += "Signature = "+HexStr(signature)+"\n";
							copy(public_key_bytes.begin(), public_key_bytes.end(), signature.begin()+sig_der_size+2);
							CScript scriptSig = CScript(signature.begin(), signature.end());
							mtx.vin.at(input_index).scriptSig = scriptSig;
						}
					} else if (prev_output_type == P2WPKH) {
						result += "V0_P2WPKH\n";
						/* Construct Script Code*/
						std::vector<unsigned char> script_pubkey_bytes;
						int r = get_first_push_bytes(script_pubkey_bytes, script_pubkey);
						if (!r) return result;
						std::vector<unsigned char> script_code_bytes(25);
						script_code_bytes[0] = 0x76;
						script_code_bytes[1] = 0xa9;
						script_code_bytes[2] = 0x14;
						copy(script_pubkey_bytes.begin(), script_pubkey_bytes.end(), script_code_bytes.begin()+3);
						script_code_bytes[23] = 0x88;
						script_code_bytes[24] = 0xac;
						result += "Script Code = "+HexStr(script_code_bytes)+"\n"; 
						CScript script_code = CScript(script_code_bytes.begin(), script_code_bytes.end()); 

						/* Hash the Trasaction to generate the SIGHASH */
						uint256 hash = SignatureHash(script_code, mtx, input_index, hash_types.at(partial_inputs_index), amount, SigVersion::WITNESS_V0);
						std::vector<unsigned char> message(32);
						copy(hash.begin(), hash.end(), message.begin());
						std::reverse(message.begin(), message.end());
						result += "message = "+HexStr(message)+"\n";

						/* Run Recover to get the Pubkey for the given Recovered Signature and Message/SigHash (Fails half the time(ignore)) */
						int recovered_signatures_length = recovered_signatures.size();
						for (int recovered_signatures_index = 0; recovered_signatures_index < recovered_signatures_length; recovered_signatures_index++) {
							secp256k1_pubkey pubkey;
							int r = secp256k1_ecdsa_recover(ctx, &pubkey, &recovered_signatures.at(recovered_signatures_index), &message[0]);
							if (r == 1) {
								result += "SUCCESS\n";
								pairs.push_back(std::make_tuple(pubkey, recovered_signatures.at(recovered_signatures_index)));
							}
						}

						bool pubkey_found = false;
						int pairs_length = pairs.size();
						secp256k1_ecdsa_signature sig;
						for (int pairs_index = 0; pairs_index < pairs_length; pairs_index++) {
							secp256k1_pubkey pubkey = std::get<0>(pairs.at(pairs_index));
							secp256k1_ecdsa_recoverable_signature recoverable_signature = std::get<1>(pairs.at(pairs_index));

							/* Serilize Compressed Pubkey */
							std::vector<unsigned char> compressed_pubkey (33);
							size_t compressed_pubkey_size = 33;
							secp256k1_ec_pubkey_serialize(ctx, &compressed_pubkey[0], &compressed_pubkey_size, &pubkey, SECP256K1_EC_COMPRESSED);
							result += "COMPRESSED public key = "+HexStr(compressed_pubkey)+"\n";

							/* Hash Compressed Pubkey */
							uint160 compressed_pubkey_hash;
							CHash160().Write(compressed_pubkey).Finalize(compressed_pubkey_hash);
							std::vector<unsigned char> compressed_pubkey_hash_bytes(20);
							copy(compressed_pubkey_hash.begin(), compressed_pubkey_hash.end(), compressed_pubkey_hash_bytes.begin());
							std::reverse(compressed_pubkey_hash_bytes.begin(), compressed_pubkey_hash_bytes.end());
							result += "COMPRESSED public key Hash = "+HexStr(compressed_pubkey_hash_bytes)+"\n";

							/* Construct Compressed ScriptPubKey */
							std::vector<unsigned char> compressed_script_pubkey_bytes(22);
							compressed_script_pubkey_bytes[0] = 0x00;
							compressed_script_pubkey_bytes[1] = 0x14;
							copy(compressed_pubkey_hash_bytes.begin(), compressed_pubkey_hash_bytes.end(), compressed_script_pubkey_bytes.begin()+2);
							result += "COMPRESSED Script Pubkey = "+HexStr(compressed_script_pubkey_bytes)+"\n";
							CScript compressed_script_pubkey = CScript(compressed_script_pubkey_bytes.begin(), compressed_script_pubkey_bytes.end());
	
							/* Test Scripts */
							if (compressed_script_pubkey == script_pubkey) {
								result += "index = "+std::to_string(pairs_index)+"\n";
								secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &recoverable_signature);
								pubkey_found = true;
								public_key_bytes = compressed_pubkey;
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
					} 
////else if (byte == 6) {
////					result += "P2TR\n";
////					std::vector<unsigned char> schnorr_signature = hex_to_bytes(compressed_signatures.at(partial_inputs_index));
////					if (!locktime_found) {
////						/* Script Execution Data Init */
////						ScriptExecutionData execdata;
////						execdata.m_annex_init = true;
////						execdata.m_annex_present = false;

////						/* Prevout Init */
////						PrecomputedTransactionData cache;
////						std::vector<CTxOut> utxos;
////						int input_length = mtx.vin.size();
////						for (int input_index_2 = 0; input_index_2 < input_length; input_index_2++) {
////							uint256 block_hash;
////							CTransactionRef prev_tx = GetTransaction(NULL, NULL, mtx.vin.at(input_index_2).prevout.hash, consensusParams, block_hash);
////							// CMutableTransaction prev_mtx = CMutableTransaction(*prev_tx);
////							CScript script = (*prev_tx).vout.at(mtx.vin.at(input_index_2).prevout.n).scriptPubKey;
////							result += "prevout script = "+serialize_script(script)+"\n";
////							amount = (*prev_tx).vout.at(mtx.vin.at(input_index_2).prevout.n).nValue;
////							result += "amount = "+std::to_string(amount)+"\n";
////							utxos.emplace_back(amount, script);
////						}
////						cache.Init(CTransaction(mtx), std::vector<CTxOut>{utxos}, true);
////						result += "Locktime = "+std::to_string(mtx.nLockTime)+"\n";
////						uint256 hash;
////						int r = SignatureHashSchnorr(hash, execdata, mtx, input_index, hash_types.at(partial_inputs_index), SigVersion::TAPROOT, cache, MissingDataBehavior::FAIL);
////						if (!r) {
////							result += "FAILURE SCHNORR HASH\n";
////						}
////						hex = hash.GetHex();
////						result += "message = "+hex+"\n";
////						std::vector<unsigned char> bytes;
////						r = get_first_push_bytes(bytes, script_pubkey);
////						if (!r) {
////							result += "ISSUE: Could not get push bytes\n";
////						}
////						hex = bytes_to_hex(bytes);
////						result += "pubkey = "+hex+"\n";
////						// hex2 = serialize_script(script_pubkey).substr(4, 64);
////						// result += "pubkey = "+hex2+"\n";
////						result += "signature = "+bytes_to_hex(schnorr_signature)+"\n";
////						secp256k1_xonly_pubkey xonly_pubkey;
////						r = secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey, bytes.data());
////						if (!r) {
////							result += "FAILURE: ISSUE PUBKEY PARSE\n";
////						}
////						r = secp256k1_schnorrsig_verify(ctx, schnorr_signature.data(), hash.begin(), 32, &xonly_pubkey);
////						if (!r) {
////							result += "FAILURE: Issue verifiy\n";
////						} else {
////							locktime_found = true;
////						}
////					}
////					if (locktime_found) {
////						std::vector<std::vector<unsigned char>> stack;
////						if (hash_types.at(partial_inputs_index) != 0x00) {
////							schnorr_signature.push_back(hash_types.at(partial_inputs_index));	
////						}
////						stack.push_back(schnorr_signature);
////						result += "INSERTING "+std::to_string(input_index)+"\n";
////						mtx.vin.at(input_index).scriptWitness.stack = stack;
////					}
////				}
					/* If LockTime Has been Found Break, Otherwise add 2^16 to it and try again */
					mtx.nLockTime += pow(2, 16);
					result += "newlock = "+std::to_string(mtx.nLockTime)+"\n";
				}
			}
			CTransactionRef tx = MakeTransactionRef(CTransaction(mtx));
			return result+"|"+EncodeHexTx(*tx, RPCSerializationFlags());


////			result += "---------------------------------------------------\n";
////			result += "compressed transaction = "+compressed_transaction+"\n";

////			/* Init Vars */
////			int transaction_index = 0;
////			bool locktime_found = true;

////			/* Parse Info Byte 
////				"xx": Version Encoding
////				"xx": LockTime Encoding
////				"xx: Input Count
////				"xx": Output Count
////			*/
////			std::string hex = compressed_transaction.substr(transaction_index, 2);
////			transaction_index += 2;
////			std::string info_byte = hex_to_binary(hex);

////			std::string version_bits = info_byte.substr(0, 2);
////			result += "version_bits = "+version_bits+"\n";

////			std::string locktime_bits = info_byte.substr(2, 2);
////			result += "locktime_bits = "+locktime_bits+"\n";

////			std::string input_count_bits = info_byte.substr(4, 2);
////			result += "input_count_bits = "+input_count_bits+"\n";

////			std::string output_count_bits = info_byte.substr(6, 2);
////			result += "output_count_bits = "+output_count_bits+"\n";

////			result += "Info Byte = "+info_byte+"\n";
////			result += "Info Byte Hex = "+hex+"\n";


////			/* Parse Version 
////				"00": Parse a VarInt
////				_: Parse Binary of version_bits for version
////			*/
////			if (version_bits == "00") {
////				std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
////				mtx.nVersion = std::get<0>(varint_result);
////				transaction_index += std::get<1>(varint_result);
////				result += "Version Hex Length = "+std::to_string(std::get<1>(varint_result))+"\n";
////			} else {
////				mtx.nVersion = binary_to_int("000000"+version_bits);
////			}
////			result += "Version = "+std::to_string(mtx.nVersion)+"\n";

////			/* Parse LockTime 
////				"00": Locktime is zero
////				"01": Locktime is only the two least signifigant bytes(Brute force later)
////				"11": Coinbase Transaction, Lock time encoded as a VarInt
////			*/
////			if (locktime_bits == "00") {
////				mtx.nLockTime = 0;
////			} else if (locktime_bits == "01") {
////				hex = compressed_transaction.substr(transaction_index, 4);
////				mtx.nLockTime = hex_to_int(hex);
////				locktime_found = false;
////				transaction_index += 4;
////				result += "Shortend LockTime Hex = "+hex+"\n";
////			} else if (locktime_bits == "11") {
////				std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
////				mtx.nLockTime = std::get<0>(varint_result);
////				transaction_index += std::get<1>(varint_result);
////				result += "VarInt LockTime Hex Length = "+std::to_string(std::get<1>(varint_result))+"\n";
////			}

////			/* Parse Input Count 
////				"00": Parse a VarInt
////				_: Parse Binary of input_count_bits for Input Count
////			*/
////			int input_count;
////			if (input_count_bits == "00") {
////				std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
////				input_count = std::get<0>(varint_result);
////				transaction_index += std::get<1>(varint_result);
////				result += "Input Count Hex Length = "+std::to_string(std::get<1>(varint_result))+"\n";
////			} else {
////				input_count = binary_to_int("000000"+input_count_bits);
////			}
////			result += "Input Count = "+std::to_string(input_count)+"\n";

////			 /* Parse Output Count 
////				"00": Parse a VarInt
////				_: Parse Binary of output_count_bits for Output Count
////			*/
////			int output_count;
////			if (output_count_bits == "00") {
////				std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
////				output_count = std::get<0>(varint_result);
////				transaction_index += std::get<1>(varint_result);
////				result += "Output Count Hex Length = "+std::to_string(std::get<1>(varint_result))+"\n";
////			} else {
////				output_count = binary_to_int("000000"+output_count_bits);
////			}
////			result += "Output Count = "+std::to_string(output_count)+"\n";
////			result += "^^^^^^^^^INFO BYTE^^^^^^^^^\n";

////			/* Parse Input Output Byte 
////				"xxx": Sequence Encoding
////				"xx: Input Count
////				"xxx": Output Count
////			*/
////			hex = compressed_transaction.substr(transaction_index, 2);
////			transaction_index += 2;
////			std::string io_byte = hex_to_binary(hex);

////			std::string sequence_bits = io_byte.substr(0, 3);
////			result += "sequence_bits = "+sequence_bits+"\n";

////			std::string input_type_bits = io_byte.substr(3, 2);
////			result += "input_type_bits = "+input_type_bits+"\n";

////			std::string output_type_bits = io_byte.substr(5, 3);
////			result += "output_type_bits = "+output_type_bits+"\n";

////			result += "Input Output Byte = "+io_byte+"\n";
////			result += "Input Output Byte Hex = "+hex+"\n";

////			int byte = binary_to_int("00000"+sequence_bits);

////			/* Parse Sequnce 
////				"000": Non Identical Sequences, Read Sequence Before Each Input
////				"001": Parse Full Sequence From VarInt, All Sequences are Identical
////				"010": Up to 4 Inputs had the Sequence Encoded in the Next Byte
////				"011"-"110": Sequence is Identical and encoded in the Sequnce Bits
////			*/ 
////			std::vector<uint32_t> sequences;
////			uint32_t sequence;
////			result += "byte = "+std::to_string(byte)+"\n";
////			switch(byte)
////			{
////				case 0:
////				{
////					break;
////				}
////				case 1: 
////				{
////					std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
////					sequence = std::get<0>(varint_result);
////					transaction_index += std::get<1>(varint_result);
////					break;
////				}
////				case 2:
////				{
////					hex = compressed_transaction.substr(transaction_index, 2);
////					result += "Encoded Sequence Byte Hex = "+hex+"\n";
////					transaction_index += 2;
////					std::string binary = hex_to_binary(hex);
////					for (int input_index = 0; input_index < input_count; input_index++) {
////						byte = binary_to_int("000000"+binary.substr(transaction_index, 2));
////						switch(byte)
////						{
////							case 0: 
////							{
////								sequences.push_back(0x00000000);
////								break;
////							}
////							case 1: 
////							{
////								sequences.push_back(0xFFFFFFF0);
////								break;
////							}
////							case 2: 
////							{
////								sequences.push_back(0xFFFFFFFE);
////								break;
////							}
////							case 3: 
////							{
////								sequences.push_back(0xFFFFFFFF);
////								break;
////							}
////						}
////					}
////					break;
////				}
////				case 3:
////				{
////					sequence = 0xFFFFFFF0;
////					break;
////				}
////				case 4:
////				{
////					sequence = 0xFFFFFFFE;
////					break;
////				}
////				case 5:
////				{
////					sequence = 0xFFFFFFFF;
////					break;
////				}
////				case 6:
////				{
////					sequence = 0x00000000;
////					break;
////				}
////				default: 
////				{
////					result += "FAILURE: SEQUNECE BITS ARE INCORRECT(technically impossible to reach this)";
////					sequence = 0x00000000;
////				}
////			}

////			/* Parse Input Type
////				"01": Up to 4 Input Types have been Encoded in the Next Byte
////			*/ 
////			std::vector<std::string> input_types;
////			if (input_type_bits == "01") {
////				hex = compressed_transaction.substr(transaction_index, 2);
////				result += "Encoded Input Type Byte Hex = "+hex+"\n";
////				std::string binary = hex_to_binary(hex);
////				transaction_index += 2;
////				for (int input_type_index = 0; input_type_index < 4; input_type_index++) {
////					result += "input_type("+std::to_string(input_type_index)+") = "+binary.substr(input_type_index, 2)+"\n";
////					input_types.push_back(binary.substr(input_type_index, 2));
////				}
////			}
////			result += "^^^^^^^^^IO BYTE^^^^^^^^^\n";
////			/* Parse Coinbase Byte 
////				"x": Coinbase Encoding
////			*/
////			hex = compressed_transaction.substr(transaction_index, 2);
////			transaction_index += 2;
////			std::string binary = hex_to_binary(hex);

////			std::string coinbase_bits = binary.substr(0, 1);
////			result += "coinbase_bits = "+coinbase_bits+"\n";

////			/* Parse Coinbase */
////			bool coinbase = binary_to_int("0000000"+coinbase_bits);

////			result += "^^^^^^^^^CB BYTE^^^^^^^^^^\n";
////			std::vector<int> half_finished_inputs, hash_types;
////			std::vector<std::string> compressed_signatures;
////			std::vector<CTxIn> vin;
////			for (int input_index = 0; input_index < input_count; input_index++) {
////				result += "---index = "+std::to_string(input_index)+"\n";
////				// Clear Stack From Previous Iterations
////				/* Parse Sequence 
////					"000": Sequence was uncompressed, Read from VarInt
////					"010": Sequence was Read Previously, Set Temp Var
////				*/
////				if (sequence_bits == "000") {
////					std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
////					sequence = std::get<0>(varint_result);
////					transaction_index += std::get<1>(varint_result);
////					result += "Sequence = "+std::to_string(sequence)+"\n";
////				} else if (sequence_bits == "010") {
////					sequence = sequences.at(input_index);
////				}

////				/* Parse Input Type 
////					"00": Input Type Was Uncomrpessed Read Next Byte
////					"01": Input Type Was Already Parsed, Set Temp Var
////					"10": All Inputs Identical, Input is Custom Type
////					"11": All Inputs Identical, Input is Compressed
////				*/
////				std::string input_type;
////				byte = binary_to_int("000000"+input_type_bits);
////				switch(byte)
////				{
////					case 0: 
////					{
////						hex = compressed_transaction.substr(transaction_index, 2);
////						transaction_index += 2;
////						input_type = hex_to_binary(hex).substr(6, 2);
////						break;
////					}
////					case 1:
////					{
////						input_type = input_types.at(input_index);
////						break;
////					}
////					case 2:
////					{
////						input_type = "00";
////						break;
////					}
////					case 3:
////					{
////						input_type = "11";
////						break;
////					}
////				}
////				int vout_int;
////				uint256 txid;
////				CScript scriptSig;
////				if (!coinbase) {
////					/* Parse TXID */
////					hex = compressed_transaction.substr(transaction_index, (32*2));
////					result += "TXID hex = "+hex+"\n";
////					txid.SetHex(hex);

////					Consensus::Params consensus_params;
////					uint256 hash;
////					CTransactionRef tr = GetTransaction(nullptr, nullptr, txid, consensus_params, hash);

////					if (tr == nullptr) {
////						result += "FAILURE\n";
////						std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
////						int block_height = std::get<0>(varint_result);
////						transaction_index += std::get<1>(varint_result);
////						result += "Block Height = "+std::to_string(block_height)+"\n";

////						varint_result = from_varint(compressed_transaction.substr(transaction_index));
////						int block_index = std::get<0>(varint_result);
////						transaction_index += std::get<1>(varint_result);
////						result += "Block Index = "+std::to_string(block_index)+"\n";
////						std::vector<CBlockIndex*> blocks;
////						blocks = blockman->GetAllBlockIndices();
////						int blocks_length = blocks.size();
////						bool block_found = false;
////						for (int blocks_index = 0; blocks_index < blocks_length; blocks_index++) {
////							const CBlockIndex* pindex{nullptr};
////							pindex = blocks.at(blocks_index);
////							int height = pindex->nHeight;
////							if (block_height == height) {
////								result += "height = "+std::to_string(height)+"\n";
////								CBlock block;
////								ReadBlockFromDisk(block, pindex, consensus_params);
////								result += "Block Hash = "+pindex->GetBlockHash().GetHex()+"\n";
////								txid = (*block.vtx.at(block_index)).GetHash();
////								result += "TXID = "+txid.GetHex()+"\n";
////								block_found = true;
////							}
////						}
////						if (!block_found) {
////							result += "ISSUE: Could not find block = "+std::to_string(block_height)+"\n";
////						}
////					} else {
////						transaction_index += 32*2;
////					}

////					/* Parse Vout */
////					std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
////					vout_int = std::get<0>(varint_result);
////					transaction_index += std::get<1>(varint_result);
////					result += "Vout = "+std::to_string(vout_int)+"\n";
////				} else {
////					txid.SetHex("0x00");
////					vout_int = 4294967295;
////				}
////				
////				result += "input_type = "+input_type+"\n";
////				/* Parse Input 
////					"00": Custom Input Type
////					"11": Compressed Input Type, Read Data Complete it After
////				*/
////				std::vector<std::vector<unsigned char>> stack;
////				if (input_type == "00") {
////					/* Parse Script Length */
////					std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
////					int script_length = std::get<0>(varint_result);
////					transaction_index += std::get<1>(varint_result);
////					result += "Script Length = "+std::to_string(script_length)+"\n";

////					/* Parse Script */
////					hex = compressed_transaction.substr(transaction_index, script_length*2);
////					transaction_index += script_length*2;
////					result += "Script = "+hex+"\n";
////					std::vector<unsigned char> bytes = hex_to_bytes(hex);
////					scriptSig = CScript(bytes.begin(), bytes.end());

////					/* Parse Witness Count */
////					varint_result = from_varint(compressed_transaction.substr(transaction_index));
////					int witness_count = std::get<0>(varint_result);
////					transaction_index += std::get<1>(varint_result);
////					result += "Witness Script Count = "+std::to_string(witness_count)+"\n";
////					for (int witnesses_index = 0; witnesses_index < witness_count; witnesses_index++) {
////						/* Parse Witness Length */
////						std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
////						int witness_script_length = std::get<0>(varint_result);
////						transaction_index += std::get<1>(varint_result);
////						result += "Witness Script Length = "+std::to_string(witness_script_length)+"\n";

////						/* Parse Witness Script */
////						hex = compressed_transaction.substr(transaction_index, witness_script_length*2);
////						transaction_index += witness_script_length*2;
////						result += "Witness Script = "+hex+"\n";
////						stack.push_back(hex_to_bytes(hex));
////					}
////				} else {
////					hex = compressed_transaction.substr(transaction_index, 64*2);
////					compressed_signatures.push_back(hex);
////					half_finished_inputs.push_back(input_index);
////					transaction_index += 64*2;
////					result += "Compressed Signature = "+hex+"\n";
////					hex = compressed_transaction.substr(transaction_index, 2);
////					transaction_index += 2;
////					hash_types.push_back(hex_to_int(hex));
////					result += "Hash Type = "+hex+"\n";
////				}

////				/* Assemble CTxIn */
////				COutPoint outpoint;
////				outpoint = COutPoint(txid, vout_int);
////				CTxIn ctxin = CTxIn(outpoint, scriptSig, sequence);
////				ctxin.scriptWitness.stack = stack;
////				vin.push_back(ctxin);
////			}
////			mtx.vin = vin;
////			result += "^^^^^^^^^INPUT^^^^^^^^^\n";
////			std::vector<CTxOut> vout;
////			for (int output_index = 0; output_index < output_count; output_index++) {
////				/* Parse Output Type 
////					"000": Output Type Uncompressed, Read From Next Byte
////					_: Parse Output Type From output_type_bits
////				*/
////				std::string output_type;
////				if (output_type_bits == "000") {
////					/* Parse Output Type */
////					hex = compressed_transaction.substr(transaction_index, 2);
////					transaction_index += 2;
////					result += "Output Type Hex = "+hex+"\n";
////					output_type = hex_to_binary(hex).substr(5, 3);
////				} else {
////					output_type = output_type_bits;
////				}

////				/* Parse Amount */
////				std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
////				CAmount amount = std::get<0>(varint_result);
////				transaction_index += std::get<1>(varint_result);
////				result += "Amount = "+std::to_string(amount)+"\n";

////				/* Parse Output 
////					"001": P2PK
////					"010": P2SH
////					"011": P2PKH
////					"100": P2WSH
////					"101": P2WPKH
////					"110": P2TR
////					"111": Custom Script
////				*/
////				CScript output_script;
////				byte = binary_to_int("00000"+output_type);
////				switch(byte)
////				{
////					case 1: {
////						hex = compressed_transaction.substr(transaction_index, 65*2);
////						transaction_index += 65*2;
////						result += "Script = "+hex+"\n";
////						hex = "41"+hex+"ac";
////						result += "Exteneded Script = "+hex+"\n";
////						std::vector<unsigned char> bytes = hex_to_bytes(hex);
////						output_script = CScript(bytes.begin(), bytes.end());
////						break;
////					}
////					case 2: {
////						hex = compressed_transaction.substr(transaction_index, 40);
////						transaction_index += 40;
////						result += "Script = "+hex+"\n";
////						hex = "a914"+hex+"87";
////						result += "Exteneded Script = "+hex+"\n";
////						std::vector<unsigned char> bytes = hex_to_bytes(hex);
////						output_script = CScript(bytes.begin(), bytes.end());
////						break;
////					}
////					case 3: {
////						hex = compressed_transaction.substr(transaction_index, 40);
////						transaction_index += 40;
////						result += "Script = "+hex+"\n";
////						hex = "76a914"+hex+"88ac";
////						result += "Exteneded Script = "+hex+"\n";
////						std::vector<unsigned char> bytes = hex_to_bytes(hex);
////						output_script = CScript(bytes.begin(), bytes.end());
////						break;
////					}
////					case 4: {
////						hex = compressed_transaction.substr(transaction_index, 64);
////						transaction_index += 64;
////						result += "Script = "+hex+"\n";
////						hex = "0020"+hex;
////						result += "Exteneded Script = "+hex+"\n";
////						std::vector<unsigned char> bytes = hex_to_bytes(hex);
////						output_script = CScript(bytes.begin(), bytes.end());
////						break;
////					}
////					case 5: {
////						hex = compressed_transaction.substr(transaction_index, 40);
////						transaction_index += 40;
////						result += "Script = "+hex+"\n";
////						hex = "0014"+hex;
////						result += "Exteneded Script = "+hex+"\n";
////						std::vector<unsigned char> bytes = hex_to_bytes(hex);
////						output_script = CScript(bytes.begin(), bytes.end());
////						break;
////					}
////					case 6: {
////						hex = compressed_transaction.substr(transaction_index, 64);
////						transaction_index += 64;
////						result += "Script = "+hex+"\n";
////						hex = "5120"+hex;
////						result += "Exteneded Script = "+hex+"\n";
////						std::vector<unsigned char> bytes = hex_to_bytes(hex);
////						output_script = CScript(bytes.begin(), bytes.end());
////						break;
////					}
////					case 7:
////					{
////						/* Parse Script Length */
////						std::tuple<long int, int32_t> varint_result = from_varint(compressed_transaction.substr(transaction_index));
////						int script_length = std::get<0>(varint_result);
////						transaction_index += std::get<1>(varint_result);
////						result += "Script Length = "+std::to_string(script_length)+"\n";

////						/* Parse Script */
////						hex = compressed_transaction.substr(transaction_index, script_length*2);
////						transaction_index += script_length*2;
////						result += "Script = "+hex+"\n";
////						std::vector<unsigned char> bytes = hex_to_bytes(hex);
////						output_script = CScript(bytes.begin(), bytes.end());
////						break;
////					}
////					default:
////					{
////						result += "FAILURE: UNCAUGHT OUTPUT TYPE;\n";
////					}
////				}
////				vout.push_back(CTxOut(amount, output_script));
////			}
////			mtx.vout = vout;
////			result += "^^^^^^^^^OUTPUT^^^^^^^^^\n";

////			int partial_inputs_length = half_finished_inputs.size();
////			for (int partial_inputs_index = 0; partial_inputs_index < partial_inputs_length; partial_inputs_index++) {
////				/* Complete Input Types */
////				int input_index = half_finished_inputs.at(partial_inputs_index);
////				result += "Half Finished Input "+std::to_string(partial_inputs_index)+", "+std::to_string(input_index)+"---------------------\n";
////				uint256 block_hash;
////				Consensus::Params consensusParams;
////				CTransactionRef prev_tx = GetTransaction(NULL, NULL, mtx.vin.at(input_index).prevout.hash, consensusParams, block_hash);
////				CMutableTransaction prev_mtx = CMutableTransaction(*prev_tx);
////				CScript script_pubkey = (*prev_tx).vout.at(mtx.vin.at(input_index).prevout.n).scriptPubKey;
////				CAmount amount = (*prev_tx).vout.at(mtx.vin.at(input_index).prevout.n).nValue;
////				result += "amount = "+std::to_string(amount)+"\n";
////				result += "Scritp Pubkey = "+serialize_script(script_pubkey)+"\n";
////				std::tuple<std::string, std::vector<unsigned char>> output_result = get_output_type((*prev_tx).vout.at(mtx.vin.at(input_index).prevout.n), result);
////				std::string script_type = std::get<0>(output_result);
////				byte = binary_to_int(script_type);

////				/* Parse Input Type 
////					"011"|"101": ECDSA Signature
////					"110": Schnorr Signature
////				*/
////				std::vector<secp256k1_ecdsa_recoverable_signature> recovered_signatures;
////				secp256k1_ecdsa_recoverable_signature rsig;
////				if (byte == 3 || byte == 5) {
////					result += "ECDSA\n";
////					std::vector<unsigned char> compact_signature = hex_to_bytes(compressed_signatures.at(partial_inputs_index));
////					for (int recovery_index = 0; recovery_index < 4; recovery_index++) {
////						/* Parse the compact signature with each of the 4 recovery IDs */
////						int r = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, &compact_signature[0], recovery_index);
////						if (r == 1) {
////							recovered_signatures.push_back(rsig);
////						}
////					}
////				} else if (byte == 6) {
////					result += "TAPROOT INIT\n";
////				} else {
////					result += "ISSUE WITH INPUT SCRIPT\n";
////				}
////				while(true) {
////					/* Parse Input 
////					"011": P2PKH
////					"101": P2WPKH
////					"110": P2TR
////					*/
////					std::vector<secp256k1_pubkey> pubkeys;
////					std::vector<unsigned char> public_key_bytes;
////					if (byte == 3 ) {
////						result += "P2PKH\n";
////						
////						/* Hash the Trasaction to generate the SIGHASH */
////						result += "Hash Type = "+int_to_hex(hash_types.at(partial_inputs_index))+"\n";
////						uint256 hash = SignatureHash(script_pubkey, mtx, input_index, hash_types.at(partial_inputs_index), amount, SigVersion::BASE);
////						hex = hash.GetHex();
////						std::vector<unsigned char> bytes;
////						bytes = hex_to_bytes(hex);
////						std::reverse(bytes.begin(), bytes.end());
////						hex = bytes_to_hex(bytes);
////						result += "message = "+hex+"\n";
////						int recovered_signatures_length = recovered_signatures.size();
////						for (int recovered_signatures_index = 0; recovered_signatures_index < recovered_signatures_length; recovered_signatures_index++) {
////							/* Run Recover to get the Pubkey for the given Recovered Signature and Message/SigHash (Fails half the time(ignore)) */
////							secp256k1_pubkey pubkey;
////							int r = secp256k1_ecdsa_recover(ctx, &pubkey, &recovered_signatures.at(recovered_signatures_index), &bytes[0]);
////							if (r == 1) {
////								result += "SUCCESS\n";
////								pubkeys.push_back(pubkey);
////							}
////						}
////						int pubkeys_length = pubkeys.size();
////						secp256k1_ecdsa_signature sig;
////						bool pubkey_found = false;
////						for (int pubkeys_index = 0; pubkeys_index < pubkeys_length; pubkeys_index++) {
////							result += "\nPUBKEY = "+std::to_string(pubkeys_index)+"\n";
////							/* Serilize Compressed Pubkey */
////							std::vector<unsigned char> c_vch (33);
////							size_t c_size = 33;
////							secp256k1_ec_pubkey_serialize(ctx, &c_vch[0], &c_size, &pubkeys.at(pubkeys_index), SECP256K1_EC_COMPRESSED);
////							hex = bytes_to_hex(c_vch);
////							result += "COMPRESSED public key = "+hex+"\n";
////							/* Hash Compressed Pubkey */
////							uint160 c_pubkeyHash;
////							CHash160().Write(c_vch).Finalize(c_pubkeyHash);
////							hex = c_pubkeyHash.GetHex();
////							bytes = hex_to_bytes(hex);
////							std::reverse(bytes.begin(), bytes.end());
////							hex = bytes_to_hex(bytes);
////							result += "COMPRESSED public key Hash = "+hex+"\n";
////							/* Construct Compressed ScriptPubKey */
////							hex = "76a914"+hex+"88ac";
////							result += "COMPRESSED Script Pubkey = "+hex+"\n";
////							bytes = hex_to_bytes(hex);
////							CScript c_script_pubkey = CScript(bytes.begin(), bytes.end());
////							/* Test Scripts */
////							if (serialize_script(c_script_pubkey) == serialize_script(script_pubkey)) {
////								secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &recovered_signatures.at(pubkeys_index));
////								pubkey_found = true;
////								public_key_bytes = c_vch;
////								break;
////							}

////							result += "-----------\n";

////							/* Serilize Uncompressed Pubkey */
////							std::vector<unsigned char> uc_vch (65);
////							size_t uc_size = 65;
////							secp256k1_ec_pubkey_serialize(ctx, &uc_vch[0], &uc_size, &pubkeys.at(pubkeys_index), SECP256K1_EC_UNCOMPRESSED);
////							hex = bytes_to_hex(uc_vch);
////							result += "UNCOMPRESSED public key = "+hex+"\n";
////							/* Hash Uncompressed PubKey */
////							uint160 uc_pubkeyHash;
////							CHash160().Write(uc_vch).Finalize(uc_pubkeyHash);
////							hex = uc_pubkeyHash.GetHex();
////							bytes = hex_to_bytes(hex);
////							std::reverse(bytes.begin(), bytes.end());
////							hex = bytes_to_hex(bytes);
////							result += "UNCOMPRESSED public key Hash = "+hex+"\n";
////							/* Construct Uncompressed ScriptPubKey */
////							hex = "76a914"+hex+"88ac";
////							result += "UNCOMPRESSED Script Pubkey = "+hex+"\n";
////							bytes = hex_to_bytes(hex);
////							CScript uc_script_pubkey = CScript(bytes.begin(), bytes.end());
////							/* Test Scripts */
////							if (serialize_script(uc_script_pubkey) == serialize_script(script_pubkey)) {
////								secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &recovered_signatures.at(pubkeys_index));
////								pubkey_found = true;
////								public_key_bytes = uc_vch;
////								break;
////							}
////						}
////						if (pubkey_found) {
////							result += "FOUND\n";
////							locktime_found = true;
////							std::vector<unsigned char> sig_der (71);
////							size_t sig_der_size = 71;
////							secp256k1_ecdsa_signature_serialize_der(ctx, &sig_der[0], &sig_der_size, &sig);
////							result += "Sig Length = "+std::to_string(sig_der_size)+"\n";
////							std::string hex = int_to_hex(sig_der_size+1);
////							hex += bytes_to_hex(sig_der, sig_der_size);
////							hex += int_to_hex(hash_types.at(partial_inputs_index));
////							std::string hex2 = bytes_to_hex(public_key_bytes);
////							int pubkey_length = hex2.length()/2;
////							hex += int_to_hex(pubkey_length);
////							hex += hex2;
////							result += "Script Signature = "+hex+"\n";
////							bytes = hex_to_bytes(hex);
////							CScript scriptSig = CScript(bytes.begin(), bytes.end());
////							mtx.vin.at(input_index).scriptSig = scriptSig;
////						} else {
////							result += "FAILURE: no pubkey found\n";
////						}
////					} else if (byte == 5) {
////						result += "V0_P2WPKH\n";
////						/* Hash the Trasaction to generate the SIGHASH */
////						secp256k1_ecdsa_signature sig;
////						std::string scriptPubKeyHash = serialize_script(script_pubkey);
////						std::string pubkeyhash = scriptPubKeyHash.substr(4, 40);
////						std::vector<unsigned char> bytes;
////						bytes = hex_to_bytes("76a914"+pubkeyhash+"88ac");
////						CScript script_code = CScript(bytes.begin(), bytes.end()); 
////						result += "Script Code = "+serialize_script(script_code)+"\n"; 
////						uint256 hash = SignatureHash(script_code, mtx, input_index, hash_types.at(partial_inputs_index), amount, SigVersion::WITNESS_V0);
////						//TODO: Get Bytes directly.
////						hex = hash.GetHex();
////						bytes = hex_to_bytes(hex);
////						std::reverse(bytes.begin(), bytes.end());
////						hex = bytes_to_hex(bytes);
////						result += "message = "+hex+"\n";

////						pubkeys.clear();
////						int recovered_signatures_length = recovered_signatures.size();
////						for (int recovered_signatures_index = 0; recovered_signatures_index < recovered_signatures_length; recovered_signatures_index++) {
////							/* Run Recover to get the Pubkey for the given Recovered Signature and Message/SigHash (Fails half the time(ignore)) */
////							secp256k1_pubkey pubkey;
////							int r = secp256k1_ecdsa_recover(ctx, &pubkey, &recovered_signatures.at(recovered_signatures_index), &bytes[0]);
////							if (r == 1) {
////								result += "SUCCESS\n";
////								pubkeys.push_back(pubkey);
////							}
////						}

////						bool pubkey_found = false;
////						int pubkeys_length = pubkeys.size();
////						for (int pubkeys_index = 0; pubkeys_index < pubkeys_length; pubkeys_index++) {
////							result += "\nPUBKEY = "+std::to_string(pubkeys_index)+"\n";
////							/* Serilize Compressed Pubkey */
////							std::vector<unsigned char> c_vch (33);
////							size_t c_size = 33;
////							secp256k1_ec_pubkey_serialize(ctx, &c_vch[0], &c_size, &pubkeys.at(pubkeys_index), SECP256K1_EC_COMPRESSED);
////							hex = bytes_to_hex(c_vch);
////							result += "COMPRESSED public key = "+hex+"\n";
////							/* Hash Compressed Pubkey */
////							uint160 c_pubkeyHash;
////							CHash160().Write(c_vch).Finalize(c_pubkeyHash);
////							hex = c_pubkeyHash.GetHex();
////							bytes = hex_to_bytes(hex);
////							std::reverse(bytes.begin(), bytes.end());
////							hex = bytes_to_hex(bytes);
////							result += "COMPRESSED public key Hash = "+hex+"\n";
////							/* Construct Compressed ScriptPubKey */
////							hex = "0014"+hex;
////							result += "COMPRESSED Script Pubkey = "+hex+"\n";
////							bytes = hex_to_bytes(hex);
////							CScript c_script_pubkey = CScript(bytes.begin(), bytes.end());
////							/* Test Scripts */
////							if (serialize_script(c_script_pubkey) == serialize_script(script_pubkey)) {
////								result += "index = "+std::to_string(pubkeys_index)+"\n";
////								secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &recovered_signatures.at(pubkeys_index));
////								pubkey_found = true;
////								public_key_bytes = c_vch;
////								break;
////							}
////						}
////						if (pubkey_found) {
////							result += "FOUND\n";
////							locktime_found = true;
////							std::vector<unsigned char> sig_der (70);
////							std::vector<std::vector<unsigned char>> stack;
////							size_t sig_der_size = 70;
////							secp256k1_ecdsa_signature_serialize_der(ctx, &sig_der[0], &sig_der_size, &sig);
////							sig_der.push_back(hash_types.at(partial_inputs_index));
////							stack.push_back(sig_der);
////							stack.push_back(public_key_bytes);
////							CScriptWitness scriptWitness;
////							scriptWitness.stack = stack;
////							result += "INSERTING "+std::to_string(input_index)+"\n";
////							mtx.vin.at(input_index).scriptWitness = scriptWitness;
////						} else {
////							result += "FAILURE: no pubkey found\n";
////						}
////					} else if (byte == 6) {
////						result += "P2TR\n";
////						std::vector<unsigned char> schnorr_signature = hex_to_bytes(compressed_signatures.at(partial_inputs_index));
////						if (!locktime_found) {
////							/* Script Execution Data Init */
////							ScriptExecutionData execdata;
////							execdata.m_annex_init = true;
////							execdata.m_annex_present = false;

////							/* Prevout Init */
////							PrecomputedTransactionData cache;
////							std::vector<CTxOut> utxos;
////							int input_length = mtx.vin.size();
////							for (int input_index_2 = 0; input_index_2 < input_length; input_index_2++) {
////								uint256 block_hash;
////								CTransactionRef prev_tx = GetTransaction(NULL, NULL, mtx.vin.at(input_index_2).prevout.hash, consensusParams, block_hash);
////								// CMutableTransaction prev_mtx = CMutableTransaction(*prev_tx);
////								CScript script = (*prev_tx).vout.at(mtx.vin.at(input_index_2).prevout.n).scriptPubKey;
////								result += "prevout script = "+serialize_script(script)+"\n";
////								amount = (*prev_tx).vout.at(mtx.vin.at(input_index_2).prevout.n).nValue;
////								result += "amount = "+std::to_string(amount)+"\n";
////								utxos.emplace_back(amount, script);
////							}
////							cache.Init(CTransaction(mtx), std::vector<CTxOut>{utxos}, true);
////							result += "Locktime = "+std::to_string(mtx.nLockTime)+"\n";
////							uint256 hash;
////							int r = SignatureHashSchnorr(hash, execdata, mtx, input_index, hash_types.at(partial_inputs_index), SigVersion::TAPROOT, cache, MissingDataBehavior::FAIL);
////							if (!r) {
////								result += "FAILURE SCHNORR HASH\n";
////							}
////							hex = hash.GetHex();
////							result += "message = "+hex+"\n";
////							std::vector<unsigned char> bytes;
////							r = get_first_push_bytes(bytes, script_pubkey);
////							if (!r) {
////								result += "ISSUE: Could not get push bytes\n";
////							}
////							hex = bytes_to_hex(bytes);
////							result += "pubkey = "+hex+"\n";
////							// hex2 = serialize_script(script_pubkey).substr(4, 64);
////							// result += "pubkey = "+hex2+"\n";
////							result += "signature = "+bytes_to_hex(schnorr_signature)+"\n";
////							secp256k1_xonly_pubkey xonly_pubkey;
////							r = secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey, bytes.data());
////							if (!r) {
////								result += "FAILURE: ISSUE PUBKEY PARSE\n";
////							}
////							r = secp256k1_schnorrsig_verify(ctx, schnorr_signature.data(), hash.begin(), 32, &xonly_pubkey);
////							if (!r) {
////								result += "FAILURE: Issue verifiy\n";
////							} else {
////								locktime_found = true;
////							}
////						}
////						if (locktime_found) {
////							std::vector<std::vector<unsigned char>> stack;
////							if (hash_types.at(partial_inputs_index) != 0x00) {
////								schnorr_signature.push_back(hash_types.at(partial_inputs_index));	
////							}
////							stack.push_back(schnorr_signature);
////							result += "INSERTING "+std::to_string(input_index)+"\n";
////							mtx.vin.at(input_index).scriptWitness.stack = stack;
////						}

////					}
////					/* If LockTime Has been Found Break, Otherwise add 2^16 to it and try again */
////					if (locktime_found) {
////						result += "LOCKTIME FOUND\n";
////						break;
////					} else {
////						mtx.nLockTime += pow(2, 16);
////						result += "lock = "+std::to_string(mtx.nLockTime)+"\n";
////					}
////				}
////			}
////			result += "------------------------R---------------------------\n";
			//CTransactionRef tx = MakeTransactionRef(CTransaction(mtx));
			//return result+"|"+EncodeHexTx(*tx, RPCSerializationFlags());
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
