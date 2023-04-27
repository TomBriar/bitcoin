// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <core_memusage.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <primitives/transaction.h>
#include <txdecompress.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <univalue.h>
#include <util/rbf.h>
#include <validation.h>
#include <version.h>
#include <logging.h>
#include <cmath>

#include <test/util/setup_common.h>

#include <rpc/blockchain.h>
#include <rpc/mining.h>
#include <rpc/client.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <cassert>
#include <univalue.h>
#include <node/blockstorage.h>
#include <node/chainstate.h>
#include <rpc/server_util.h>
#include <uint256.h>
#include <node/miner.h>
#include <key_io.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include <base58.h>
#include <timedata.h>
#include <shutdown.h>
#include <consensus/merkle.h>
#include <pow.h>
#include <node/transaction.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1.h>
#include <node/coin.h>
#include <rpc/rawtransaction_util.h>
#include <random.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <interfaces/chain.h>
#include <index/txindex.h>

using node::BlockManager;
using node::BlockAssembler;
using node::CBlockTemplate;
using node::ReadBlockFromDisk;
using node::GetTransaction;
using node::RegenerateCommitments;

namespace {
	class SecpContext {
			secp256k1_context* ctx;

		public:
			SecpContext() {
				ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
			}
			~SecpContext() {
				secp256k1_context_destroy(ctx);
			}
			secp256k1_context* GetContext() {
				return ctx;
			}
	};
	struct CompressionRoundtripFuzzTestingSetup : public TestChain100Setup {
		CompressionRoundtripFuzzTestingSetup(const std::string& chain_name, const std::vector<const char*>& extra_args) : TestChain100Setup{chain_name, extra_args} 
		{}

		//TODO: replace with known values
		CCompressedTxId GetCompressedTxId(uint256 txid, CBlock block) {
			ChainstateManager& chainman = EnsureChainman(m_node);
            Chainstate& active_chainstate = chainman.ActiveChainstate();
            BlockManager* blockman = &active_chainstate.m_blockman;

			const CBlockIndex* pindex{nullptr};
			{
				LOCK(cs_main);
				pindex = blockman->LookupBlockIndex(block.GetHash());
			}
			assert(pindex);
			uint32_t block_height = pindex->nHeight;
			uint32_t block_index;
			assert(block.LookupTransactionIndex(txid, block_index));
			return CCompressedTxId(block_height, block_index);
		}


    	UniValue CallRPC(const std::string& rpc_method, const std::vector<std::string>& arguments)
    	{   
    		JSONRPCRequest request;
    		request.context = &m_node;
    		request.strMethod = rpc_method;
    		try {
    			request.params = RPCConvertValues(rpc_method, arguments);
    		} catch (const std::runtime_error&) {
    			return NullUniValue;
    		}   
    		return tableRPC.execute(request);
    	}

		bool IsTopBlock(CBlock block) {
			LOCK(cs_main);
			if (m_node.chainman->ActiveChain().Tip()->GetBlockHash() == block.GetHash()) return true;
////		std::cout << "Checking block: " << std::endl;
////		std::cout << "\t" << "Block Tip = " << m_node.chainman->ActiveChain().Tip()->GetBlockHash() << std::endl;
////		std::cout << "\t" << "Block Hash = " << block.GetHash() << std::endl;
			return false;
		}

		/* Compressed P2PKH = 1, Uncompressed P2PKH = 2, P2WPKH = 3, P2TR = 4, P2SH = 5, P2WSH = 6 */
		CScript GenerateDestination(secp256k1_context* ctx, secp256k1_keypair kp, int script_type = 1){
			assert(script_type > 0 && script_type < 6);
			secp256k1_pubkey pubkey;
			assert(secp256k1_keypair_pub(ctx, &pubkey, &kp));

			std::cout << "script_type " << script_type << std::endl;
			if (script_type == 5) {
				/* Serilize Compressed Pubkey */
				std::vector<unsigned char> compressed_pubkey (33);
				size_t c_size = 33;
				secp256k1_ec_pubkey_serialize(ctx, &compressed_pubkey[0], &c_size, &pubkey, SECP256K1_EC_COMPRESSED);

				/* Hash Compressed Pubkey */
				uint160 compressed_pubkey_hash;
				CHash160().Write(compressed_pubkey).Finalize(compressed_pubkey_hash);

				/* Construct Compressed Script */
				std::vector<unsigned char> compressed_script(25);
				compressed_script[0] = 0x76;
				compressed_script[1] = 0xa9;
				compressed_script[2] = 0x14;
				copy(compressed_pubkey_hash.begin(), compressed_pubkey_hash.end(), compressed_script.begin()+3);
				compressed_script[23] = 0x88;
				compressed_script[24] = 0xac;
				
 				/* Hash Script */
				uint160 script_hash;
				CHash160().Write(compressed_script).Finalize(script_hash);
				
				/* Construct Address */
				std::vector<unsigned char> script(23);
				script[0] = 0xa9;
				script[1] = 0x14;
				copy(script_hash.begin(), script_hash.end(), script.begin()+2);
				script[22] = 0x87;
				return CScript(script.begin(), script.end());
			} else if (script_type == 1) {
			/* Serilize Compressed Pubkey */
				std::vector<unsigned char> compressed_pubkey (33);
				size_t c_size = 33;
				secp256k1_ec_pubkey_serialize(ctx, &compressed_pubkey[0], &c_size, &pubkey, SECP256K1_EC_COMPRESSED);

				/* Hash Compressed Pubkey */
				uint160 compressed_pubkey_hash;
				CHash160().Write(compressed_pubkey).Finalize(compressed_pubkey_hash);

				/* Construct Compressed ScriptPubKey */
				std::vector<unsigned char> compressed_script(25);
				compressed_script[0] = 0x76;
				compressed_script[1] = 0xa9;
				compressed_script[2] = 0x14;
				copy(compressed_pubkey_hash.begin(), compressed_pubkey_hash.end(), compressed_script.begin()+3);
				compressed_script[23] = 0x88;
				compressed_script[24] = 0xac;
				return CScript(compressed_script.begin(), compressed_script.end());
			} else if (script_type == 2) {
				/* Serilize Uncompressed Pubkey */
				std::vector<unsigned char> uncompressed_pubkey (65);
				size_t uc_size = 65;
				secp256k1_ec_pubkey_serialize(ctx, &uncompressed_pubkey[0], &uc_size, &pubkey, SECP256K1_EC_UNCOMPRESSED);

				/* Hash Uncompressed PubKey */
				uint160 uncompressed_pubkey_hash;
				CHash160().Write(uncompressed_pubkey).Finalize(uncompressed_pubkey_hash);

				/* Construct Uncompressed Script */
				std::vector<unsigned char> uncompressed_script(25);
				uncompressed_script[0] = 0x76;
				uncompressed_script[1] = 0xa9;
				uncompressed_script[2] = 0x14;
				copy(uncompressed_pubkey_hash.begin(), uncompressed_pubkey_hash.end(), uncompressed_script.begin()+3);
				uncompressed_script[23] = 0x88;
				uncompressed_script[24] = 0xac;
				return CScript(uncompressed_script.begin(), uncompressed_script.end());
			} else if (script_type == 3) {
				/* Serilize Compressed Pubkey */
				std::vector<unsigned char> compressed_pubkey (33);
				size_t c_size = 33;
				secp256k1_ec_pubkey_serialize(ctx, &compressed_pubkey[0], &c_size, &pubkey, SECP256K1_EC_COMPRESSED);

				/* Hash Compressed Pubkey */
				uint160 compressed_pubkey_hash;
				CHash160().Write(compressed_pubkey).Finalize(compressed_pubkey_hash);

				/* Construct Compressed Script */
				std::vector<unsigned char> compressed_script(22);
				compressed_script[0] = 0x00;
				compressed_script[1] = 0x14;
				copy(compressed_pubkey_hash.begin(), compressed_pubkey_hash.end(), compressed_script.begin()+2);
				return CScript(compressed_script.begin(), compressed_script.end());
			} else if (script_type == 6) {
				/* Serilize Compressed Pubkey */
				std::vector<unsigned char> compressed_pubkey (33);
				size_t c_size = 33;
				secp256k1_ec_pubkey_serialize(ctx, &compressed_pubkey[0], &c_size, &pubkey, SECP256K1_EC_COMPRESSED);

				/* Hash Compressed Pubkey */
				uint160 compressed_pubkey_hash;
				CHash160().Write(compressed_pubkey).Finalize(compressed_pubkey_hash);

				/* Construct Compressed Script */
				std::vector<unsigned char> compressed_script(25);
				compressed_script[0] = 0x76;
				compressed_script[1] = 0xa9;
				compressed_script[2] = 0x14;
				copy(compressed_pubkey_hash.begin(), compressed_pubkey_hash.end(), compressed_script.begin()+3);
				compressed_script[23] = 0x88;
				compressed_script[24] = 0xac;
				
 				/* Hash Script */
				uint256 script_hash;
				CHash256().Write(compressed_script).Finalize(script_hash);
				
				/* Construct Address */
				std::vector<unsigned char> script(34);
				script[0] = 0x00;
				script[1] = 0x20;
				copy(script_hash.begin(), script_hash.end(), script.begin()+2);
				return CScript(script.begin(), script.end());
			} else if (script_type == 4) {
				/* Serilize XOnly Pubkey */
				secp256k1_xonly_pubkey xonly_pubkey;
				assert(secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_pubkey, NULL, &pubkey));
				std::vector<unsigned char> xonly_pubkey_bytes (32);
				secp256k1_xonly_pubkey_serialize(ctx, &xonly_pubkey_bytes[0], &xonly_pubkey);

				/* Construct Script */
				std::vector<unsigned char> taproot_script(34);
				taproot_script[0] = 0x51;
				taproot_script[1] = 0x20;
				copy(xonly_pubkey_bytes.begin(), xonly_pubkey_bytes.end(), taproot_script.begin()+2);
				return CScript(taproot_script.begin(), taproot_script.end());
			}
			assert(false);
		}
		bool SignTransaction(secp256k1_context* ctx, CMutableTransaction& mtx, std::vector<secp256k1_keypair> kps) {

			FillableSigningProvider keystore;
			int kps_length = kps.size();
			for (int kps_index = 0; kps_index < kps_length; kps_index++) {
				std::vector<unsigned char> secret_key(32);
				if (!secp256k1_keypair_sec(ctx, &secret_key[0], &kps.at(kps_index))) return false;
				CKey key;
				key.Set(secret_key.begin(), secret_key.end(), true);
				keystore.AddKey(key);
				if (!key.IsValid()) return false;
				CKey key2;
				key2.Set(secret_key.begin(), secret_key.end(), false);
				keystore.AddKey(key2);
				if (!key2.IsValid()) return false;
			}

			// Fetch previous transactions (inputs):
			std::map<COutPoint, Coin> coins;
			for (const CTxIn& txin : mtx.vin) {
				coins[txin.prevout]; // Create empty map entry keyed by prevout.
			}
			FindCoins(m_node, coins);

			// Parse the prevtxs array
			//ParsePrevouts(NULL, &keystore, coins);
			std::cout << "signing\n";

			std::map<int, bilingual_str> input_errors;
			::SignTransaction(mtx, &keystore, coins, SIGHASH_ALL, input_errors);
			for (const auto& err_pair : input_errors) {
				std::cout << "ERROR: "+err_pair.second.original+", "+std::to_string(err_pair.first)+"\n";
				assert(false);
			}
			
			return true;
		}
		bool InitTXIndex() {
			g_txindex = std::make_unique<TxIndex>(interfaces::MakeChain(m_node), m_cache_sizes.tx_index, false, node::fReindex);
			if (!g_txindex->Start()) {
				return false;
			}
			return true;
		}
	};
	secp256k1_context* ctx = nullptr;
	SecpContext secp_context = SecpContext();
	CompressionRoundtripFuzzTestingSetup* rpc = nullptr;
	std::vector<std::tuple<uint256, secp256k1_keypair, uint32_t, int, CScript, CCompressedTxId>> unspent_transactions;
	std::vector<std::tuple<uint256, secp256k1_keypair, uint32_t, int>> coinbase_transactions;
	CompressionRoundtripFuzzTestingSetup* InitializeCompressionRoundtripFuzzTestingSetup()
	{
		static const auto setup = MakeNoLogFileContext<CompressionRoundtripFuzzTestingSetup>();
		SetRPCWarmupFinished();
		return setup.get();
	}
};

void compression_roundtrip_initialize()
{
    SelectParams(CBaseChainParams::REGTEST);
	rpc = InitializeCompressionRoundtripFuzzTestingSetup();
	ctx = secp_context.GetContext();
	assert(rpc->InitTXIndex());
	FastRandomContext frandom_ctx(true);

	//Generate Coinbase Transactions For Future Inputs
	for (int i = 0; i < 100; i++) {
		secp256k1_keypair coinbase_kp;
		std::vector<unsigned char> secret_key = frandom_ctx.randbytes(32);
		assert(secp256k1_keypair_create(ctx, &coinbase_kp, &secret_key[0]));

		int script_type = frandom_ctx.randrange(4)+1;
		CScript coinbase_scriptPubKey =	rpc->GenerateDestination(ctx, coinbase_kp, script_type);

		std::vector<CMutableTransaction> txins;
		CBlock coinbase_block =	rpc->CreateAndProcessBlock(txins, coinbase_scriptPubKey);
		assert(rpc->IsTopBlock(coinbase_block));
		coinbase_transactions.push_back(std::make_tuple(coinbase_block.vtx.at(0)->GetHash(), coinbase_kp, 0, coinbase_block.vtx.at(0)->vout.at(0).nValue));
	}

	//Generate Coinbase Transactions For Compression Inputs
	for (int i = 0; i < 100; i++) {
		secp256k1_keypair coinbase_kp;
		std::vector<unsigned char> secret_key = frandom_ctx.randbytes(32);
		assert(secp256k1_keypair_create(ctx, &coinbase_kp, &secret_key[0]));

		int script_type = frandom_ctx.randrange(4)+1;
		CScript coinbase_scriptPubKey =	rpc->GenerateDestination(ctx, coinbase_kp, script_type);

		std::vector<CMutableTransaction> txins;
		CBlock coinbase_block =	rpc->CreateAndProcessBlock(txins, coinbase_scriptPubKey);
		assert(rpc->IsTopBlock(coinbase_block));
		uint256 txid = coinbase_block.vtx.at(0)->GetHash();
		unspent_transactions.push_back(std::make_tuple(txid, coinbase_kp, 0, coinbase_block.vtx.at(0)->vout.at(0).nValue, coinbase_scriptPubKey, rpc->GetCompressedTxId(txid, coinbase_block)));
	}

	//Generate Transactions For Compression Inputs
	int coinbase_length = coinbase_transactions.size();
	for (int coinbase_index = 0; coinbase_index < coinbase_length; coinbase_index++) {
		uint256 coinbase_txid = std::get<0>(coinbase_transactions.at(coinbase_index));
		secp256k1_keypair coinbase_kp = std::get<1>(coinbase_transactions.at(coinbase_index));
		uint32_t coinbase_vout = std::get<2>(coinbase_transactions.at(coinbase_index));
		int coinbase_amount = std::get<3>(coinbase_transactions.at(coinbase_index));

		CMutableTransaction mtx;
		mtx.nVersion = 0;
		mtx.nLockTime = 0;

		CTxIn in;
		in.prevout = COutPoint{coinbase_txid, coinbase_vout};
		in.nSequence = 0;
		mtx.vin.push_back(in);

		int index = 0;
		std::vector<std::tuple<secp256k1_keypair, int, int, CScript>> outs;
		uint32_t remaining_amount = coinbase_amount;
		LIMITED_WHILE(remaining_amount > 2000, 10000) {
			CTxOut out;	

			uint32_t amount = frandom_ctx.randrange(remaining_amount-1000)+1;
			remaining_amount -= amount;
			out.nValue = amount;

			secp256k1_keypair out_kp;
			std::vector<unsigned char> secret_key = frandom_ctx.randbytes(32);
			assert(secp256k1_keypair_create(ctx, &out_kp, &secret_key[0]));

			int script_type = frandom_ctx.randrange(4)+1;
			out.scriptPubKey = rpc->GenerateDestination(ctx, out_kp, script_type);
			mtx.vout.push_back(out);
			outs.push_back(std::make_tuple(out_kp, index, amount, out.scriptPubKey));
			index++;
		}

		assert(mtx.vout.size() != 0);
		assert(rpc->SignTransaction(ctx, mtx, {coinbase_kp}));

		std::vector<unsigned char> secret_key = frandom_ctx.randbytes(32);
		secp256k1_keypair main_kp;
		assert(secp256k1_keypair_create(ctx, &main_kp, &secret_key[0]));

		CScript main_scriptPubKey;
		int script_type = frandom_ctx.randrange(4)+1;
		main_scriptPubKey = rpc->GenerateDestination(ctx, main_kp, script_type);

		std::vector<CMutableTransaction> txins;
		txins.push_back(mtx);
		CBlock main_block = rpc->CreateAndProcessBlock(txins, main_scriptPubKey);
		assert(rpc->IsTopBlock(main_block));
		for (auto const& out : outs) {
			uint256 txid = mtx.GetHash();
			unspent_transactions.push_back(std::make_tuple(txid,  std::get<0>(out), std::get<1>(out), std::get<2>(out), std::get<3>(out), rpc->GetCompressedTxId(txid, main_block)));
		}
	}
}

FUZZ_TARGET_INIT(compression_roundtrip, compression_roundtrip_initialize)
{
	std::cout << "START-------------------------------" << std::endl;
	FuzzedDataProvider fdp(buffer.data(), buffer.size());
	std::vector<secp256k1_keypair> keypairs;
	CMutableTransaction mtx;
	mtx.nVersion = fdp.ConsumeIntegral<uint32_t>();
	mtx.nLockTime = fdp.ConsumeIntegral<uint8_t>();

	uint32_t total = 0;
	std::vector<CScript> input_scripts;
	std::vector<CCompressedTxId> txids;
	LIMITED_WHILE(total == 0 || fdp.ConsumeBool(), 10000) {
		int index = fdp.ConsumeIntegralInRange<int>(0, unspent_transactions.size()-1);
		uint256 txid = std::get<0>(unspent_transactions.at(index));
		keypairs.push_back(std::get<1>(unspent_transactions.at(index)));
		uint32_t vout = std::get<2>(unspent_transactions.at(index));
		input_scripts.push_back(std::get<4>(unspent_transactions.at(index)));
		txids.push_back(std::get<5>(unspent_transactions.at(index)));
		
		total += std::get<3>(unspent_transactions.at(index));

		CTxIn in;
		in.prevout = COutPoint{txid, vout};
		in.nSequence = fdp.ConsumeIntegral<uint32_t>();
		mtx.vin.push_back(in);
	}

	uint32_t remaining_amount = total;
	LIMITED_WHILE(remaining_amount > 2000 && (fdp.ConsumeBool() || mtx.vout.size() == 0), 10000) {
		CTxOut out;	
		uint16_t amount = fdp.ConsumeIntegralInRange<uint16_t>(1, remaining_amount-1000);
		remaining_amount -= amount;
		out.nValue = amount;

		std::vector<unsigned char> secret_key = fdp.ConsumeBytes<uint8_t>(32);
		if (secret_key.size() != 32) return;
		secp256k1_keypair out_kp;
		if (!secp256k1_keypair_create(ctx, &out_kp, &secret_key[0])) return;

		CScript out_scriptPubKey;
		int script_type = fdp.ConsumeIntegralInRange<uint32_t>(1, 4);
		out.scriptPubKey = rpc->GenerateDestination(ctx, out_kp, script_type);
		mtx.vout.push_back(out);
	}
	if (mtx.vout.size() == 0) return;

	assert(rpc->SignTransaction(ctx, mtx, keypairs));

	std::cout << "tx: " << CTransaction(mtx).ToString() << std::endl;
	//compress
////const CTransaction tx = CTransaction(mtx);
////CCompressedTransaction compressed_transaction = CCompressedTransaction(tx, txids, input_scripts);
////std::cout << "compressed_tx: " << compressed_transaction.ToString() << std::endl;
////CTransaction new_tx = CTransaction(compressed_transaction);
////std::cout << "uncompressed_tx: " << new_tx.ToString() << std::endl;




////CDataStream stream(SER_DISK, 0);	
////compressed_transaction.Serialize(stream);
////std::vector<std::byte> data(stream.size());
////stream.read(data);
////std::vector<unsigned char> uc_data = reinterpret_cast<std::vector<unsigned char> &&> (data);
////std::string hex = HexStr(uc_data);
////std::cout << "SERIALIZED: " << hex << std::endl;
	assert(false);
////std::vector<std::string> arguments;
////std::string rpc_method;
////UniValue rpc_result;

////std::string serilized_transaction =	EncodeHexTx(CTransaction(mtx));
////arguments.push_back(serilized_transaction);
////rpc_method = "compressrawtransaction";
////try {
////	rpc_result = rpc->CallRPC(rpc_method, arguments);
////} catch (const UniValue& json_rpc_error) {
////	const std::string error_msg{find_value(json_rpc_error, "message").get_str()};
////	std::cout << "ERROR: " << error_msg << std::endl;
////	assert(false);
////}

////std::string compressed_transaction = rpc_result.get_str();

//////decompress
////rpc_method = "decompressrawtransaction";
////arguments.clear();
////arguments.push_back(compressed_transaction);
////try {
////	rpc_result = rpc->CallRPC(rpc_method, arguments);
////} catch (const UniValue& json_rpc_error) {
////	const std::string error_msg{find_value(json_rpc_error, "message").get_str()};
////	std::cout << "ERROR: " << error_msg << std::endl;
////	assert(false);
////}
////std::string decompressed_transaction = rpc_result.get_str();
////std::cout << "decomp: " << decompressed_transaction << std::endl;
////std::cout << "serili: " << serilized_transaction << std::endl;
////if (decompressed_transaction != serilized_transaction) {
////	if (decompressed_transaction.vin.size() != serilized_transaction.vin.size()) {
////		std::cout << "vin sizes don't match" << std::endl;
////	} else if (decompressed_transaction.vin != serilized_transaction.vin) {
////		int vin_length = decompressed_transaction.vin.size();
////		for (int vin_index = 0; vin_index < vin_length; vin_index++) {
////			if (decompressed_transaction.vin.at(vin_index).prevout != serilized_transaction.vin.at(vin_index).prevout) {
////				std::cout << "prevouts don't match (" << vin_index << ")" << std::endl;
////			}
////			if (decompressed_transaction.vin.at(vin_index).scriptSig != serilized_transaction.vin.at(vin_index).scriptSig) {
////				std::cout << "scriptSig don't match (" << vin_index << "): " << std::endl;
////				std::cout << "decomp " << HexStr(decompressed_transaction_vin.at(vin_index).scriptSig) << std::endl;
////				std::cout << "seri " << HexStr(serilized_transaction.at(vin_index).scriptSig) << std::endl;
////			}
////		} 
////	}
////}
////assert(decompressed_transaction == serilized_transaction);
}
