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
#include <primitives/compression.h>

using node::BlockManager;
using node::BlockAssembler;
using node::CBlockTemplate;
using node::ReadBlockFromDisk;
using node::GetTransaction;
using node::RegenerateCommitments;
using node::FindCoins;

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

		void GetCoins(std::map<COutPoint, Coin>& map) {
			FindCoins(m_node, map);
		}

		bool IsTopBlock(CBlock block) {
			LOCK(cs_main);
			if (m_node.chainman->ActiveChain().Tip()->GetBlockHash() == block.GetHash()) return true;
			return false;
		}

		CScript GenerateDestination(secp256k1_context* ctx, secp256k1_keypair kp, int scriptInt, std::vector<unsigned char> custom_script_bytes){
			secp256k1_pubkey pubkey;
			assert(secp256k1_keypair_pub(ctx, &pubkey, &kp));
			std::vector<std::vector<unsigned char>> vSolutions;
			TxoutType scriptType = TxoutType::NONSTANDARD;
			bool pc = true;
			//TODO: use scripthashes
			switch(scriptInt) {
				case 0:
					scriptType = TxoutType::PUBKEY;
					break;
				case 1:
					scriptType = TxoutType::PUBKEYHASH;
					break;
				case 2:
					//scriptType = TxoutType::SCRIPTHASH;
					scriptType = TxoutType::PUBKEYHASH;
					break;
				case 3:
					scriptType = TxoutType::WITNESS_V0_KEYHASH;
					break;
				case 4:
					//scriptType = TxoutType::WITNESS_V0_SCRIPTHASH;
					scriptType = TxoutType::PUBKEYHASH;
					break;
				case 5:
					scriptType = TxoutType::WITNESS_V1_TAPROOT;
					break;
				case 6:
					scriptType = TxoutType::PUBKEYHASH;
					pc = false;
					break;
			}

			if (scriptType == TxoutType::PUBKEY) { 
				std::vector<unsigned char> ucPubkey (65);
				size_t ucSize = 65;
				secp256k1_ec_pubkey_serialize(ctx, &ucPubkey[0], &ucSize, &pubkey, SECP256K1_EC_UNCOMPRESSED);
				vSolutions.push_back(ucPubkey);
			} else if (scriptType == TxoutType::PUBKEYHASH) {
				if (pc) {
					std::vector<unsigned char> cPubkey (33);
					size_t cSize = 33;
					secp256k1_ec_pubkey_serialize(ctx, &cPubkey[0], &cSize, &pubkey, SECP256K1_EC_COMPRESSED);
					uint160 cpHash;
					CHash160().Write(cPubkey).Finalize(cpHash);
					std::vector<unsigned char> cpHashBytes(20);
					copy(cpHash.begin(), cpHash.end(), cpHashBytes.begin());
					vSolutions.push_back(cpHashBytes);
				} else {
					std::vector<unsigned char> ucPubkey (65);
					size_t ucSize = 65;
					secp256k1_ec_pubkey_serialize(ctx, &ucPubkey[0], &ucSize, &pubkey, SECP256K1_EC_UNCOMPRESSED);
					uint160 ucpHash;
					CHash160().Write(ucPubkey).Finalize(ucpHash);
					std::vector<unsigned char> ucpHashBytes(20);
					copy(ucpHash.begin(), ucpHash.end(), ucpHashBytes.begin());
					vSolutions.push_back(ucpHashBytes);
				}
			} else if (scriptType == TxoutType::WITNESS_V0_SCRIPTHASH || scriptType == TxoutType::SCRIPTHASH) {
				std::vector<unsigned char> cPubkey (33);
				size_t cSize = 33;
				secp256k1_ec_pubkey_serialize(ctx, &cPubkey[0], &cSize, &pubkey, SECP256K1_EC_COMPRESSED);
				uint160 cpHash;
				CHash160().Write(cPubkey).Finalize(cpHash);
				std::vector<unsigned char> cpHashBytes(20);
				copy(cpHash.begin(), cpHash.end(), cpHashBytes.begin());
				std::vector<std::vector<unsigned char>> vSolutionsTemp;
				vSolutionsTemp.push_back(cpHashBytes);
				CTxDestination destination;
				BuildDestination(vSolutionsTemp, scriptType, destination);
				CScript p2pkh = GetScriptForDestination(destination);
				uint160 scriptHash;
				CHash160().Write(p2pkh).Finalize(scriptHash);
				std::vector<unsigned char> script(20);
				copy(scriptHash.begin(), scriptHash.end(), script.begin());
				vSolutions.push_back(script);
			} else if (scriptType == TxoutType::WITNESS_V0_KEYHASH) {
				std::vector<unsigned char> cPubkey (33);
				size_t cSize = 33;
				secp256k1_ec_pubkey_serialize(ctx, &cPubkey[0], &cSize, &pubkey, SECP256K1_EC_COMPRESSED);
				uint160 cpHash;
				CHash160().Write(cPubkey).Finalize(cpHash);
				std::vector<unsigned char> cpHashBytes(20);
				copy(cpHash.begin(), cpHash.end(), cpHashBytes.begin());
				vSolutions.push_back(cpHashBytes);
			} else if (scriptType == TxoutType::WITNESS_V1_TAPROOT) {
				/* Serilize XOnly Pubkey */
				secp256k1_xonly_pubkey xonly_pubkey;
				assert(secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_pubkey, NULL, &pubkey));
				std::vector<unsigned char> xonly_pubkey_bytes (32);
				secp256k1_xonly_pubkey_serialize(ctx, &xonly_pubkey_bytes[0], &xonly_pubkey);

				/* Construct Script */
				std::vector<unsigned char> taprootScript(32);
				copy(xonly_pubkey_bytes.begin(), xonly_pubkey_bytes.end(), taprootScript.begin());
				vSolutions.push_back(taprootScript);
			} else if (scriptType == TxoutType::NONSTANDARD) {
				vSolutions.push_back(custom_script_bytes);
			}
			CTxDestination destination;
			BuildDestination(vSolutions, scriptType, destination);
			return GetScriptForDestination(destination);
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
	std::vector<std::tuple<uint256, secp256k1_keypair, uint32_t, int, CScript, uint256, CCompressedTxId>> unspent_transactions;
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

		int script_type = frandom_ctx.randrange(7);
		std::vector<unsigned char> custom_script_bytes = frandom_ctx.randbytes(128);
		CScript coinbase_scriptPubKey =	rpc->GenerateDestination(ctx, coinbase_kp, script_type, custom_script_bytes);

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
		int script_type = frandom_ctx.randrange(7);
		std::vector<unsigned char> custom_script_bytes = frandom_ctx.randbytes(128);
		CScript coinbase_scriptPubKey =	rpc->GenerateDestination(ctx, coinbase_kp, script_type, custom_script_bytes);

		std::vector<CMutableTransaction> txins;
		CBlock coinbase_block =	rpc->CreateAndProcessBlock(txins, coinbase_scriptPubKey);
		assert(rpc->IsTopBlock(coinbase_block));
		uint256 txid = coinbase_block.vtx.at(0)->GetHash();
		unspent_transactions.push_back(std::make_tuple(txid, coinbase_kp, 0, coinbase_block.vtx.at(0)->vout.at(0).nValue, coinbase_scriptPubKey, txid, rpc->GetCompressedTxId(txid, coinbase_block)));
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

			int script_type = frandom_ctx.randrange(7);
			std::vector<unsigned char> custom_script_bytes = frandom_ctx.randbytes(128);
			out.scriptPubKey = rpc->GenerateDestination(ctx, out_kp, script_type, custom_script_bytes);
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

		int script_type = frandom_ctx.randrange(7);
		std::vector<unsigned char> custom_script_bytes = frandom_ctx.randbytes(128);
		main_scriptPubKey = rpc->GenerateDestination(ctx, main_kp, script_type, custom_script_bytes);

		std::vector<CMutableTransaction> txins;
		txins.push_back(mtx);
		CBlock main_block = rpc->CreateAndProcessBlock(txins, main_scriptPubKey);
		assert(rpc->IsTopBlock(main_block));
		for (auto const& out : outs) {
			uint256 txid = mtx.GetHash();
			unspent_transactions.push_back(std::make_tuple(txid,  std::get<0>(out), std::get<1>(out), std::get<2>(out), std::get<3>(out), txid, rpc->GetCompressedTxId(txid, main_block)));
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
	std::vector<uint256> txids;
	std::vector<CCompressedTxId> compressed_txids;
	std::vector<int> used_indexs;


	// GENERATE INPUTS //
	LIMITED_WHILE(total == 0 || fdp.ConsumeBool(), static_cast<unsigned char>(unspent_transactions.size()-1)) {
		int index = fdp.ConsumeIntegralInRange<int>(0, unspent_transactions.size()-1);
		if (std::find(used_indexs.begin(), used_indexs.end(), index) != used_indexs.end())
			break;
		used_indexs.push_back(index);
		uint256 txid = std::get<0>(unspent_transactions.at(index));
		keypairs.push_back(std::get<1>(unspent_transactions.at(index)));
		uint32_t vout = std::get<2>(unspent_transactions.at(index));
		input_scripts.push_back(std::get<4>(unspent_transactions.at(index)));
		txids.push_back(std::get<5>(unspent_transactions.at(index)));
		compressed_txids.push_back(std::get<6>(unspent_transactions.at(index)));
		
		total += std::get<3>(unspent_transactions.at(index));

		CTxIn in;
		in.prevout = COutPoint{txid, vout};
		in.nSequence = fdp.ConsumeIntegral<uint32_t>();
		mtx.vin.push_back(in);
	}


	// GENERATE OUTPUTS //
	uint32_t remaining_amount = total;
	bool sign = true;
	LIMITED_WHILE(remaining_amount > 2000 && (fdp.ConsumeBool() || mtx.vout.size() == 0), 10000) {
		CTxOut out;	
		uint32_t limit = pow(2, 16);
		int range_amount;
		if (remaining_amount > limit) {
			range_amount = limit-1000;
		} else {
			range_amount = remaining_amount-1000;
		}
		uint16_t amount = fdp.ConsumeIntegralInRange<uint16_t>(1, range_amount);
		remaining_amount -= amount;
		out.nValue = amount;

		std::vector<unsigned char> secret_key = fdp.ConsumeBytes<uint8_t>(32);
		if (secret_key.size() != 32) return;
		secp256k1_keypair out_kp;
		if (!secp256k1_keypair_create(ctx, &out_kp, &secret_key[0])) return;

		CScript out_scriptPubKey;

		int script_type = fdp.ConsumeIntegralInRange<uint16_t>(0, 7);
		if (script_type == 7) 
			sign = false;
		std::vector<unsigned char> custom_script_bytes = fdp.ConsumeBytes<uint8_t>(128);
		out.scriptPubKey = rpc->GenerateDestination(ctx, out_kp, script_type, custom_script_bytes);
		mtx.vout.push_back(out);
	}
	if (mtx.vout.size() == 0) return;
	
	if (sign)
		assert(rpc->SignTransaction(ctx, mtx, keypairs));

	std::cout << "tx: " << CTransaction(mtx).ToString() << std::endl;

    const CTransaction tx = CTransaction(mtx);
    CCompressedTransaction compressed_transaction = CCompressedTransaction(ctx, tx, compressed_txids, input_scripts);
	std::cout << "doneou" << std::endl;
	
    std::cout << "ctx: " << compressed_transaction.ToString() << std::endl;
//	CCompressedTransaction uct = compressed_transaction;
////std::cout << "prevout compressed: " << compressed_transaction.vin.at(0).prevout.txid().ToString() << std::endl;
////CDataStream stre(SER_DISK, 0);
////bool compressed = compressed_transaction.vin.at(0).prevout.txid().IsCompressed();
////compressed_transaction.vin.at(0).prevout.txid().Serialize(stre);
////std::cout << "stream: " << HexStr(stre) << std::endl;
////CCompressedTxId txid = CCompressedTxId(deserialize, stre, compressed);
////std::cout << "prveout: " << txid.ToString() << std::endl;
////

////assert(false);

    CDataStream stream(SER_DISK, 0);
    compressed_transaction.Serialize(stream);
	std::cout << "SERIALIZED: " << HexStr(stream) << std::endl;
    CCompressedTransaction uct = CCompressedTransaction();
    uct.Unserialize(stream);
    
    std::cout << "ctx: " << compressed_transaction.ToString() << std::endl;
    std::cout << "uct: " << uct.ToString() << std::endl;
	assert(compressed_transaction.vin == uct.vin);
	assert(compressed_transaction.vout == uct.vout);
    assert(compressed_transaction == uct);
	
	//TODO: serilize and unserilize

    std::map<COutPoint, Coin> coins;
    for (size_t index = 0; index < uct.vin.size(); index++) {
    	coins[COutPoint(txids.at(index), uct.vin.at(index).prevout.n())]; // Create empty map entry keyed by prevout.
    }
    rpc->GetCoins(coins);
    std::vector<CTxOut> outs;
	for (size_t index = 0; index < uct.vin.size(); index++) {
    	outs.push_back(coins[COutPoint(txids.at(index), uct.vin.at(index).prevout.n())].out);
    }
    CTransaction new_tx = CTransaction(CMutableTransaction(ctx, uct, txids, outs));
    std::cout << "uctx: " << new_tx.ToString() << std::endl;
	assert(tx == new_tx);
}
