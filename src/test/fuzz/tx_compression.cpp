// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/util/setup_common.h>
#include <primitives/transaction.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <rpc/blockchain.h>
#include <rpc/request.h>
#include <validation.h>
#include <rpc/client.h>
#include <rpc/server.h>
#include <univalue.h>
#include <util/rbf.h>
#include <univalue.h>
#include <rpc/util.h>
#include <core_io.h>
#include <version.h>
#include <logging.h>
#include <cassert>
#include <cmath>

#include <base58.h>
#include <core_io.h>
#include <key.h>
#include <key_io.h>
#include <node/context.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <rpc/blockchain.h>
#include <rpc/client.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <span.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>

#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>


namespace {
	struct TXCompressionFuzzTestingSetup : public TestingSetup {
		TXCompressionFuzzTestingSetup(const std::string& chain_name, const std::vector<const char*>& extra_args) : TestingSetup{chain_name, extra_args} 
		{}

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
	};

	TXCompressionFuzzTestingSetup* rpc = nullptr;
	TXCompressionFuzzTestingSetup* InitializeTXCompressionFuzzTestingSetup()
	{
		static const auto setup = MakeNoLogFileContext<TXCompressionFuzzTestingSetup>();
		SetRPCWarmupFinished();
		return setup.get();
	}
};

void tx_compression_initialize()
{
    SelectParams(CBaseChainParams::REGTEST);
	rpc = InitializeTXCompressionFuzzTestingSetup();
}

FUZZ_TARGET_INIT(tx_compression, tx_compression_initialize)
{
	FuzzedDataProvider fdp(buffer.data(), buffer.size());
	CMutableTransaction mtx;
	mtx = ConsumeTransaction(fdp, {}, 100, 100);
	std::vector<std::string> arguments;
	std::string rpc_method = "compressrawtransaction";
	arguments.push_back(EncodeHexTx(CTransaction(mtx)));
	try {
    	rpc->CallRPC(rpc_method, arguments);
	} catch (const UniValue& json_rpc_error) {
		const std::string error_msg{find_value(json_rpc_error, "message").get_str()};
		std::cout << "ERROR: " << error_msg << std::endl;
		// Once c++20 is allowed, starts_with can be used.
		// if (error_msg.starts_with("Internal bug detected")) {
		if (0 == error_msg.rfind("Internal bug detected", 0)) {
			// Only allow the intentional internal bug
			assert(error_msg.find("trigger_internal_bug") != std::string::npos);
		}
	}
}
