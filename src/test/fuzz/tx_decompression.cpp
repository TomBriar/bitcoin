// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/util/setup_common.h>
#include <primitives/transaction.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
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

namespace {
	struct TXDecompressionFuzzTestingSetup : public TestingSetup {
		TXDecompressionFuzzTestingSetup(const std::string& chain_name, const std::vector<const char*>& extra_args) : TestingSetup{chain_name, extra_args} 
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

	TXDecompressionFuzzTestingSetup* rpc = nullptr;
	TXDecompressionFuzzTestingSetup* InitializeTXDecompressionFuzzTestingSetup()
	{
		static const auto setup = MakeNoLogFileContext<TXDecompressionFuzzTestingSetup>();
		SetRPCWarmupFinished();
		return setup.get();
	}
};

void tx_decompression_initialize()
{
    SelectParams(CBaseChainParams::REGTEST);
	rpc = InitializeTXDecompressionFuzzTestingSetup();
}

FUZZ_TARGET_INIT(tx_decompression, tx_decompression_initialize)
{
	const std::string tx_hex = HexStr(buffer);
    std::vector<std::string> arguments;
    std::string rpc_method = "decompressrawtransaction";
	arguments.push_back(tx_hex);
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
