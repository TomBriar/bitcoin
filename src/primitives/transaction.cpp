// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <consensus/amount.h>
#include <hash.h>
#include <script/script.h>
#include <serialize.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <version.h>

#include <cassert>
#include <stdexcept>

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeWitnessHash() const
{
    if (!HasWitness()) {
        return hash;
    }
    return SerializeHash(*this, SER_GETHASH, 0);
}

CTransaction::CTransaction(const CMutableTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}
CTransaction::CTransaction(CMutableTransaction&& tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), nVersion(tx.nVersion), nLockTime(tx.nLockTime), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut + tx_out.nValue))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        nValueOut += tx_out.nValue;
    }
    assert(MoneyRange(nValueOut));
    return nValueOut;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (const auto& tx_in : vin)
        str += "    " + tx_in.ToString() + "\n";
    for (const auto& tx_in : vin)
        str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (const auto& tx_out : vout)
        str += "    " + tx_out.ToString() + "\n";
    return str;
}

std::string CCompressedTransaction::ToString() const
{
	std::string str;
	str += strprintf("CCompressedTransaction:\n	InputCount=%u,\n	nOutputCount=%u,\n	nVersion=%u,\n	nLockTime=%u\n",
	nInputCount,
	nOutputCount,
	nVersion,
	nLockTime);
	for (const auto& txin : vin)
		str += strprintf("	CCompressedTxIn:\n		signature=%s,\n		hashType=%u,\n		CCompressedOutPoint:\n			CCompressedTxId:\n				block_height=%u,\n				block_index=%u\n			n=%u\n		nSquence=%u,\n		compressed=%b\n",
		HexStr(txin.signature),
		txin.hashType,
		txin.prevout.txid.block_height,
		txin.prevout.txid.block_index,
		txin.prevout.n,
		txin.nSequence,
		txin.compressed);
	for (const auto& txout : vout)
		str += strprintf("	CCompressedTxOut:\n		scriptPubKey=%s\n		compressed=%b\n,		nValue=%u",
		HexStr(txout.scriptPubKey),
		txout.compressed,
		txout.nValue);
	return str;
}

CCompressedTxId::CCompressedTxId() : block_height(0), block_index(0) {};
CCompressedTxId::CCompressedTxId(const uint32_t& block_height, const uint32_t& block_index) : block_height(block_height), block_index(block_index) {};

CCompressedOutPoint::CCompressedOutPoint(const uint32_t& n, const CCompressedTxId& txid) : txid(txid), n(n) {}

CCompressedTxIn::CCompressedTxIn(secp256k1_context* ctx, const CTxIn& txin, const CCompressedTxId& txid, const CScript& scriptPubKey) : prevout(txin.prevout.n, txid) {
	prevout = CCompressedOutPoint(txin.prevout.n, txid);
	compressed = false;
	CScript scriptSig;
	if (scriptPubKey.IsPayToPublicKeyHash()) {
		scriptSig = txin.scriptSig;
	} else if (scriptPubKey.IsPayToWitnessPublicKeyHash()) {
		scriptSig = CScript(txin.scriptWitness.stack.at(0).begin(), txin.scriptWitness.stack.at(0).end());
	}
	if (scriptSig.size() == 0) {
		opcodetype opcodeRet;
		CScriptBase::const_iterator pc = scriptSig.begin();
		scriptSig.GetOp(pc, opcodeRet, signature);
		hashType = signature.at(signature.size()-1);
		int length = signature.size()-1;
		secp256k1_ecdsa_signature sig;
		if (secp256k1_ecdsa_signature_parse_der(ctx, &sig, &signature[0], length)) {
			if (secp256k1_ecdsa_signature_serialize_compact(ctx, &signature[0], &sig)) {
				signature.resize(length);
				compressed = true;
			}
		}
	} else if (scriptPubKey.IsPayToTaproot()) {
		signature = txin.scriptWitness.stack.at(0);
		//TODO: based on sig length parse hashType
		hashType = 0;
		compressed = true;
	}
	if (!compressed) {
		CDataStream stream(SER_DISK, 0);
		stream << VARINT(txin.scriptSig.size());
		stream << txin.scriptSig;
		for (size_t index = 0; index < txin.scriptWitness.stack.size(); index++) {
			stream << VARINT(txin.scriptWitness.stack.at(index).size());
			stream << txin.scriptWitness.stack.at(index);
		}
		std::vector<std::byte> sig_stream(stream.size());
		stream.read(sig_stream);
		signature = reinterpret_cast<std::vector<unsigned char> &&> (sig_stream);
	}
	nSequence = txin.nSequence;
}

CCompressedTxOut::CCompressedTxOut(const CTxOut& txout) {
	scriptType = txout.scriptPubKey.GetScriptType();
	if (scriptType != scripttype::Custom) {
		opcodetype opcodeRet;
		CScriptBase::const_iterator pc = txout.scriptPubKey.begin();
		while (pc < txout.scriptPubKey.end()) {
			txout.scriptPubKey.GetOp(pc, opcodeRet, scriptPubKey);
			if (scriptPubKey.size() > 0) {
				break;
			}
		}	
		compressed = true;
	} else {
		copy(txout.scriptPubKey.begin(), txout.scriptPubKey.end(), scriptPubKey.begin());
		compressed = false;
	}
}

CCompressedTransaction::CCompressedTransaction(secp256k1_context* ctx, const CTransaction tx, const std::vector<CCompressedTxId>& txids, const std::vector<CScript>& scriptPubKeys) {
		nInputCount = tx.vin.size();
		nOutputCount = tx.vout.size(); 
		nVersion = tx.nVersion; 
		nLockTime = tx.nLockTime; 
		for (auto const& txout : tx.vout) {
			vout.push_back(CCompressedTxOut(txout));
		}
		for (size_t index = 0; index < tx.vin.size(); index++) {
			vin.push_back(CCompressedTxIn(ctx, tx.vin.at(index), txids.at(index), scriptPubKeys.at(index))); 
		}
	}
