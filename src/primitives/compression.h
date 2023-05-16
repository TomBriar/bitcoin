#ifndef BITCOIN_PRIMITIVES_COMPRESSION_H
#define BITCOIN_PRIMITIVES_COMPRESSION_H

#include <streams.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <consensus/amount.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <cmath>
#include <logging.h>
#include <util/strencodings.h>
#include <bitset>


class CCompressedTxId
{
public:
    uint32_t block_height;
    uint32_t block_index;

    explicit CCompressedTxId();
    explicit CCompressedTxId(const uint32_t& block_height, const uint32_t& block_index);


	friend bool operator==(const CCompressedTxId& a, const CCompressedTxId& b)
	{
		return a.block_height == b.block_height && a.block_index == b.block_index;
	}
};

class CCompressedOutPoint
{
public:
	CCompressedTxId txid;
    uint32_t n;

	explicit CCompressedOutPoint(const uint32_t& n, const CCompressedTxId& txid);

	friend bool operator==(const CCompressedOutPoint& a, const CCompressedOutPoint& b)
	{
		return a.txid == b.txid && a.n == b.n;
	}
};

class CCompressedTxIn
{
public:
	std::vector<unsigned char> signature;
	uint8_t hashType;
    CCompressedOutPoint prevout;
    uint32_t nSequence;
	bool standardSequence;
	bool compressed;
	bool sigSigned;

	explicit CCompressedTxIn(secp256k1_context* ctx, const CTxIn& txin, const CCompressedTxId& txid, const CScript& scriptPubKey);

	friend bool operator==(const CCompressedTxIn& a, const CCompressedTxIn& b)
	{
		return a.signature == b.signature && a.hashType == b.hashType && a.prevout == b.prevout && a.nSequence == b.nSequence && a.compressed == b.compressed && a.sigSigned == b.sigSigned;
	}
};


class CCompressedTxOut
{
public:
	std::vector<unsigned char> scriptPubKey;
	TxoutType scriptType;
	bool compressed;
    uint32_t nValue;

	explicit CCompressedTxOut(const CTxOut& txout);

	friend bool operator==(const CCompressedTxOut& a, const CCompressedTxOut& b)
	{
		return a.scriptPubKey == b.scriptPubKey && a.scriptType == b.scriptType && a.compressed == b.compressed && a.nValue == b.nValue;
	}
};

/** A compressed version of CTransaction. */
struct CCompressedTransaction
{
    uint32_t nInputCount;
    uint32_t nOutputCount;
	uint32_t nVersion;
	uint32_t nLockTime;
	bool shortendLockTime;
	bool coinbase;

	CCompressedTransaction()
	{
		SetNull();
	}

	std::vector<CCompressedTxIn> vin;
	std::vector<CCompressedTxOut> vout;

    explicit CCompressedTransaction(secp256k1_context* ctx, const CTransaction tx, const std::vector<CCompressedTxId>& txids, const std::vector<CScript>& scriptPubKeys);

	void SetNull()
	{
		nInputCount = 0;
		nOutputCount = 0;
		nVersion = 0;
		nLockTime = 0;
		shortendLockTime = false;
		vin.clear();
		vout.clear();
	}

	bool IsNull() const
	{
		return (nInputCount == 0);
	}	

	friend bool operator==(const CCompressedTransaction& a, const CCompressedTransaction& b)
	{
		return a.nInputCount == b.nInputCount && a.nOutputCount == b.nOutputCount && a.nVersion == b.nVersion && a.nLockTime == b.nLockTime && a.shortendLockTime == b.shortendLockTime && a.vin == b.vin && a.vout == b.vout;
	}

    bool IsMinimalInput() {return nInputCount < 4;}
    bool IsMinimalOutput() {return nOutputCount < 4;}
	/* Transaction
		"B"  : Input Byte
			"bb" : Version
			"bb" : Input Count
			"bb" : Input Type
			"bb" : Lock Time
		"B"  : Output Byte
			"bbb": Sequence
			"bb": Output Count
			"bbb": Output Type
		"B"  : Coinbase Byte
			"b": Coinbase
		"?"   : Version VarInt      if (Input Byte & 0x03 == 0x00)
		"?"   : Input Count VarInt  if (Input Byte & 0x0c == 0x00)
		"B"  : Input Type Byte     if (Input Byte & 0x30 == 0x01)
		"BB": LockTime Shortend   if (Input Byte & 0xc0 == 0x01)
		"?"   : LockTime VarInt     if (Input Byte & 0xc0 == 0x03)
		"?"   : Sequence VarInt     if (Output Byte & 0x07 == 0x01)
		"B"  : Sequence Byte       if (Output Byte & 0x07 == 0x02)
		"?"   : Output Count VarInt if (Output Byte & 0x18 == 0x00)
		for each input {
			"?"        : Sequence VarInt          if (Output Byte & 0x07 == 0x00)
			"B"       : Input Type Byte          if (Input Byte & 0x30 == 0x00)
			"?"        : TXID Block Height VarInt if (!coinbase)
			"?"        : TXID Block Index VarInt  if (!coinbase)
			"32 B" : TXID                     if (coinbase)
			"?"        : Signature Script Length VarInt if (input_type == CustomInput)
			"?"        : Signature Script               if (input_type == CustomInput)
			"?"        : Witness Count                  if (input_type == CustomInput)
			for each witness {
				"?" : Witness Length VarInt if (input_type == CustomInput)
				"?" : Witness               if (input_type == CustomInput)
			}
			"65 B" : Signature Script         if (input_type != CustomInput)
		}
		for each output {
			"B"       : Output Type Byte         if (Output Byte & 0x07 == 0x00)
			"?"        : Amount VarInt
			"?"        : Script Length VarInt     if (output_type == CustomOutput)
			"?"        : Script                   
		}
	*/
	/* Compressed Transaction
		"?": Control VarInt
			"bb": Version
			"bb": Input Count 
			"bb": Output Count
			"bb": LockTime
			"b": Coinbase
			"bb": Input Compression
			"bbb": Sequence 
			"bbb": Output Compression
	*/


	template <typename Stream>
	inline void Serialize(Stream& s) const {
		uint64_t control = 0;
		/* Version */
		int version = 0, inputCount = 0, outputCount = 0, lockTime = 0, inputType = 0, outputTypeInt = 0, sequenceInt = 0;
		if (this->nVersion < 4) version = this->nVersion;
		if (this->nInputCount < 4) inputCount = this->nInputCount;
		if (this->nOutputCount < 4) outputCount = this->nOutputCount;
		if (this->shortendLockTime) lockTime = 1; else if (this->nLockTime != 0) lockTime = 2;
		std::cout << "control = " << std::bitset<32>(control) << std::endl;

		bool inputCompressed = this->vin.at(0).compressed;
		bool identicalInputCompression = true;

		uint32_t sequence = this->vin.at(0).nSequence;
		bool allStandard = this->vin.at(0).standardSequence;
		bool identicalSequence = true;

		for (size_t i = 1; i < this->vin.size(); i++) {
			if (this->vin.at(i).compressed != inputCompressed) identicalInputCompression = false;
			if (sequence != this->vin.at(i).nSequence) identicalSequence = false;
			if (allStandard) allStandard = this->vin.at(i).standardSequence;
		}

		if (identicalInputCompression) {
			if (inputCompressed) inputType = 3; else inputType = 2;
		} else {
			if (this->nInputCount < 9) inputType = 1;
		}
		
		if (identicalSequence) {
			if (allStandard) {
				if (sequence == 0x00000000) sequenceInt = 1;
				if (sequence == 0xFFFFFFF0) sequenceInt = 2;
				if (sequence == 0xFFFFFFFE) sequenceInt = 3;
				if (sequence == 0xFFFFFFFF) sequenceInt = 4;
			} else sequenceInt = 5;
		} else {
			if (allStandard && this->nInputCount < 5) sequenceInt = 6;
		}

		TxoutType outputType = this->vout.at(0).scriptType;
		bool identicalOutputCompression = true;
		for (size_t i = 1; i < this->vout.size(); i++) {
			if (this->vout.at(i).scriptType != outputType) identicalOutputCompression = false;
		}
		if (identicalOutputCompression) {
			if (outputType == TxoutType::PUBKEY) outputTypeInt = 1;
			if (outputType == TxoutType::PUBKEYHASH) outputTypeInt = 2;
			if (outputType == TxoutType::SCRIPTHASH) outputTypeInt = 3;
			if (outputType == TxoutType::WITNESS_V0_SCRIPTHASH) outputTypeInt = 4;
			if (outputType == TxoutType::WITNESS_V0_KEYHASH) outputTypeInt = 5;
			if (outputType == TxoutType::WITNESS_V1_TAPROOT) outputTypeInt = 6;
			if (outputType == TxoutType::NONSTANDARD) outputTypeInt = 7;
		}
		control |= version;
		control |= inputCount << 2;
		control |= outputCount << 4;
		control |= lockTime << 6;
		control |= this->coinbase << 8;
		control |= inputType << 9;
		control |= sequenceInt << 12;
		control |= outputTypeInt << 15;
		std::cout << "control = " << std::bitset<32>(control) << std::endl;
		s << VARINT(control);

		if (!version) s << VARINT(this->nVersion);
		if (!inputCount) s << VARINT(this->nInputCount);
		if (!outputCount) s << VARINT(this->nOutputCount);
		if (!lockTime) s << VARINT(this->nLockTime);
		if (inputType == 1) {
			uint64_t inputTypeInt = 0;
			for (size_t i = 0; i < this->vin.size(); i++) {
				if (this->vin.at(i).compressed) inputTypeInt |= (1 << i);
			}
			s << VARINT(inputTypeInt);
		}
		if (sequenceInt == 5) s << VARINT(this->vin.at(0).nSequence);
		if (sequenceInt == 6) {
			uint64_t compressedSequenceInt = 0;
			for (size_t i = 0; i < this->vin.size(); i++) {
				if (this->vin.at(i).nSequence == 0x00000000) compressedSequenceInt |= (0 << (i*2));
				if (this->vin.at(i).nSequence == 0xFFFFFFF0) compressedSequenceInt |= (1 << (i*2));
				if (this->vin.at(i).nSequence == 0xFFFFFFFE) compressedSequenceInt |= (2 << (i*2));
				if (this->vin.at(i).nSequence == 0xFFFFFFFF) compressedSequenceInt |= (3 << (i*2));
			}
			s << VARINT(compressedSequenceInt);
		}

	}

	template <typename Stream>
	inline void Unserialize(Stream& s) {
		std::cout << "DESERIALIZE" << std::endl;
		uint64_t control = std::numeric_limits<uint64_t>::max();
		s >> VARINT(control);
		int version = control & 0b11;
		int inputCount = control & (0b11 << 2);
		int outputCount = control & (0b11 << 4);
		int lockTime = control & (0b11 << 6);
////	bool coinbase = control & (0b11 << 7);
		int inputType = control & (0b1 << 9);
		int sequenceInt = control & (0b111 << 12);
////	int outputTypeInt = control & (0b111 << 15);
		std::cout << "control = " << std::bitset<32>(control) << std::endl;

		if (!version) {
			this->nVersion = std::numeric_limits<uint32_t>::max();
			s >> VARINT(this->nVersion);
		} else this->nVersion = version;

		if (!inputCount) {
			this->nInputCount = std::numeric_limits<uint32_t>::max();
			s >> VARINT(this->nInputCount);
		} else this->nInputCount = inputCount;

		if (!outputCount) {
			this->nOutputCount = std::numeric_limits<uint32_t>::max();
			s >> VARINT(this->nOutputCount);
		} else this->nOutputCount = outputCount;
	
		if (!lockTime) {
			this->nLockTime = std::numeric_limits<uint32_t>::max();
			s >> VARINT(this->nLockTime);
		} else this->nLockTime = lockTime;
		
		uint64_t compressedInputType;
		if (inputType == 1) {
			compressedInputType = std::numeric_limits<uint64_t>::max();
			s >> VARINT(compressedInputType);
		}
		uint64_t onlySequence;
		uint64_t compressedSequence;
		if (sequenceInt == 5) {
			onlySequence = std::numeric_limits<uint64_t>::max();
			s >> VARINT(onlySequence);
		} else if (sequenceInt == 6) {
			compressedSequence = std::numeric_limits<uint64_t>::max();
			s >> VARINT(compressedSequence);
		}
	


	}

	template <typename Stream>
	CCompressedTransaction(deserialize_type, Stream& s) {
		Unserialize(s);
	}

    std::string ToString() const;
};

#endif // BITCOIN_PRIMITIVES_COMPRESSION_H
