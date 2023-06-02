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
	uint256 txid;
	bool compressed;

    explicit CCompressedTxId();
    explicit CCompressedTxId(const uint32_t& block_height, const uint32_t& block_index);
    explicit CCompressedTxId(const uint256& txid);


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

	explicit CCompressedOutPoint();
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
	bool compressed;

	explicit CCompressedTxIn();
	explicit CCompressedTxIn(secp256k1_context* ctx, const CTxIn& txin, const CCompressedTxId& txid, const CScript& scriptPubKey);
	
	uint8_t SerializeSequence() const {
		if (this->nSequence == 0xFFFFFFF0) return 1;
		if (this->nSequence == 0xFFFFFFFE) return 2;
		if (this->nSequence == 0xFFFFFFFF) return 3;
		return 0;
	}

	void UnserializeSequence(uint8_t sequenceEncoding) {
		if (sequenceEncoding == 0) this->nSequence = 0x00000000;
		if (sequenceEncoding == 1) this->nSequence = 0xFFFFFFF0;
		if (sequenceEncoding == 2) this->nSequence = 0xFFFFFFFE;
		if (sequenceEncoding == 3) this->nSequence = 0xFFFFFFFF;
	}

	bool isSigned() const {
		return this->signature.size() > 0;
	}

	bool isSequenceStandard() const {
		return this->nSequence == 0x00 || this->nSequence == 0xFFFFFFF0 || this->nSequence == 0xFFFFFFFE || this->nSequence == 0xFFFFFFFF;
	}
	
	bool isHashStandard() const {
		return this->hashType == 0x00 || this->hashType == 0x01;
	}

	friend bool operator==(const CCompressedTxIn& a, const CCompressedTxIn& b)
	{
		return a.signature == b.signature && a.hashType == b.hashType && a.prevout == b.prevout && a.nSequence == b.nSequence && a.compressed == b.compressed;
	}
};


class CCompressedTxOut
{
public:
	std::vector<unsigned char> scriptPubKey;
	TxoutType scriptType;
	bool compressed;
    uint32_t nValue;

	explicit CCompressedTxOut();
	explicit CCompressedTxOut(const CTxOut& txout);
	
	uint8_t SerializeType() const {
		if (this->scriptType == TxoutType::PUBKEY) return 1;
		if (this->scriptType == TxoutType::PUBKEYHASH) return 2;
		if (this->scriptType == TxoutType::SCRIPTHASH) return 3;
		if (this->scriptType == TxoutType::WITNESS_V0_SCRIPTHASH) return 4;
		if (this->scriptType == TxoutType::WITNESS_V0_KEYHASH) return 5;
		if (this->scriptType == TxoutType::WITNESS_V1_TAPROOT) return 6;
		return 0;
	}
	void UnserializeType(uint8_t outputTypeI) {
		if (outputTypeI == 1) this->scriptType = TxoutType::PUBKEY;
		if (outputTypeI == 2) this->scriptType = TxoutType::PUBKEYHASH;
		if (outputTypeI == 3) this->scriptType = TxoutType::SCRIPTHASH;
		if (outputTypeI == 4) this->scriptType = TxoutType::WITNESS_V0_SCRIPTHASH;
		if (outputTypeI == 5) this->scriptType = TxoutType::WITNESS_V0_KEYHASH;
		if (outputTypeI == 6) this->scriptType = TxoutType::WITNESS_V1_TAPROOT;
		if (outputTypeI == 7) this->scriptType = TxoutType::NONSTANDARD;
	}

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
		"?": Version Varint 			if (Version == 0)
		"?": InputCount Varint 		 	if (InputCount == 0)
		"?": OutputCount Varint		 	if (OutputCount == 0)
		"?": Locktime Varint  			if (LockTime == 0)
		for each input/output {
			"?" VControl VarInt
				"b": Signed
				"b": Compressed Siganture
				"b": Taproot Signature
				"b": Compressed Txid 
				"b": Standard Hash
				"b": Hash Type
				"b": Sequence Standard
				"bb": Sequence Encoding
				"bbb": Script Type
		}
		for each input {
			"B" Sequence				if (Sequence == 0)
			"?" Block Height 			if (Compressed TxId == 1)
			"?" Block Index 			if (Compressed TxId == 1)
			"32 B" TxId 				if (Compressed TxId == 0)
			"?" Vout
			"?" Signature Length		if (Signed && Compressed Signature == 0)
			"?" Signature 				if (Signed && Compressed Signature == 0)
			"64 B" Signature 			if (Signed && Compressed Siganture == 1)
			"1 B"  Hash Type 			if (Standard Hash == 0)
		}
		for each output {
			"?": Script Length			if (Script Type == 0)
			"B 65|32|20|?": Script 
			"?": Amount
		}
	*/

	template <typename Stream>
	inline void Serialize(Stream& s) const {
		uint8_t version = 0;
		if (this->nVersion < 4) version = this->nVersion;
		uint8_t inputCount = 0;
		if (this->nInputCount < 4) inputCount = this->nInputCount;
		uint8_t outputCount = 0;
		if (this->nOutputCount < 4) outputCount = this->nOutputCount;
		uint8_t lockTime = 0;
		if (this->shortendLockTime) lockTime = 1; else if (this->nLockTime != 0) lockTime = 2;

		uint64_t control = version;
		control |= inputCount << 2;
		control |= outputCount << 4;
		control |= lockTime << 6;
		s << VARINT(control);
		std::cout << "c: " << std::bitset<64>(control) << std::endl;

		if (!version) s << VARINT(this->nVersion);
		if (!inputCount) s << VARINT(this->nInputCount);
		if (!outputCount) s << VARINT(this->nOutputCount);
		if (lockTime) s << VARINT(this->nLockTime);

		for (size_t index = 0; index < std::max(this->vin.size(), this->vout.size()); index++) {
			bool signatureSigned = 0;
			bool compressedSignature = 0;
			bool compressedTxId = 0;
			bool standardHash = 0;
			bool hashType = 0;
			bool standardSequence = 0;
			uint8_t sequenceEncoding = 0;
			if (this->vin.size() > index) {
				signatureSigned = this->vin.at(index).isSigned();
				compressedSignature = this->vin.at(index).compressed;
				compressedTxId = this->vin.at(index).prevout.txid.compressed;
				standardHash = this->vin.at(index).isHashStandard();
				hashType = this->vin.at(index).hashType;
				standardSequence = this->vin.at(index).isSequenceStandard();
				sequenceEncoding = this->vin.at(index).SerializeSequence();
			}
			uint8_t scriptType = 7;
			if (this->vout.size() > index) {
				if (this->vout.at(index).scriptPubKey.size()) scriptType = this->vout.at(index).SerializeType();
			}
			uint64_t vControl = 0;
			vControl |= signatureSigned;
			vControl |= compressedSignature << 1;
			vControl |= compressedTxId << 2;
			vControl |= standardHash << 3;
			vControl |= hashType << 4;
			vControl |= standardSequence << 5;
			vControl |= sequenceEncoding << 6;
			vControl |= scriptType << 8;
			s << VARINT(vControl);
			std::cout << "vc: " << std::bitset<64>(vControl) << std::endl;

			if (this->vin.size() > index) {
				if (!standardSequence) s << VARINT(this->vin.at(index).nSequence);
				if (compressedTxId) {
					s << VARINT(this->vin.at(index).prevout.txid.block_height);
					s << VARINT(this->vin.at(index).prevout.txid.block_index);
				} else {
					s.write(MakeByteSpan(this->vin.at(index).prevout.txid.txid));
				}
				s << VARINT(this->vin.at(index).prevout.n);
				if (signatureSigned) {
					if (compressedSignature) {
						std::cout << "compressed >>>><<<<" << std::endl;
						s.write(MakeByteSpan(this->vin.at(index).signature));
						if (!standardHash) s << this->vin.at(index).hashType;
					} else {
						s << VARINT(this->vin.at(index).signature.size());
						s.write(MakeByteSpan(this->vin.at(index).signature));
						s << VARINT(this->vin.at(index).hashType);
					}
				}
			}
			if (this->vout.size() > index) {
				if (scriptType != 7) {
					if (!scriptType) s << VARINT(this->vout.at(index).scriptPubKey.size());
					s.write(MakeByteSpan(this->vout.at(index).scriptPubKey));
				}
				s << VARINT(this->vout.at(index).nValue);
			}
		}
	}

	template <typename Stream>
	inline void Unserialize(Stream& s) {
		std::cout << "desirialize" << std::endl;
		uint64_t control = std::numeric_limits<uint64_t>::max();
		s >> VARINT(control);
		std::cout << "c: " << std::bitset<64>(control) << std::endl;
		uint8_t version = control & 0b11;
		uint8_t inputCount = (control & (0b11 << 2)) >> 2;
		uint8_t outputCount = (control & (0b11 << 4)) >> 4;
		uint8_t lockTime = (control & (0b11 << 6)) >> 6;

		if (!version) {
			std::cout << "version varint" << std::endl;
			this->nVersion = std::numeric_limits<uint32_t>::max();
			s >> VARINT(this->nVersion);
		} else this->nVersion = version;
		if (!inputCount) {
			std::cout << "input varint" << std::endl;
			this->nInputCount = std::numeric_limits<uint32_t>::max();
			s >> VARINT(this->nInputCount);
		} else this->nInputCount = inputCount;
		if (!outputCount) {
			std::cout << "output varint" << std::endl;
			this->nOutputCount = std::numeric_limits<uint32_t>::max();
			s >> VARINT(this->nOutputCount);
		} else this->nOutputCount = outputCount;
		if (lockTime) {
			std::cout << "lock varint" << std::endl;
			this->nLockTime = std::numeric_limits<uint32_t>::max();
			s >> VARINT(this->nLockTime);
		} else this->nLockTime = lockTime;


		for (size_t index = 0; index < std::max(this->nInputCount, this->nOutputCount); index++) {
			uint64_t vControl = std::numeric_limits<uint64_t>::max();
			s >> VARINT(vControl);
			std::cout << "vc: " << std::bitset<64>(vControl) << std::endl;
			
			bool signatureSigned = vControl & 0b1;
			bool compressedSignature = (vControl & (0b1 << 1)) >> 1;
			bool compressedTxId = (vControl & (0b1 << 2)) >> 2;
			bool standardHash = (vControl & (0b1 << 3)) >> 3;
			bool hashType = (vControl & (0b1 << 4)) >> 4;
			bool standardSequence = (vControl & (0b1 << 5)) >> 5;
			uint8_t sequenceEncoding = (vControl & (0b11 << 6)) >> 6;
			uint8_t scriptType = (vControl & (0b111 << 8)) >> 8;
			std::cout << "test: " << standardHash << ", " << hashType << std::endl;

			if (this->nInputCount > index) {
 				std::cout << "input: " << index << std::endl;
				CCompressedTxIn vin{};
				CCompressedOutPoint prevout{};
				CCompressedTxId txid{};
				if (standardSequence) {vin.UnserializeSequence(sequenceEncoding);} 
				else {
					vin.nSequence = std::numeric_limits<uint32_t>::max();
					s >> VARINT(vin.nSequence);
				}
				if (compressedTxId) {
					txid.block_height = std::numeric_limits<uint32_t>::max();
					txid.block_index = std::numeric_limits<uint32_t>::max();
					s >> VARINT(txid.block_height);
					s >> VARINT(txid.block_index);
					txid.compressed = true;
				} else {
					std::vector<std::byte> vbTxId(32);
					s.read(vbTxId);
					txid.txid = uint256(reinterpret_cast<std::vector<unsigned char> &&> (vbTxId));
				}
				prevout.txid = txid;
				
				prevout.n = std::numeric_limits<uint32_t>::max();
				s >> VARINT(prevout.n);
				std::cout << "prvout.n " << prevout.n << std::endl;
				if (signatureSigned) {
					if (compressedSignature) {
						std::vector<std::byte> vbSignature(64);
						s.read(vbSignature);
						vin.signature = reinterpret_cast<std::vector<unsigned char> &&> (vbSignature);
						if (standardHash) {
							vin.hashType = hashType;
						} else {
							vin.hashType = std::numeric_limits<uint8_t>::max();
							s >> VARINT(vin.hashType);
						}
						vin.compressed = true;
					} else {
						uint64_t scriptLength = std::numeric_limits<uint64_t>::max();
						s >> VARINT(scriptLength);
						std::vector<std::byte> vbSignature(scriptLength);
						s.read(vbSignature);
						vin.signature = reinterpret_cast<std::vector<unsigned char> &&> (vbSignature);
						vin.hashType = std::numeric_limits<uint8_t>::max();
						s >> VARINT(vin.hashType);	
						std::cout << "ht: " << vin.hashType << std::endl;
					}
					std::cout << "sig: " << HexStr(vin.signature) << std::endl;
				}
				vin.prevout = prevout;
				this->vin.push_back(vin);
			}
			if (this->nOutputCount > index) {
 				std::cout << "output: " << index << std::endl;
				CCompressedTxOut vout;
				vout.UnserializeType(scriptType);

				uint64_t scriptLength = std::numeric_limits<uint64_t>::max();
				switch(scriptType) {
					case 1:
						scriptLength = 65;
						break;
					case 2:
					case 3:
					case 5:
						scriptLength = 20;
						break;
					case 4:
					case 6:
						scriptLength = 32;
						break;
					case 7:
						break;
					default:
						s >> VARINT(scriptLength);
						break;
				}
				if (scriptType != 7) {
					std::cout << "scriptLength: " << scriptLength << std::endl;
					std::vector<std::byte> vbScriptPubKey(scriptLength);
					s.read(vbScriptPubKey);
					vout.scriptPubKey = reinterpret_cast<std::vector<unsigned char> &&> (vbScriptPubKey);
					vout.compressed = scriptType > 0 && scriptType < 7;
				
					std::cout << "scriptPubKey: " << HexStr(vout.scriptPubKey) << std::endl;
				}
				vout.nValue = std::numeric_limits<uint32_t>::max();
				s >> VARINT(vout.nValue);
				this->vout.push_back(vout);
			}
		}
	}

	template <typename Stream>
	CCompressedTransaction(deserialize_type, Stream& s) {
		Unserialize(s);
	}

    std::string ToString() const;
};

#endif // BITCOIN_PRIMITIVES_COMPRESSION_H
