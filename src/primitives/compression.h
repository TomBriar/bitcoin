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
private:
	uint32_t m_block_height;
	uint32_t m_block_index;
	uint256 m_txid;
public:
	const uint32_t&  block_height() const  { return m_block_height; }
    const uint32_t& block_index() const { return m_block_index; }
	const uint256& txid() const { return m_txid; }

    explicit CCompressedTxId(const uint32_t& block_height, const uint32_t& block_index);
    explicit CCompressedTxId(const uint256& txid);

	bool IsCompressed() const {
		return m_txid.IsNull();
	}

	friend bool operator==(const CCompressedTxId& a, const CCompressedTxId& b) {
		return a.m_block_height == b.m_block_height && a.m_block_index == b.m_block_index && a.m_txid	== b.m_txid;
	}
	friend bool operator!=(const CCompressedTxId& a, const CCompressedTxId& b) {
		return !(a == b);
	}

	template <typename Stream>
	inline void Serialize(Stream& s) const {
		if (this->IsCompressed()) {
			s << VARINT(this->m_block_height);
			s << VARINT(this->m_block_index);
		} else {
			s.write(MakeByteSpan(this->m_txid));
		}
	}

	template <typename Stream>
	inline void Unserialize(Stream& s, bool& compressed) {
		if (compressed) {
			this->m_block_height = std::numeric_limits<uint32_t>::max();
			this->m_block_index = std::numeric_limits<uint32_t>::max();
			s >> VARINT(this->m_block_height);
			s >> VARINT(this->m_block_index);
		} else {
			std::vector<unsigned char> txid(32);
			s.read(MakeWritableByteSpan(txid));
			this->m_txid = uint256(txid);
		}
	}

	template <typename Stream>
	CCompressedTxId(deserialize_type, Stream& s, bool& compressed) {
		Unserialize(s, compressed);
	}

    std::string ToString() const;
};

class CCompressedOutPoint
{
private:
	CCompressedTxId m_txid;
	uint32_t m_n;
public:
	const CCompressedTxId& txid() const { return m_txid; }
    const uint32_t& n() const { return m_n; }

	explicit CCompressedOutPoint(const CCompressedTxId& txid, const uint32_t& n);

	friend bool operator==(const CCompressedOutPoint& a, const CCompressedOutPoint& b) {
		return a.m_txid == b.m_txid && a.m_n == b.m_n;
	}
	friend bool operator!=(const CCompressedOutPoint& a, const CCompressedOutPoint& b) {
		return !(a == b);
	}

	template <typename Stream>
	inline void Serialize(Stream& s) const {
		this->m_txid.Serialize(s);
		s << VARINT(this->m_n);	
	}

	template <typename Stream>
	inline void Unserialize(Stream& s, bool& compressedTxId, bool constructor=false) {
		if (!constructor) this->m_txid.Unserialize(s, compressedTxId);
		this->m_n = std::numeric_limits<uint32_t>::max();
		s >> VARINT(this->m_n);
	}

	template <typename Stream>
	explicit CCompressedOutPoint(deserialize_type, Stream& s, bool& compressedTxId) : m_txid(CCompressedTxId(deserialize, s, compressedTxId)) {
		Unserialize(s, compressedTxId, true);
	}

    std::string ToString() const;
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
	explicit CCompressedTxIn(const CCompressedOutPoint& prevout);
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
    uint32_t nValue;

	explicit CCompressedTxOut();
	explicit CCompressedTxOut(const CTxOut& txout);

	bool IsCompressed() const {
		return this->scriptType == TxoutType::PUBKEY || this->scriptType == TxoutType::PUBKEYHASH || this->scriptType == TxoutType::SCRIPTHASH || this->scriptType == TxoutType::WITNESS_V0_KEYHASH || this->scriptType == TxoutType::WITNESS_V0_SCRIPTHASH || this->scriptType == TxoutType::WITNESS_V1_TAPROOT;
	}

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
		if (outputTypeI > 7) throw std::ios_base::failure(strprintf("Script Type Deseralization must be 1-7, %s is not a valid Script Type.", ToString(outputTypeI)));
	}

	friend bool operator==(const CCompressedTxOut& a, const CCompressedTxOut& b)
	{
		return a.scriptPubKey == b.scriptPubKey && a.scriptType == b.scriptType && a.nValue == b.nValue;
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

	CCompressedTransaction() {};

	std::vector<CCompressedTxIn> vin;
	std::vector<CCompressedTxOut> vout;

    explicit CCompressedTransaction(secp256k1_context* ctx, const CTransaction tx, const std::vector<CCompressedTxId>& txids, const std::vector<CScript>& scriptPubKeys);

	bool IsCoinbase() const {
		if (this->vin.size() > 1) return this->vin.at(0).prevout.n() == 4294967295;
		return false;
	} 

	friend bool operator==(const CCompressedTransaction& a, const CCompressedTransaction& b)
	{
		return a.nInputCount == b.nInputCount && a.nOutputCount == b.nOutputCount && a.nVersion == b.nVersion && a.nLockTime == b.nLockTime && a.shortendLockTime == b.shortendLockTime && a.vin == b.vin && a.vout == b.vout;
	}

	friend bool operator!=(const CCompressedTransaction& a, const CCompressedTransaction& b)
	{
		return !(a == b);
	}
	
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
				compressedTxId = this->vin.at(index).prevout.txid().IsCompressed();
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
				this->vin.at(index).prevout.Serialize(s);
				if (signatureSigned) {
					if (compressedSignature) {
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
		this->shortendLockTime = false;
		if (lockTime) {
			if (lockTime ==	1) this->shortendLockTime = true;
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
				uint32_t nSequence;
				if (standardSequence) {
					switch(sequenceEncoding) {
						case 0: nSequence = 0x00000000; 
							break;
						case 1: nSequence = 0xFFFFFFF0;
							break;
						case 2: nSequence = 0xFFFFFFFE;
							break;
						case 3: nSequence = 0xFFFFFFFF;
							break;
					}
				} else {
					nSequence = std::numeric_limits<uint32_t>::max();
					s >> VARINT(nSequence);
				}

				std::cout << "hi" << std::endl;
				CCompressedTxIn vin = CCompressedTxIn(CCompressedOutPoint(deserialize, s, compressedTxId));
				std::cout << "bye" << std::endl;
				vin.nSequence = nSequence;

				if (signatureSigned) {
					if (compressedSignature) {
						vin.signature.resize(64);
						s.read(MakeWritableByteSpan(vin.signature));
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
						vin.signature.resize(scriptLength);
						s.read(MakeWritableByteSpan(vin.signature));
						vin.hashType = std::numeric_limits<uint8_t>::max();
						s >> VARINT(vin.hashType);	
					}
				}
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
					vout.scriptPubKey.resize(scriptLength);
					s.read(MakeWritableByteSpan(vout.scriptPubKey));
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
