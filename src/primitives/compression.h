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
	inline void Unserialize(Stream& s, bool compressed) {
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
	CCompressedTxId(deserialize_type, Stream& s, bool compressed) {
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
	inline void Unserialize(Stream& s, bool compressedTxId, bool constructor=false) {
		if (!constructor) this->m_txid.Unserialize(s, compressedTxId);
		this->m_n = std::numeric_limits<uint32_t>::max();
		s >> VARINT(this->m_n);
	}

	template <typename Stream>
	explicit CCompressedOutPoint(deserialize_type, Stream& s, bool compressedTxId) : m_txid(CCompressedTxId(deserialize, s, compressedTxId)) {
		Unserialize(s, compressedTxId, true);
	}

    std::string ToString() const;
};

class CCompressedTxIn
{
private:
    CCompressedOutPoint m_prevout;
	std::vector<unsigned char> m_signature;
	bool m_compressedSignature;
	uint8_t m_hashType;
    uint32_t m_nSequence;
public:
	const CCompressedOutPoint& prevout() const { return m_prevout; }
	const std::vector<unsigned char>& signature() const { return m_signature; }
	const bool& compressedSignature() const { return m_compressedSignature; }
	const uint8_t& hashType() const { return m_hashType; }
	const uint32_t& nSequence() const { return m_nSequence; }

	explicit CCompressedTxIn(secp256k1_context* ctx, const CTxIn& txin, const CCompressedTxId& txid, const CScript& scriptPubKey);
	
	bool IsSigned() const {
		return this->m_signature.size() > 0;
	}

	bool IsSequenceStandard() const {
		return this->m_nSequence == 0x00 || this->m_nSequence == 0xFFFFFFF0 || this->m_nSequence == 0xFFFFFFFE || this->m_nSequence == 0xFFFFFFFF;
	}
	
	bool IsHashStandard() const {
		return this->m_hashType == 0x00 || this->m_hashType == 0x01;
	}

	friend bool operator==(const CCompressedTxIn& a, const CCompressedTxIn& b) {
		return a.m_prevout == b.m_prevout && a.m_signature == b.m_signature && a.m_compressedSignature == b.m_compressedSignature && a.m_hashType == b.m_hashType && a.m_nSequence == b.m_nSequence;
	}

	friend bool operator!=(const CCompressedTxIn& a, const CCompressedTxIn& b) {
		return !(a == b);
	}

	uint64_t GetMetadata() const {
		uint64_t metadata = 0;
		metadata |= this->IsSigned();
		metadata |= this->m_compressedSignature << 1;
		metadata |= this->m_prevout.txid().IsCompressed() << 2;
		metadata |= this->IsHashStandard() << 3;
		metadata |= (this->m_hashType > 0) << 4;
		metadata |= this->IsSequenceStandard() << 5;
		metadata |= ((this->m_nSequence == 0xFFFFFFF0) ? 0x01 : (this->m_nSequence == 0xFFFFFFFE) ? 0x02 : (this->m_nSequence == 0xFFFFFFFF) ? 0x03 : 0x00) << 6;
		return metadata;
	}

	template <typename Stream>
	inline void Serialize(Stream& s) const {
		this->m_prevout.Serialize(s);
		if (this->IsSigned()) {
			if (this->m_compressedSignature) {
				s.write(MakeByteSpan(this->m_signature));
				if (!this->IsHashStandard()) s << this->m_hashType;
			} else {
				s << VARINT(this->m_signature.size());
				s.write(MakeByteSpan(this->m_signature));
				s << VARINT(this->m_hashType);
			}
		}
		if (!this->IsSequenceStandard()) s << VARINT(this->m_nSequence);
	}

	template <typename Stream>
	inline void Unserialize(Stream& s, uint64_t& metadata, bool constructor=false) {
		bool signatureSigned = metadata & 0b1;
		m_compressedSignature = (metadata & (0b1 << 1)) >> 1;
		bool compressedTxId = (metadata & (0b1 << 2)) >> 2;
		bool standardHash = (metadata & (0b1 << 3)) >> 3;
		bool hashType = (metadata & (0b1 << 4)) >> 4;
		bool standardSequence = (metadata & (0b1 << 5)) >> 5;
		uint8_t sequenceEncoding = (metadata & (0b11 << 6)) >> 6;

		if (!constructor) this->m_prevout.Unserialize(s, compressedTxId);
			
		if (signatureSigned) {
			if (this->m_compressedSignature) {
				m_signature.resize(64);
				s.read(MakeWritableByteSpan(m_signature));
				if (standardHash) {
					m_hashType = hashType;
				} else {
					m_hashType = std::numeric_limits<uint8_t>::max();
					s >> VARINT(m_hashType);
				}
			} else {
				uint64_t scriptLength = std::numeric_limits<uint64_t>::max();
				s >> VARINT(scriptLength);
				m_signature.resize(scriptLength);
				s.read(MakeWritableByteSpan(m_signature));
				m_hashType = std::numeric_limits<uint8_t>::max();
				s >> VARINT(m_hashType);	
			}
		} else m_hashType = 0;

		if (standardSequence) {
			if (sequenceEncoding == 0x01) m_nSequence = 0xFFFFFFF0;
			if (sequenceEncoding == 0x02) m_nSequence = 0xFFFFFFFE;
			if (sequenceEncoding == 0x03) m_nSequence = 0xFFFFFFFF;
			if (sequenceEncoding == 0x00) m_nSequence = 0x00;
		} else {
			m_nSequence = std::numeric_limits<uint32_t>::max();
			s >> VARINT(m_nSequence);
		}
	}

	template <typename Stream>
	explicit CCompressedTxIn(deserialize_type, Stream& s, uint64_t& metadata) : m_prevout(CCompressedOutPoint(deserialize, s, ((metadata & (0b1 << 2)) >> 2) == 1)) {
		Unserialize(s, metadata, true);
	}

    std::string ToString() const;
};


class CCompressedTxOut
{
private:
	std::vector<unsigned char> m_scriptPubKey;
	TxoutType m_scriptType;
    uint32_t m_nValue;
public:
	const std::vector<unsigned char>& scriptPubKey() const { return m_scriptPubKey; }
	const TxoutType& scriptType() const { return m_scriptType; }
	const uint32_t& nValue() const { return m_nValue; }

	explicit CCompressedTxOut(const CTxOut& txout);

	bool IsCompressed() const {
		return this->m_scriptType == TxoutType::PUBKEY || this->m_scriptType == TxoutType::PUBKEYHASH || this->m_scriptType == TxoutType::SCRIPTHASH || this->m_scriptType == TxoutType::WITNESS_V0_KEYHASH || this->m_scriptType == TxoutType::WITNESS_V0_SCRIPTHASH || this->m_scriptType == TxoutType::WITNESS_V1_TAPROOT;
	}

	friend bool operator==(const CCompressedTxOut& a, const CCompressedTxOut& b)
	{
		return a.m_scriptPubKey == b.m_scriptPubKey && a.m_scriptType == b.m_scriptType && a.m_nValue == b.m_nValue;
	}

	uint8_t GetSerializedScriptType() const {
		if (!this->m_scriptPubKey.size()) return 0;
		if (this->m_scriptType == TxoutType::PUBKEY) return 1;
		if (this->m_scriptType == TxoutType::PUBKEYHASH) return 2;
		if (this->m_scriptType == TxoutType::SCRIPTHASH) return 3;
		if (this->m_scriptType == TxoutType::WITNESS_V0_SCRIPTHASH) return 4;
		if (this->m_scriptType == TxoutType::WITNESS_V0_KEYHASH) return 5;
		if (this->m_scriptType == TxoutType::WITNESS_V1_TAPROOT) return 6;
		return 7;
	}

	template <typename Stream>
	inline void Serialize(Stream& s) const {
		if (this->m_scriptPubKey.size()) {
			if (!this->IsCompressed()) s << VARINT(this->m_scriptPubKey.size());
			s.write(MakeByteSpan(this->m_scriptPubKey));
		}
		s << VARINT(this->m_nValue);
	}

	template <typename Stream>
	inline void Unserialize(Stream& s, uint8_t& serializedScriptType) {
		if (serializedScriptType == 0) {
			this->m_scriptType = TxoutType::NONSTANDARD;
		} else {
			uint64_t scriptLength = std::numeric_limits<uint64_t>::max();
			if (serializedScriptType == 1) {
				scriptLength = 65;
				this->m_scriptType = TxoutType::PUBKEY;
			} else if (serializedScriptType == 2) {
				scriptLength = 20;
				this->m_scriptType = TxoutType::PUBKEYHASH;
			} else if (serializedScriptType == 3) {
				scriptLength = 20;
				this->m_scriptType = TxoutType::SCRIPTHASH;
			} else if (serializedScriptType == 4) {
				scriptLength = 32;
				this->m_scriptType = TxoutType::WITNESS_V0_SCRIPTHASH;
			} else if (serializedScriptType == 5) {
				scriptLength = 20;
				this->m_scriptType = TxoutType::WITNESS_V0_KEYHASH;
			} else if (serializedScriptType == 6) {
				scriptLength = 32;
				this->m_scriptType = TxoutType::WITNESS_V1_TAPROOT;
			} else if (serializedScriptType == 7) {
				s >> VARINT(scriptLength);
				this->m_scriptType = TxoutType::NONSTANDARD;
			} else {
				throw std::ios_base::failure(strprintf("Script Type Deseralization must be 0-7, %u is not a valid Script Type.", serializedScriptType));
			}
			this->m_scriptPubKey.resize(scriptLength);
			s.read(MakeWritableByteSpan(this->m_scriptPubKey));
		}
		this->m_nValue = std::numeric_limits<uint32_t>::max();
		s >> VARINT(this->m_nValue);
	}

	template <typename Stream>
	explicit CCompressedTxOut(deserialize_type, Stream& s, uint8_t& serializedScriptType) { 
		Unserialize(s, serializedScriptType);
	}

    std::string ToString() const;
};

/** A compressed version of CTransaction. */
class CCompressedTransaction
{
private:
	uint32_t m_nVersion;
	uint32_t m_nLockTime;
	bool m_shortendLockTime;
	std::vector<CCompressedTxIn> m_vin;
	std::vector<CCompressedTxOut> m_vout;
public:

	const uint32_t& nVersion() const { return m_nVersion; }
	const uint32_t& nLockTime() const { return m_nLockTime; }
	const bool& shortendLockTime() const { return m_shortendLockTime; }
	const std::vector<CCompressedTxIn>& vin() const { return m_vin; }
	const std::vector<CCompressedTxOut>& vout() const { return m_vout; }

    explicit CCompressedTransaction(secp256k1_context* ctx, const CTransaction tx, const std::vector<CCompressedTxId>& txids, const std::vector<CScript>& scriptPubKeys);

	bool IsCoinbase() const {
		if (this->m_vin.size() > 1) return this->m_vin.at(0).prevout().n() == 4294967295;
		return false;
	} 

	friend bool operator==(const CCompressedTransaction& a, const CCompressedTransaction& b)
	{
		return a.m_nVersion == b.m_nVersion && a.m_nLockTime == b.m_nLockTime && a.m_shortendLockTime == b.m_shortendLockTime && a.m_vin == b.m_vin && a.m_vout == b.m_vout;
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
		if (this->m_nVersion < 4) version = this->m_nVersion;
		uint8_t inputCount = 0;
		if (this->m_vin.size() < 4) inputCount = this->m_vin.size();
		uint8_t outputCount = 0;
		if (this->m_vout.size() < 4) outputCount = this->m_vout.size();
		uint8_t lockTime = 0;
		if (this->m_shortendLockTime) lockTime = 1; else if (this->m_nLockTime != 0) lockTime = 2;

		uint64_t control = version;
		control |= inputCount << 2;
		control |= outputCount << 4;
		control |= lockTime << 6;
		s << VARINT(control);

		if (!version) s << VARINT(this->m_nVersion);
		if (!inputCount) s << VARINT(this->m_vin.size());
		if (!outputCount) s << VARINT(this->m_vout.size());
		if (lockTime) s << VARINT(this->m_nLockTime);

		for (size_t index = 0; index < std::max(this->m_vin.size(), this->m_vout.size()); index++) {
			uint64_t vControl = 0;
			if (this->m_vin.size() > index) vControl = this->m_vin.at(index).GetMetadata();
			uint8_t serializedScriptType = 0;
			if (this->m_vout.size() > index) serializedScriptType = this->m_vout.at(index).GetSerializedScriptType();
			vControl |= serializedScriptType << 8;
			s << VARINT(vControl);
			if (this->m_vin.size() > index) this->m_vin.at(index).Serialize(s);
			if (this->m_vout.size() > index) this->m_vout.at(index).Serialize(s);
		}
	}

	template <typename Stream>
	inline void Unserialize(Stream& s) {
		uint64_t control = std::numeric_limits<uint64_t>::max();
		s >> VARINT(control);
		uint8_t version = control & 0b11;
		uint8_t inputCount = (control & (0b11 << 2)) >> 2;
		uint8_t outputCount = (control & (0b11 << 4)) >> 4;
		uint8_t lockTime = (control & (0b11 << 6)) >> 6;
		uint32_t nInputCount = std::numeric_limits<uint32_t>::max();
		uint32_t nOutputCount = std::numeric_limits<uint32_t>::max();

		if (!version) {
			this->m_nVersion = std::numeric_limits<uint32_t>::max();
			s >> VARINT(this->m_nVersion);
		} else this->m_nVersion = version;
		if (!inputCount) {
			s >> VARINT(nInputCount);
		} else nInputCount = inputCount;
		if (!outputCount) {
			s >> VARINT(nOutputCount);
		} else nOutputCount = outputCount;
		this->m_shortendLockTime = false;
		if (lockTime) {
			if (lockTime ==	1) this->m_shortendLockTime = true;
			this->m_nLockTime = std::numeric_limits<uint32_t>::max();
			s >> VARINT(this->m_nLockTime);
		} else this->m_nLockTime = lockTime;

		for (size_t index = 0; index < std::max(nInputCount, nOutputCount); index++) {
			uint64_t vControl = std::numeric_limits<uint64_t>::max();
			s >> VARINT(vControl);
			uint8_t serializedScriptType = (vControl & (0b111 << 8)) >> 8;

			if (nInputCount > index) this->m_vin.push_back(CCompressedTxIn(deserialize, s, vControl));
			if (nOutputCount > index) this->m_vout.push_back(CCompressedTxOut(deserialize, s, serializedScriptType));
		}
	}

	template <typename Stream>
	CCompressedTransaction(deserialize_type, Stream& s) {
		Unserialize(s);
	}

    std::string ToString() const;
};

#endif // BITCOIN_PRIMITIVES_COMPRESSION_H
