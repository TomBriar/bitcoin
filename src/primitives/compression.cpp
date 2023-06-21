#include <primitives/compression.h>

CCompressedTxId::CCompressedTxId(const uint256& txid) : m_block_height(0), m_block_index(0), m_txid(txid) {};

CCompressedTxId::CCompressedTxId(const uint32_t& block_height, const uint32_t& block_index) : m_block_height(block_height), m_block_index(block_index) {};

std::string CCompressedTxId::ToString() const
{
	return strprintf("CCompressedTxId(block_height=%u, block_index=%u, txid=%s)",
	m_block_height,
	m_block_index,
	HexStr(m_txid));
}

CCompressedOutPoint::CCompressedOutPoint(const CCompressedTxId& txid, const uint32_t& n) : m_txid(txid), m_n(n) {}

std::string CCompressedOutPoint::ToString() const
{
	return strprintf("CCompressedOutPoint(txid=%s, n=%u)",
	m_txid.ToString(),
	m_n);
}

CCompressedTxIn::CCompressedTxIn(secp256k1_context* ctx, const CTxIn& txin, const CCompressedTxId& txid, const CScript& scriptPubKey) : m_prevout(txid, txin.prevout.n) {
	m_compressedSignature = false;
	m_hashType = 0;
	if (txin.scriptSig.size() || txin.scriptWitness.stack.size()) {
		CScript scriptSig;
		if (scriptPubKey.IsPayToPublicKeyHash()) {
			scriptSig = txin.scriptSig;
		} else if (txin.scriptWitness.stack.size() && scriptPubKey.IsPayToWitnessPublicKeyHash()) {
			scriptSig = CScript(txin.scriptWitness.stack.at(0).begin(), txin.scriptWitness.stack.at(0).end());
		}
		if (scriptSig.size()) {
			opcodetype opcodeRet;
			CScriptBase::const_iterator pc = scriptSig.begin();
			scriptSig.GetOp(pc, opcodeRet, m_signature);
			m_hashType = m_signature.at(m_signature.size()-1);
			int length = m_signature.size()-1;
			secp256k1_ecdsa_signature sig;
			if (secp256k1_ecdsa_signature_parse_der(ctx, &sig, &m_signature[0], length)) {
				if (secp256k1_ecdsa_signature_serialize_compact(ctx, &m_signature[0], &sig)) {
					m_signature.resize(64);
					m_compressedSignature = true;
				}
			}
		} else if (txin.scriptWitness.stack.size() && scriptPubKey.IsPayToTaproot()) {
			if (txin.scriptWitness.stack.at(0).size() != 64) {
				m_signature = txin.scriptWitness.stack.at(0);
				m_hashType = m_signature[m_signature.size()-1];
				m_signature.pop_back();
			}
			m_compressedSignature = true;
		}
		if (!m_compressedSignature) {
			CDataStream stream(SER_DISK, 0);
			stream << VARINT(txin.scriptSig.size());
			if (txin.scriptSig.size())
				stream << txin.scriptSig;
			stream << VARINT(txin.scriptWitness.stack.size());
			for (size_t index = 0; index < txin.scriptWitness.stack.size(); index++) {
				stream << VARINT(txin.scriptWitness.stack.at(index).size());
				stream << txin.scriptWitness.stack.at(index);
			}
			m_signature.resize(stream.size());
			stream.read(MakeWritableByteSpan(m_signature));
		}
	}
	m_nSequence = txin.nSequence;
}

std::string CCompressedTxIn::ToString() const
{
	return strprintf("CCompressedTxIn(prevout=%s, signature=%s, compressed=%b, hashType=%u, nSequence=%u)",
	m_prevout.ToString(),
	HexStr(m_signature),
	m_compressedSignature,
	m_hashType,
	m_nSequence);
}

CCompressedTxOut::CCompressedTxOut(const CTxOut& txout) {
	m_nValue = txout.nValue;
	std::vector<std::vector<unsigned char>> solutions;
	m_scriptType = Solver(txout.scriptPubKey, solutions);
	switch (m_scriptType) {
		case TxoutType::PUBKEY:
		case TxoutType::PUBKEYHASH:
		case TxoutType::SCRIPTHASH:
		case TxoutType::WITNESS_V0_KEYHASH:
		case TxoutType::WITNESS_V0_SCRIPTHASH:
		case TxoutType::WITNESS_V1_TAPROOT:
			m_scriptPubKey = solutions.at(0);
			break;
		default:
			m_scriptPubKey.resize(txout.scriptPubKey.size());
			copy(txout.scriptPubKey.begin(), txout.scriptPubKey.end(), m_scriptPubKey.begin());
	}
}

std::string CCompressedTxOut::ToString() const
{
	return strprintf("CCompressedTxOut(scriptPubKey=%s, scriptType=%s, nValue=%u)",
	HexStr(m_scriptPubKey),
	GetTxnOutputType(m_scriptType),
	m_nValue);
}

CCompressedTransaction::CCompressedTransaction(secp256k1_context* ctx, const CTransaction tx, const std::vector<CCompressedTxId>& txids, const std::vector<CScript>& scriptPubKeys) {
	m_nVersion = tx.nVersion; 
	m_nLockTime = tx.nLockTime; 
	m_shortendLockTime = false;

	for (auto const& txout : tx.vout) {
		m_vout.push_back(CCompressedTxOut(txout));
	}

	for (size_t index = 0; index < tx.vin.size(); index++) {
		m_vin.push_back(CCompressedTxIn(ctx, tx.vin.at(index), txids.at(index), scriptPubKeys.at(index))); 
	}

	uint32_t limit = pow(2, 16);
	if (tx.nLockTime > limit) {
		for (uint32_t i = 0; i < tx.vin.size(); i++) {
			if (m_vin.at(i).compressedSignature()) {
				m_nLockTime = tx.nLockTime % limit;
				m_shortendLockTime = true;
			}
		}
	}
}

std::string CCompressedTransaction::ToString() const
{
	std::string str;
	str += strprintf("CCompressedTransaction(nVersion=%u, nLockTime=%u, shortendlocktim=%b,\n",
	m_nVersion,
	m_nLockTime,
	m_shortendLockTime);
	for (const auto& txin : m_vin)
		str += txin.ToString()+"\n";
	for (const auto& txout : m_vout)
		str += txout.ToString()+"\n";
	str += ")";
	return str;
}

CTxOut::CTxOut(const CCompressedTxOut& txout) {
	if (txout.IsCompressed()) {
		std::vector<std::vector<unsigned char>> vSolutions;
		vSolutions.push_back(std::move(txout.scriptPubKey()));
		CTxDestination destination;
		if(BuildDestination(vSolutions, txout.scriptType(), destination)) throw std::ios_base::failure("Script Deseralization Faild, Either Invalid Payload or Script Type.");
		scriptPubKey = GetScriptForDestination(destination);
	} else {
		scriptPubKey = CScript(txout.scriptPubKey().begin(), txout.scriptPubKey().end());
	}
	nValue = txout.nValue();
}

//TODO: Accept custom class for txids, outs, tx
CMutableTransaction::CMutableTransaction(const secp256k1_context* ctx, const CCompressedTransaction& tx, const std::vector<uint256>& txids, const std::vector<CTxOut>& outs) {
	assert(outs.size() == tx.vin().size());
	/* Set Values */
	nVersion = tx.nVersion();
	nLockTime = tx.nLockTime();
	for (const auto& txout : tx.vout()) {
		vout.push_back(CTxOut(txout));
	}
	for (size_t index = 0; index < tx.vin().size(); index++) {
		vin.push_back(CTxIn(COutPoint(txids.at(index), tx.vin().at(index).prevout().n()), CScript(), tx.vin().at(index).nSequence()));
	}

	/* Recover Sigantures*/
	for (size_t index = 0; index < tx.vin().size(); index++) {
		if (tx.vin().at(index).compressedSignature()) {
			/* Parse Signatures */
			std::vector<secp256k1_ecdsa_recoverable_signature> recoverableSignatures;
			if (outs.at(index).scriptPubKey.IsPayToPublicKeyHash() || outs.at(index).scriptPubKey.IsPayToWitnessPublicKeyHash()) {
				for (int recoveryId = 0; recoveryId < 4; recoveryId++) {
            		secp256k1_ecdsa_recoverable_signature rsig;
					if (secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, &tx.vin().at(index).signature()[0], recoveryId)) {
						recoverableSignatures.push_back(rsig);
					}
				}
		 	} else if (outs.at(index).scriptPubKey.IsPayToTaproot()) {
				std::vector<std::vector<unsigned char>> stack;
				stack.push_back(tx.vin().at(index).signature());
				if (tx.vin().at(index).hashType()) stack[0].push_back(tx.vin().at(index).hashType());
				vin.at(index).scriptWitness.stack = stack;
			}

			bool lockTimeFound = false;
			while(!lockTimeFound) {
				if (outs.at(index).scriptPubKey.IsPayToPublicKeyHash() || outs.at(index).scriptPubKey.IsPayToWitnessPublicKeyHash()) {
					/* Generate Message as Hash of the Transaction */
					std::vector<unsigned char> message(32);
					uint256 hash;
					if (outs.at(index).scriptPubKey.IsPayToPublicKeyHash()) {
						hash = SignatureHash(outs.at(index).scriptPubKey, *this, index, tx.vin().at(index).hashType(), outs.at(index).nValue, SigVersion::BASE);
					} else {
						std::vector<std::vector<unsigned char>> vSolutions;
						Solver(outs.at(index).scriptPubKey, vSolutions);
						CTxDestination destination;
						BuildDestination(vSolutions, TxoutType::WITNESS_V0_KEYHASH, destination);
						CScript scriptCode = GetScriptForDestination(destination);
						hash = SignatureHash(scriptCode, *this, index, tx.vin().at(index).hashType(), outs.at(index).nValue, SigVersion::WITNESS_V0);
					}
                    copy(hash.begin(), hash.end(), message.begin());

                    /* Dervive Signature Public Key Pairs */
                    for (auto const& rsig : recoverableSignatures) {
                        secp256k1_pubkey pubkey;
						secp256k1_ecdsa_signature sig;
                        if (secp256k1_ecdsa_recover(ctx, &pubkey, &rsig, &message[0])) {

							/* Serilize Compressed Pubkey */
							size_t cpSize = 33;
							std::vector<unsigned char> cpVec(cpSize);
							secp256k1_ec_pubkey_serialize(ctx, &cpVec[0], &cpSize, &pubkey, SECP256K1_EC_COMPRESSED);

							/* Hash Compressed Pubkey */
							uint160 cpHash;
							CHash160().Write(cpVec).Finalize(cpHash);

							/* Generate Compressed Address */
							std::vector<unsigned char> cpHashVec(20);
							copy(cpHash.begin(), cpHash.end(), cpHashVec.begin());
							std::vector<std::vector<unsigned char>> cpVSolutions;
							cpVSolutions.push_back(std::move(cpHashVec));
							CTxDestination cpDestination;
							if (outs.at(index).scriptPubKey.IsPayToPublicKeyHash()) {
								BuildDestination(cpVSolutions, TxoutType::PUBKEYHASH, cpDestination);
							} else {
								BuildDestination(cpVSolutions, TxoutType::WITNESS_V0_KEYHASH, cpDestination);
							}	
							CScript cpScriptPubKey = GetScriptForDestination(cpDestination);

							/* Test Compressed Address*/
							std::vector<unsigned char> pVec;
							size_t pSize = 0;
							if (cpScriptPubKey == outs.at(index).scriptPubKey) {
								pVec = std::move(cpVec);
								pSize = cpSize;
							} else if (outs.at(index).scriptPubKey.IsPayToPublicKeyHash()) {
								
								/* Serilize Uncompressed Pubkey */
								size_t ucpSize = 65;
								std::vector<unsigned char> ucpVec(ucpSize);
								secp256k1_ec_pubkey_serialize(ctx, &ucpVec[0], &ucpSize, &pubkey, SECP256K1_EC_UNCOMPRESSED);

								/* Hash Uncompressed Pubkey */
								uint160 ucpHash;
								CHash160().Write(ucpVec).Finalize(ucpHash);

								/* Generate Uncompressed Address */
								std::vector<unsigned char> ucpHashVec(20);
								copy(ucpHash.begin(), ucpHash.end(), ucpHashVec.begin());
								std::vector<std::vector<unsigned char>> ucpVSolutions;
								ucpVSolutions.push_back(std::move(ucpHashVec));
								CTxDestination ucpDestination;
								BuildDestination(ucpVSolutions, TxoutType::PUBKEYHASH, ucpDestination);
								CScript ucpScriptPubKey = GetScriptForDestination(ucpDestination);
		
								/* Test Uncompressed Address*/
								if (ucpScriptPubKey == outs.at(index).scriptPubKey) {
									pVec = std::move(ucpVec);
									pSize = ucpSize;
								} 
							}

							/* If Testing was Sucessful Recover Signature */
							if (pVec.size()) {
								secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &rsig);
								lockTimeFound = true;
								std::vector<unsigned char> sigDER (71);
								size_t sdSize = 71;
								secp256k1_ecdsa_signature_serialize_der(ctx, &sigDER[0], &sdSize, &sig);
								if (outs.at(index).scriptPubKey.IsPayToPublicKeyHash()) {
									std::vector<unsigned char> signature (1+sdSize+1+1+pSize);
									signature[0] = sdSize+1;
									copy(sigDER.begin(), sigDER.end(), signature.begin()+1);
									signature[sdSize+1] = tx.vin().at(index).hashType();
									signature[sdSize+2] = pSize;
									copy(pVec.begin(), pVec.end(), signature.begin()+sdSize+3);
									CScript scriptSig = CScript(signature.begin(), signature.end());
									vin.at(index).scriptSig = scriptSig;
									break;
								} else {
									std::vector<unsigned char> signature (sdSize+1);
									copy(sigDER.begin(), sigDER.end(), signature.begin());
									signature[sdSize] = tx.vin().at(index).hashType();
									std::vector<std::vector<unsigned char>> stack;
									stack.push_back(signature);
									stack.push_back(pVec);
									vin.at(index).scriptWitness.stack = stack;
									break;
								}
							}
						};
                    }
				} else if (outs.at(index).scriptPubKey.IsPayToTaproot()) {
					std::vector<unsigned char> schnorr_signature = tx.vin().at(index).signature();

					/* Script Execution Data Init */
					ScriptExecutionData execdata;
					execdata.m_annex_init = true;
					execdata.m_annex_present = false;

					/* Prevout Init */
					PrecomputedTransactionData cache;
					cache.Init(CTransaction(*this), std::vector<CTxOut>{outs}, true);

					/* Compute Signature Hash */
					uint256 hash;
					assert(SignatureHashSchnorr(hash, execdata, *this, index, tx.vin().at(index).hashType(), SigVersion::TAPROOT, cache, MissingDataBehavior::FAIL));
					
					/* Recover Public Key*/
					std::vector<unsigned char> pubkey_bytes;
					std::vector<std::vector<unsigned char>> vSolutions;
					assert(Solver(outs.at(index).scriptPubKey, vSolutions) == TxoutType::WITNESS_V1_TAPROOT);
					secp256k1_xonly_pubkey xonly_pubkey;
					assert(secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey, &(vSolutions[0])[0]));
						
					if (secp256k1_schnorrsig_verify(ctx, &tx.vin().at(index).signature()[0], hash.begin(), 32, &xonly_pubkey)) lockTimeFound = true;
				}

				/* If Testing was Unsuccessful Continue to Grid Locktime */
				if (!tx.shortendLockTime() || lockTimeFound) { 
					lockTimeFound = true; 
				} else {
					if (nLockTime > uint32_t(nLockTime + pow(2, 16))) break;
					nLockTime += pow(2, 16);
				}
			}
		} else if (tx.vin().at(index).IsSigned()) {
			CDataStream stream(SER_DISK, 0);
			stream.write(MakeByteSpan(tx.vin().at(index).signature()));
			uint64_t scriptSigLength = std::numeric_limits<uint64_t>::max();
			stream >> VARINT(scriptSigLength);
			if (scriptSigLength) {
				std::vector<unsigned char> scriptSigBytes(scriptSigLength);
				stream.read(MakeWritableByteSpan(scriptSigBytes));
				vin.at(index).scriptSig = CScript(scriptSigBytes.begin(), scriptSigBytes.end());
			}
			uint64_t witnessCount = std::numeric_limits<uint64_t>::max();
			stream >> VARINT(witnessCount);
			std::vector<std::vector<unsigned char>> stack;
			for (uint64_t i = 0; witnessCount < i; i++) {
				uint64_t witnessLength = std::numeric_limits<uint64_t>::max();
				stream >> VARINT(witnessLength);
				std::vector<unsigned char> witness(witnessLength);
				stream.read(MakeWritableByteSpan(witness));
				stack.push_back(witness);
			}
			vin.at(index).scriptWitness.stack = stack;
		}
	}
}
