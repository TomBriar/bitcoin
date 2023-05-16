#include <primitives/compression.h>

CMutableTransaction::CMutableTransaction(const secp256k1_context* ctx, const CCompressedTransaction& tx, const std::vector<uint256>& txids, const std::vector<CTxOut>& outs) {
	assert(outs.size() == tx.vin.size());
	std::cout << "DECOMPRESS" << std::endl;
	nVersion = tx.nVersion;
	nLockTime = tx.nLockTime;
	for (const auto& txout : tx.vout) {
		CScript script;
		if (txout.scriptType != TxoutType::NONSTANDARD) {
			std::vector<std::vector<unsigned char>> vSolutions;
			vSolutions.push_back(std::move(txout.scriptPubKey));
			CTxDestination destination;
			assert(BuildDestination(vSolutions, txout.scriptType, destination));
			script = GetScriptForDestination(destination);
		} else {
			script = CScript(txout.scriptPubKey.begin(), txout.scriptPubKey.end());
		}
		vout.push_back(CTxOut(txout.nValue, script));
	}
	for (size_t index = 0; index < tx.vin.size(); index++) {
		//empty scriptSig and scriptWitness
		vin.push_back(CTxIn(COutPoint(txids.at(index), tx.vin.at(index).prevout.n), CScript(), tx.vin.at(index).nSequence));
	}

	for (size_t index = 0; index < tx.vin.size(); index++) {
		std::cout << "vin" << std::endl;
		std::cout << "outs size = " << outs.size() << std::endl;
		if (tx.vin.at(index).compressed) {
			std::vector<secp256k1_ecdsa_recoverable_signature> recoverableSignatures;
			if (outs.at(index).scriptPubKey.IsPayToPublicKeyHash() || outs.at(index).scriptPubKey.IsPayToWitnessPublicKeyHash()) {
				for (int recoveryId = 0; recoveryId < 4; recoveryId++) {
            		secp256k1_ecdsa_recoverable_signature rsig;
					if (secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, &tx.vin.at(index).signature[0], recoveryId)) {
						recoverableSignatures.push_back(rsig);
					}
				}
		 	} else if (outs.at(index).scriptPubKey.IsPayToTaproot()) {
				std::vector<std::vector<unsigned char>> stack;
				stack.push_back(tx.vin.at(index).signature);
				if (tx.vin.at(index).hashType)
					stack[0].push_back(tx.vin.at(index).hashType);
				vin.at(index).scriptWitness.stack = stack;
			}
			bool lockTimeFound = false;
			while(!lockTimeFound) {
				if (outs.at(index).scriptPubKey.IsPayToPublicKeyHash() || outs.at(index).scriptPubKey.IsPayToWitnessPublicKeyHash()) {
					std::cout << "P2PKH || P2WPKH" << std::endl;
					uint256 hash;
					if (outs.at(index).scriptPubKey.IsPayToPublicKeyHash()) {
						hash = SignatureHash(outs.at(index).scriptPubKey, *this, index, tx.vin.at(index).hashType, outs.at(index).nValue, SigVersion::BASE);
					} else {
						std::vector<std::vector<unsigned char>> vSolutions;
						Solver(outs.at(index).scriptPubKey, vSolutions);
						CTxDestination destination;
						BuildDestination(vSolutions, TxoutType::WITNESS_V0_KEYHASH, destination);
						CScript scriptCode = GetScriptForDestination(destination);
						hash = SignatureHash(scriptCode, *this, index, tx.vin.at(index).hashType, outs.at(index).nValue, SigVersion::WITNESS_V0);
					}
					std::vector<unsigned char> message(32);
                    copy(hash.begin(), hash.end(), message.begin());

                    /* Dervive Sig Public Key Pairs */
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

							/* Generate Address */
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

								/* Generate Address */
								std::vector<unsigned char> ucpHashVec(20);
								copy(ucpHash.begin(), ucpHash.end(), ucpHashVec.begin());
								std::vector<std::vector<unsigned char>> ucpVSolutions;
								ucpVSolutions.push_back(std::move(ucpHashVec));
								CTxDestination ucpDestination;
								BuildDestination(ucpVSolutions, TxoutType::PUBKEYHASH, ucpDestination);
								CScript ucpScriptPubKey = GetScriptForDestination(ucpDestination);
								if (ucpScriptPubKey == outs.at(index).scriptPubKey) {
									pVec = std::move(ucpVec);
									pSize = ucpSize;
								} 
							}

							/* Test Scripts */
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
									signature[sdSize+1] = tx.vin.at(index).hashType;
									signature[sdSize+2] = pSize;
									copy(pVec.begin(), pVec.end(), signature.begin()+sdSize+3);
									CScript scriptSig = CScript(signature.begin(), signature.end());
									vin.at(index).scriptSig = scriptSig;
									break;
								} else {
									std::vector<unsigned char> signature (sdSize+1);
									copy(sigDER.begin(), sigDER.end(), signature.begin());
									signature[sdSize] = tx.vin.at(index).hashType;
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
					std::cout << "P2TR\n";
					std::vector<unsigned char> schnorr_signature = tx.vin.at(index).signature;

					/* Script Execution Data Init */
					ScriptExecutionData execdata;
					execdata.m_annex_init = true;
					execdata.m_annex_present = false;

					/* Prevout Init */
					PrecomputedTransactionData cache;
					cache.Init(CTransaction(*this), std::vector<CTxOut>{outs}, true);

					/* Compute Signature Hash */
					uint256 hash;
					int r = SignatureHashSchnorr(hash, execdata, *this, index, tx.vin.at(index).hashType, SigVersion::TAPROOT, cache, MissingDataBehavior::FAIL);

					if (!r) {
						std::cout << "FAILURE SCHNORR HASH\n";
					}
					std::cout << "message = "+hash.GetHex()+"\n";
					std::vector<unsigned char> pubkey_bytes;
					std::vector<std::vector<unsigned char>> vSolutions;
					assert(Solver(outs.at(index).scriptPubKey, vSolutions) == TxoutType::WITNESS_V1_TAPROOT);
					secp256k1_xonly_pubkey xonly_pubkey;
					r = secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey, &(vSolutions[0])[0]);
					if (!r) {
						std::cout << "FAILURE: ISSUE PUBKEY PARSE\n";
					}

					r = secp256k1_schnorrsig_verify(ctx, &tx.vin.at(index).signature[0], hash.begin(), 32, &xonly_pubkey);
					if (!r) {
						std::cout << "FAILURE: Issue verifiy\n";
					} else {
						lockTimeFound = true;
					}
				} else {
					std::cout << "no deserlie impl" << std::endl;
					assert(false);
				}
				if (!tx.shortendLockTime || lockTimeFound) {lockTimeFound = true;} else {nLockTime += pow(2, 16);}
			}
		} else if (tx.vin.at(index).sigSigned) {
			std::cout << "deserlize" << std::endl;
			std::vector<unsigned char> sig(tx.vin.at(index).signature.size());
			copy(tx.vin.at(index).signature.begin(), tx.vin.at(index).signature.end(), sig.begin());
			std::vector<std::byte> bvec = reinterpret_cast<std::vector<std::byte> &&> (sig);
			CDataStream stream(SER_DISK, 0);
			stream.write(bvec);
			uint64_t scriptSigLength = std::numeric_limits<uint64_t>::max();
			stream >> VARINT(scriptSigLength);
			if (scriptSigLength) {
				std::vector<std::byte> scriptSigBytes(scriptSigLength);
				stream.read(scriptSigBytes);
				std::vector<unsigned char> script = reinterpret_cast<std::vector<unsigned char> &&> (scriptSigBytes);
				vin.at(index).scriptSig = CScript(script.begin(), script.end());
			}
			//TODO: avoid reinterpret cast by adding new constructor for CScript(std::byte)
			uint64_t witnessCount = std::numeric_limits<uint64_t>::max();
			stream >> VARINT(witnessCount);
			std::vector<std::vector<unsigned char>> stack;
			for (uint64_t i = 0; witnessCount < i; i++) {
				uint64_t witnessLength = std::numeric_limits<uint64_t>::max();
				stream >> VARINT(witnessLength);
				std::vector<std::byte> witness(witnessLength);
				stream.read(witness);
				stack.push_back(reinterpret_cast<std::vector<unsigned char> &&> (witness));
			}
			vin.at(index).scriptWitness.stack = stack;
		}
	}
}

CCompressedTxId::CCompressedTxId() : block_height(0), block_index(0) {};
CCompressedTxId::CCompressedTxId(const uint32_t& block_height, const uint32_t& block_index) : block_height(block_height), block_index(block_index) {};

CCompressedOutPoint::CCompressedOutPoint(const uint32_t& n, const CCompressedTxId& txid) : txid(txid), n(n) {}

CCompressedTxIn::CCompressedTxIn(secp256k1_context* ctx, const CTxIn& txin, const CCompressedTxId& txid, const CScript& scriptPubKey) : prevout(txin.prevout.n, txid) {
	prevout = CCompressedOutPoint(txin.prevout.n, txid);
	sigSigned = false;
	compressed = false;
	if (txin.scriptSig.size() || txin.scriptWitness.stack.size()) {
		sigSigned = true;
		CScript scriptSig;
		if (scriptPubKey.IsPayToPublicKeyHash()) {
			scriptSig = txin.scriptSig;
		} else if (txin.scriptWitness.stack.size() && scriptPubKey.IsPayToWitnessPublicKeyHash()) {
			scriptSig = CScript(txin.scriptWitness.stack.at(0).begin(), txin.scriptWitness.stack.at(0).end());
		}
		if (scriptSig.size()) {
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
		} else if (txin.scriptWitness.stack.size() && scriptPubKey.IsPayToTaproot()) {
			if (txin.scriptWitness.stack.at(0).size() == 64) {
				hashType = 0;
			} else {
				signature = txin.scriptWitness.stack.at(0);
				hashType = signature[signature.size()-1];
				signature.pop_back();
			}
			compressed = true;
		}
		if (!compressed) {
			CDataStream stream(SER_DISK, 0);
			stream << VARINT(txin.scriptSig.size());
			if (txin.scriptSig.size())
				stream << txin.scriptSig;
			stream << VARINT(txin.scriptWitness.stack.size());
			for (size_t index = 0; index < txin.scriptWitness.stack.size(); index++) {
				stream << VARINT(txin.scriptWitness.stack.at(index).size());
				stream << txin.scriptWitness.stack.at(index);
			}
			std::vector<std::byte> sig_stream(stream.size());
			stream.read(sig_stream);
			signature = reinterpret_cast<std::vector<unsigned char> &&> (sig_stream);
		}
	}
	nSequence = txin.nSequence;
	standardSequence = txin.nSequence == 0x00000000 || txin.nSequence == 0xFFFFFFF0 || txin.nSequence == 0xFFFFFFFE || txin.nSequence == 0xFFFFFFFF;
}

CCompressedTxOut::CCompressedTxOut(const CTxOut& txout) {
	nValue = txout.nValue;
	std::vector<std::vector<unsigned char>> solutions;
	scriptType = Solver(txout.scriptPubKey, solutions);
	switch (scriptType) {
		case TxoutType::PUBKEY:
		case TxoutType::PUBKEYHASH:
		case TxoutType::SCRIPTHASH:
		case TxoutType::WITNESS_V0_KEYHASH:
		case TxoutType::WITNESS_V0_SCRIPTHASH:
		case TxoutType::WITNESS_V1_TAPROOT:
			compressed = true;
			scriptPubKey = solutions.at(0);
			break;
		default:
			compressed = false;
			copy(txout.scriptPubKey.begin(), txout.scriptPubKey.end(), scriptPubKey.begin());
	}
}

CCompressedTransaction::CCompressedTransaction(secp256k1_context* ctx, const CTransaction tx, const std::vector<CCompressedTxId>& txids, const std::vector<CScript>& scriptPubKeys) {
	nInputCount = tx.vin.size();
	nOutputCount = tx.vout.size(); 
	nVersion = tx.nVersion; 
	nLockTime = tx.nLockTime; 
	shortendLockTime = false;
	coinbase = tx.vin[0].prevout.n == 4294967295;

	for (auto const& txout : tx.vout) {
		vout.push_back(CCompressedTxOut(txout));
	}

	for (size_t index = 0; index < tx.vin.size(); index++) {
		vin.push_back(CCompressedTxIn(ctx, tx.vin.at(index), txids.at(index), scriptPubKeys.at(index))); 
	}

	uint32_t limit = pow(2, 16);
	if (tx.nLockTime > limit) {
		for (uint32_t i = 0; i < nInputCount; i++) {
			if (vin.at(i).compressed) {
				nLockTime = tx.nLockTime % limit;
				shortendLockTime = true;
			}
		}
	}
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
