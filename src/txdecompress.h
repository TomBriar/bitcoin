#ifndef BITCOIN_TXDECOMPRESS_H
#define BITCOIN_TXDECOMPRESS_H

#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <coins.h>

CMutableTransaction decompress_transaction(const secp256k1_context* ctx, const CCompressedTransaction& tx, const std::vector<uint256>& txids, const std::vector<CTxOut>& outs) {
	CMutableTransaction mtx;
	mtx.nVersion = tx.nVersion;
	mtx.nLockTime = tx.nLockTime;
	for (const auto& txout : tx.vout) {
		mtx.vout.push_back(CTxOut(txout.nValue, CScript(txout.scriptPubKey, txout.scriptType)));
	}
	for (size_t index = 0; index < tx.vin.size(); index++) {
		//empty scriptSig and scriptWitness
		mtx.vin.push_back(CTxIn(COutPoint(txids.at(index), tx.vin.at(index).prevout.n), CScript(), tx.vin.at(index).nSequence));
	}

	for (size_t index = 0; index < tx.vin.size(); index++) {
		if (tx.vin.at(index).compressed) {
			std::vector<secp256k1_ecdsa_recoverable_signature> recoverableSignatures;
			if (outs.at(index).scriptPubKey.IsPayToPublicKeyHash() || outs.at(index).scriptPubKey.IsPayToWitnessPublicKeyHash()) {
				for (int recoveryId = 0; recoveryId < 5; recoveryId++) {
            		secp256k1_ecdsa_recoverable_signature rsig;
					if (secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, &tx.vin.at(index).signature[0], recoveryId)) {
						recoverableSignatures.push_back(rsig);
					}
				}
		 	}
			bool lockTimeFound = false;
			while(!lockTimeFound) {
				if (outs.at(index).scriptPubKey.IsPayToPublicKeyHash()) {
					uint256 hash = SignatureHash(outs.at(index).scriptPubKey, mtx, index, tx.vin.at(index).hashType, outs.at(index).nValue, SigVersion::BASE);
					std::vector<unsigned char> message(32);
                    copy(hash.begin(), hash.end(), message.begin());

                    /* Dervive Sig Public Key Pairs */
                    for (auto const& rsig : recoverableSignatures) {
                        secp256k1_pubkey pubkey;
						secp256k1_ecdsa_signature sig;
                        if (secp256k1_ecdsa_recover(ctx, &pubkey, &rsig, &message[0])) {
							/* Serilize Compressed Pubkey */
							size_t compressedPubkeySize = 33;
							std::vector<unsigned char> compressedPubkeyBytes (pubkeySize);
							secp256k1_ec_pubkey_serialize(ctx, &compressedPubkeyBytes[0], &compressedPubkeySize, &pubkey, SECP256K1_EC_COMPRESSED);

							/* Hash Compressed Pubkey */
							uint160 compressedPubkeyHash;
							CHash160().Write(compressedPubkeyBytes).Finalize(compressedPubkeyHash);
							std::vector<unsigned char> pubkeyHashBytes(20);
							copy(pubkeyHash.begin(), pubkeyHash.end(), pubkeyHashBytes.begin());

							/* Test Scripts */
							if (CScript(pubkeyHashBytes, scripttype::P2PKH) == outs.at(index).scriptPubKey) {
								secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &rsig);
								// success
								lockTimeFound = true;
								std::vector<unsigned char> sig_der (71);
								size_t sig_der_size = 71;
								secp256k1_ecdsa_signature_serialize_der(ctx, &sig_der[0], &sig_der_size, &sig);
								sig_der_size += 1;
								std::vector<unsigned char> signature (sig_der_size+1+1+pubkeyBytes.size());
								signature[0] = sig_der_size;
								copy(sig_der.begin(), sig_der.end(), signature.begin()+1);
								signature[sig_der_size] = tx.vin.at(index).hashType;
								signature[sig_der_size+1] = pubkeyBytes.size();
								copy(pubkeyBytes.begin(), pubkeyBytes.end(), pubkeyBytes.begin()+sig_der_size+2);
								CScript scriptSig = CScript(signature.begin(), signature.end());
								mtx.vin.at(index).scriptSig = scriptSig;
								break;
							}
						};
                    }
				}
				if (!tx.shortendLockTime || lockTimeFound) {lockTimeFound = true;} else {mtx.nLockTime += pow(2, 16)}
			}
		} else {
			std::cout << "no deserlize impl" << std::endl;
			assert(false);
			//TODO: deserlize tx.vin.at(index).signature
		}
	}
	return mtx; 
}

#endif // BITCOIN_TXDECOMPRESS_H
