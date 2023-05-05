#ifndef BITCOIN_SIGHASH_H
#define BITCOIN_SIGHASH_H

#include <script/script.h>
#include <uint256.h>
#include <uint256.h>
#include <consensus/amount.h>
//struct CMutableTransaction;

template <class T>
uint256 SignatureHashInt(const CScript& scriptCode, const T& txTo, unsigned int nIn, int nHashType, const CAmount& amount, int sigint);

#endif // BITCOIN_SIGHASH_H
