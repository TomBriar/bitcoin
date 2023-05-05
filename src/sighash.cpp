#include <sighash.h>
#include <script/interpreter.h>


//template <class T>
uint256 SignatureHashInt(const CScript& scriptCode, const CMutableTransaction& txTo, unsigned int nIn, int nHashType, const CAmount& amount, int sigint)
{
	SigVersion sigversion;
	if (sigint == 0) {
		sigversion = SigVersion::BASE;
	} else {
		sigversion = SigVersion::BASE;
	}
	
	return SignatureHash(scriptCode, txTo, nIn, nHashType, amount, sigversion);
}


