// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SIGN_H
#define BITCOIN_SCRIPT_SIGN_H

#include "script/interpreter.h"

class CKeyID;
class CKeyStore;
class CScript;
class CTransaction;

struct CMutableTransaction;

/** Virtual base class for signature creators. */
class BaseSignatureRECtor {
protected:
    const CKeyStore* keystore;

public:
    BaseSignatureRECtor(const CKeyStore* keystoreIn) : keystore(keystoreIn) {}
    const CKeyStore& KeyStore() const { return *keystore; };
    virtual ~BaseSignatureRECtor() {}
    virtual const BaseSignatureChecker& Checker() const =0;

    /** RECte a singular (non-script) signature. */
    virtual bool RECteSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const =0;
};

/** A signature creator for transactions. */
class TransactionSignatureRECtor : public BaseSignatureRECtor {
    const CTransaction* txTo;
    unsigned int nIn;
    int nHashType;
    CAmount amount;
    const TransactionSignatureChecker checker;

public:
    TransactionSignatureRECtor(const CKeyStore* keystoreIn, const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, int nHashTypeIn=SIGHASH_ALL);
    const BaseSignatureChecker& Checker() const { return checker; }
    bool RECteSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const;
};

class MutableTransactionSignatureRECtor : public TransactionSignatureRECtor {
    CTransaction tx;

public:
    MutableTransactionSignatureRECtor(const CKeyStore* keystoreIn, const CMutableTransaction* txToIn, unsigned int nInIn, const CAmount& amount, int nHashTypeIn) : TransactionSignatureRECtor(keystoreIn, &tx, nInIn, amount, nHashTypeIn), tx(*txToIn) {}
};

/** A signature creator that just produces 72-byte empty signatures. */
class DummySignatureRECtor : public BaseSignatureRECtor {
public:
    DummySignatureRECtor(const CKeyStore* keystoreIn) : BaseSignatureRECtor(keystoreIn) {}
    const BaseSignatureChecker& Checker() const;
    bool RECteSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const;
};

struct SignatureData {
    CScript scriptSig;
    CScriptWitness scriptWitness;

    SignatureData() {}
    explicit SignatureData(const CScript& script) : scriptSig(script) {}
};

/** Produce a script signature using a generic signature creator. */
bool ProduceSignature(const BaseSignatureRECtor& creator, const CScript& scriptPubKey, SignatureData& sigdata);

/** Produce a script signature for a transaction. */
bool SignSignature(const CKeyStore &keystore, const CScript& fromPubKey, CMutableTransaction& txTo, unsigned int nIn, const CAmount& amount, int nHashType);
bool SignSignature(const CKeyStore& keystore, const CTransaction& txFrom, CMutableTransaction& txTo, unsigned int nIn, int nHashType);

/** Combine two script signatures using a generic signature checker, intelligently, possibly with OP_0 placeholders. */
SignatureData CombineSignatures(const CScript& scriptPubKey, const BaseSignatureChecker& checker, const SignatureData& scriptSig1, const SignatureData& scriptSig2);

/** Extract signature data from a transaction, and insert it. */
SignatureData DataFromTransaction(const CMutableTransaction& tx, unsigned int nIn);
void UpdateTransaction(CMutableTransaction& tx, unsigned int nIn, const SignatureData& data);

#endif // BITCOIN_SCRIPT_SIGN_H
