// EllipticCurve.h: interface for the CEllipticCurve class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_ELLIPTICCURVE_H__0372B568_C633_4807_B268_B59E2CDE28B5__INCLUDED_)
#define AFX_ELLIPTICCURVE_H__0372B568_C633_4807_B268_B59E2CDE28B5__INCLUDED_

#include "Mpi.h"
#include "sm3hash.h"

#define KDF				Sm3KDF
#define HASH_256		SM3_HASH_256
#define HASH_192		SM3_HASH_192
#define HASH_STATE		SM3_HASH_STATE
#define HashInit		Sm3HashInit
#define HashPending		Sm3HashPending
#define HashFinal		Sm3HashFinal

#ifndef DCS_ECC_CURVE_ID_1
	#define DCS_ECC_CURVE_ID_1				1
#endif

#ifndef DCS_ECC_CURVE_ID_2
	#define DCS_ECC_CURVE_ID_2				2
#endif

#ifndef DCS_ECC_CURVE_ID_3
	#define DCS_ECC_CURVE_ID_3				3
#endif

#define MAX_CPU_TSX 16

typedef struct structCECCPublicKey
{
	CMpi m_pntPx;
	CMpi m_pntPy;
}CECCPublicKey;

typedef struct structCECCPrivateKey
{
	CMpi m_pntPx;
	CMpi m_pntPy;
	CMpi m_paramD;
	// need 96 bits;
	unsigned char empty_pad[12] __attribute__((aligned(64)));
}CECCPrivateKey;

// ------------------------------------------------------------

/*extern CModulus g_paramFieldP;	
extern CMpi g_paramA;
extern CMpi g_paramB;
extern CMpi g_PntGx;
extern CMpi g_PntGy;
extern CModulus g_paramN;*/
// ------------------------------------------------------------

//void Jacobian2Stand(CMpi &x, CMpi &y, CMpi &z);
void CEllipticCurveJacobian2Stand(CMpi *x, CMpi *y, CMpi *z);
//static bool CheckPoint(const CMpi &x, const CMpi &y);
int CEllipticCurveCheckPoint(CMpi *x, CMpi *y); //1 ok, 0 fail
//static void InitParam();
void CEllipticCurveInitParam(void);
//void MultiplyPubByTable(CMpi &x, CMpi &y, const CMpi &m, const CMpi &PubX, const CMpi &PubY); (x, y) = m*(X, Y)
void CEllipticCurveMultiplyPubByTable5(CMpi *x, CMpi *y, CMpi *m, CMpi *PubX, CMpi *PubY);
//void MultiplyPubByTable(CMpi &x, CMpi &y, CMpi &z, const CMpi &m, const CMpi &PubX, const CMpi &PubY); 
void CEllipticCurveMultiplyPubByTable6(CMpi *x, CMpi *y, CMpi *z, CMpi *m, CMpi *PubX, CMpi *PubY);
//void DoubleMplJacobian(CMpi &x2, CMpi &y2, CMpi &z2, const CMpi &x, const CMpi &y, const CMpi &z);		// (x, y, z) = (x, y, z) + (x, y, z)
void CEllipticCurveDoubleMplJacobian6(CMpi *x2, CMpi *y2, CMpi *z2, CMpi *x, CMpi *y, CMpi *z);		
// (x, y, z) = (x, y, z) + (mx, my, mz)
//void AddMplJacobian(CMpi &x, CMpi &y, CMpi &z, const CMpi &mx, const CMpi &my, const CMpi &mz);
void CEllipticCurveAddMplJacobian6(CMpi *x, CMpi *y, CMpi *z, CMpi *mx, CMpi *my, CMpi *mz);
void CEllipticCurveAddMplJacobian6New(CMpi *x, CMpi *y, CMpi *z, CMpi *mx, CMpi *my, CMpi *mz);
//void DoubleMplJacobian(CMpi &x, CMpi &y, CMpi &z);		// (x, y, z) = (x, y, z) + (x, y, z)
void CEllipticCurveDoubleMplJacobian3(CMpi *x, CMpi *y, CMpi *z);		// (x, y, z) = (x, y, z) + (x, y, z)
// (x, y) = m*(X, Y)
// (x, y) = m*(Gx, Gy)
//void MultiplyGByTable(CMpi &x, CMpi &y, const CMpi &m);	
void CEllipticCurveMultiplyGByTable3(CMpi *x, CMpi *y, CMpi *m);
//void MultiplyGByTable(CMpi &x, CMpi &y, CMpi &z, const CMpi &m);
void CEllipticCurveMultiplyGByTable4(CMpi *x, CMpi *y, CMpi *z, CMpi *m);

//int HashUserId(unsigned char *pbOut, const unsigned char *pUserName, int iLenOfName);
int PubHashUserId(CECCPublicKey *t, unsigned char *pbOut, unsigned char *pUserName, int iLenOfName);
int PriHashUserId(CECCPrivateKey *t, unsigned char *pbOut, unsigned char *pUserName, int iLenOfName);
//int Verify(const unsigned char *pDigest, int iLenOfDigest, const unsigned char *pSig, int iLenOfSig);
int Verify(CECCPublicKey *pk,unsigned char *pDigest, int iLenOfDigest, unsigned char *pSig, int iLenOfSig);
//int Encrypt(unsigned char *pbCipher1, unsigned char *pbX2, unsigned char *pbY2, const unsigned char *pRnd, int iLenOfRnd);
// pbCipher1 = k*G
// pbCipher2(x2, y2) = [k*inv(h)]*[h]*P
int Encrypt(CECCPublicKey *pk, unsigned char *pbCipher1, unsigned char *pbX2, unsigned char *pbY2,  unsigned char *pRnd, int iLenOfRnd);
//int EncryptMessage(unsigned char *pbOut, const unsigned char *pbIn, int iLenOfIn, const unsigned char *pRnd, int iLenOfRnd);
int EncryptMessage(CECCPublicKey *pk, unsigned char *pbOut,  unsigned char *pbIn, int iLenOfIn,  unsigned char *pRnd, int iLenOfRnd);
//int VerifyMessage(const unsigned char *pMsg, int iLenOfMsg, const unsigned char *pSig, int iLenOfSig, const unsigned char *pUserName, int iLenOfUserName);
int VerifyMessage(CECCPublicKey *pk, unsigned char *pMsg, int iLenOfMsg, unsigned char *pSig, int iLenOfSig, unsigned char *pUserName, int iLenOfUserName);
//int SetKey(const CMpi &paramPx, const CMpi &paramPy);
int SetPublicKey(CECCPublicKey *pk, CMpi *paramPx,  CMpi *paramPy);

//int GenerateKey(const unsigned char *pRandomUser,int iLenOfRandom);
int GenerateKey(CECCPrivateKey *sk,  unsigned char *pRandomUser,int iLenOfRandom);
//int SetKey(const CMpi &paramD, bool fComputePubKey = true);
int SetPrivateKey(CECCPrivateKey *sk, CMpi *paramD, int fComputePubKey);
//int SetKey(const CMpi &paramD, const CMpi &paramPx, const CMpi &paramPy);
int SetPrivateKeyDirect(CECCPrivateKey *sk, CMpi *paramD,  CMpi *paramPx, CMpi *paramPy);
//int Sign(unsigned char *pOut, const unsigned char *pIn, int iLen, const unsigned char *pRnd, int iLenOfRnd);
int Sign(CECCPrivateKey *sk,unsigned char *pOut, unsigned char *pIn, int iLen, unsigned char *pRnd, int iLenOfRnd);
//int Decrypt(const unsigned char *pbCipher1, int iLenOfCipher1, unsigned char *pbX2, unsigned char *pbY2);
int Decrypt(CECCPrivateKey *sk, unsigned char *pbCipher1, int iLenOfCipher1, unsigned char *pbX2, unsigned char *pbY2);
//	int SignMessage(unsigned char *pOut, const unsigned char *pMsg, int iLenOfMsg, const unsigned char *pUserName, int iLenOfUserName, const unsigned char *pRnd, int iLenOfRnd);
int SignMessage(CECCPrivateKey *sk, unsigned char *pOut, unsigned char *pMsg, int iLenOfMsg, unsigned char *pUserName, int iLenOfUserName, unsigned char *pRnd, int iLenOfRnd);
//int DecryptMessage(unsigned char *pbOut, const unsigned char *pbIn, int iLenOfIn);
int DecryptMessage(CECCPrivateKey *sk, unsigned char *pbOut,  unsigned char *pbIn, int iLenOfIn);

int GenerateKeySafe(CECCPrivateKey *sk,  unsigned char *pRandomUser,int iLenOfRandom);
int SignMessageSafe(CECCPrivateKey *sk, unsigned char *pOut, unsigned char *pMsg, int iLenOfMsg, unsigned char *pUserName, int iLenOfUserName, unsigned char *pRnd, int iLenOfRnd);
int DecryptMessageSafe(CECCPrivateKey *sk, unsigned char *pbOut,  unsigned char *pbIn, int iLenOfIn);
int CEllipticCurveMultiplyPubByTable6Safe(CMpi *x, CMpi *y, CMpi *z, CMpi *m, CMpi *PubX, CMpi *PubY);
int CEllipticCurveMultiplyGByTable3Safe(CMpi *x, CMpi *y, CMpi *m);
#endif // !defined(AFX_ELLIPTICCURVE_H__0372B568_C633_4807_B268_B59E2CDE28B5__INCLUDED_)
