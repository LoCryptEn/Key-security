// Mpi.h: interface for the CMpi class.
//
//		MPI_LENGTH
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_MPI_H__B3328615_E05B_11D4_961E_0050FC0F4715__INCLUDED_)
#define AFX_MPI_H__B3328615_E05B_11D4_961E_0050FC0F4715__INCLUDED_


#define DCS_ECC_KEY_LENGTH	 (256/8)
#define MPI_LENGTH 8		// 256/8/4 = 8
#define POSITIVE 1
#define NEGTIVE (-1)
#define HEX28BITS 0xFFFFFFF   // Short 4 bits then  int
#define HEX32BITS 0xFFFFFFFF  // This is in the int length
#define MPI_INFINITE 0xFFFFFFF
#define UNSIGNEDLEFTBIT 0x80000000
#define BITS_OF_INT 32

#define DOUBLE_INT unsigned long long
#define __mpimax(x,y) (x>y?x:y)
#define __mpimin(x,y) (x<y?x:y)

#if !defined(BYTE)
typedef unsigned char BYTE;
#endif

#ifndef NULL
  #define NULL	0L
#endif // NULL


/* Multi precision integer */
typedef struct structCMpi
{
	unsigned int m_aiMyInt[MPI_LENGTH];
	unsigned int m_iCarry;
	int m_iMySign;
	int m_iLengthInInts;
	int m_pad;//for enc and dec
}CMpi;


/* Long Multi precision integer */
typedef struct structCMpl
{
	CMpi h;
	CMpi l;
}CMpl;

typedef struct structCModulus
{
	CMpi m_oModulus;
}CModulus;
/**************begin for CMpi Class***********************/
int CMpiIsNegative(CMpi * t);
int CMpiGetLengthInBits(CMpi * t);
int CMpiExport(CMpi * t, BYTE *abOutBytes, int iMinLength);	
int CMpiInport(CMpi * t, BYTE *abContent, int iLength);
int CMpiGetLengthInBytes(CMpi * t);
//void TestAdd(CMpi *result, const CMpi *m);
//void TestMul(CMpl *result, const CMpi *m);
void CMpiBitShiftLeft(CMpi * t, int iShiftBits);
void CMpiBitShiftRight(CMpi * t, int iShiftBits);
void CMpiRegularize(CMpi * t);
void CMpiChangeSign(CMpi * t);
void CMpiFastSquare(CMpl *res, CMpi *t);
//CMpi & operator =(const CMpl &l) ;
void CMpiAssignCMpl(CMpi *res, CMpl *l);
void CMpiAssignCMpi(CMpi *res, CMpi *l);
//CMpl operator *(const CMpi &m) const;
void CMpiMultiByCMpi(CMpl *res, CMpi *t,  CMpi *m); //res = t*m
//CMpi & operator *=(const unsigned int n);
void CMpiMultiByN(CMpi *t,  unsigned int n); // t= t*n
//int operator !=(const unsigned int n) const;
//int operator ==(const unsigned int n) const;
int CMpiEqualN(CMpi *t,  unsigned int n);  // == return 1,else return 0
//int operator !=(const CMpi &m) const;
//int operator ==(const CMpi &m) const;
int CMpiEqualCMpi(CMpi *t,  CMpi *m);  // == return 1,else return 0
//CMpi & operator <<=(const int n);   //BitShiftLeftAssign
void CMpiBitShiftLeftAssign(CMpi *t,  int n); 
//CMpi & operator >>=(const int n); 	// BitShiftRightAssign
void CMpiBitShiftRightAssign(CMpi *t,  int n); 
//int operator >> (const CMpi &m) const; // Compare by ABS
int CMpiABSBigger(CMpi *t,  CMpi *m);
//int operator << (const CMpi &m) const; // Compare by ABS
int CMpiABSNotBigger(CMpi *t,  CMpi *m);
//int operator > (const CMpi &m) const;
int CMpiBigger(CMpi *t,  CMpi *m);
//int operator < (const CMpi &m) const;
int CMpiNotBigger(CMpi *t,  CMpi *m);
//CMpi & operator -=(const CMpi &m);
void CMpiSubAssign(CMpi *t, CMpi *m); // t = t - m;
//CMpi & operator +=(const CMpi &m);
void CMpiAddAssign(CMpi *t, CMpi *m); // t = t + m;
//CMpi operator -(const CMpi &m) const; 
void CMpiSub(CMpi *res, CMpi *t, CMpi *m); // res = t - m
//CMpi operator -() const; 
void CMpiMinus(CMpi *res,CMpi *t);
//CMpi operator + (const CMpi &m) const;
void CMpiAdd(CMpi *res, CMpi *t, CMpi *m); //res = t+ m
void CMpiInitN(CMpi *t,unsigned int iInitial);
void CMpiInit(CMpi *t);
/**************end for CMpi Class***********************/

/**************begin for CMpl Class***********************/
void CMplInit(CMpl *t);
void CMplInitN(CMpl *t,unsigned int iInitial);
//CMpl(const CMpi &m);
void CMplAssignCMpi(CMpl *t,  CMpi *m);
void CMplAssignCMpl(CMpl *t,  CMpl *m);
//CMpl & operator <<=(const int n); // shift left, become bigger by multi 2^^32
void CMplBitShiftLeftAssign(CMpl *t,  int n); 
//CMpl & operator >>=(const int n); // shift right, become small
void CMplBitShiftRightAssign(CMpl *t,  int n); 
//CMpl & operator +=(const CMpl &oMpl);
void CMplAddAssign(CMpl *t, CMpl *m); // t = t + m;
//CMpl & operator -=(const CMpl &oMpl);
void CMplSubAssign(CMpl *t, CMpl *oMpl);
//int operator ==(const CMpl &oMpl) const;
int CMplEqual(CMpl *t,  CMpl *oMpl);
//CMpl & BitShiftLeft(const int iShiftBits);
void CMplBitShiftLeft(CMpl *t,  int iShiftBits);
//CMpl & BitShiftRight(const int iShiftBits);
void CMplBitShiftRight(CMpl *t,  int iShiftBits);	
//void Reduction(const CMpi &m);	// this = this%m
void CMplReduction(CMpl *t, CMpi *m);	// this = this%m
//void ReductionByTable(const CMpi &m);	// this = this%m
//void CMplReductionByTable(CMpl *t,  CMpi *m);	// this = this%m
void CMplFastReduction(CMpl *t,  CMpi *m); // replace CMplReductionByTable
//CMpi & operator %=(const CMpi &m);
void CMplModAssign(CMpi*res, CMpl *t, CMpi *m);
/**************end for CMpl Class***********************/


/**************begin for CModulus Class***********************/
//int GetLengthInBytes();
int CModulusGetLengthInBytes(CModulus *t);
//CModulus(const CMpi &oMpi);
void CModulusInitCMpi(CModulus *t,  CMpi *oMpi);
//CModulus();
//void Init();
void CModulusInit(CModulus *t);
//CMpi BinaryInverse(const CMpi &oMpi) ; // return oMpi**(-1)
void CModulusBinaryInverse(CMpi *res, CModulus *t,  CMpi *oMpi);
/**************end for CModulus Class***********************/

#endif // !defined(AFX_MPI_H__B3328615_E05B_11D4_961E_0050FC0F4715__INCLUDED_)

