// Mpi.cpp: implementation of the CMpi class.
//
//////////////////////////////////////////////////////////////////////

#include "Mpi.h"

int CMpiIsNegative(CMpi * t)
{
	if (t->m_iMySign==POSITIVE)
		return 0;
	else
		return 1;
}

int CMpiGetLengthInBits(CMpi * t)
{
	// Write By Jing
	int i;
	unsigned int k;
	int iLength;
	for (i=t->m_iLengthInInts-1;i>=0;i--)
	{
		if (t->m_aiMyInt[i]!=0)
			break;
	}
	iLength = (i+1)*8*sizeof(unsigned int);
	k = t->m_aiMyInt[i];
	for (i=0;i<8*sizeof(unsigned int);i++)
	{
		if ( UNSIGNEDLEFTBIT & (k<<i))
			break;
	}
	return iLength - i;
}


int CMpiExport(CMpi * t,BYTE *abOutBytes, int iMinLength)
{
	// Write by Jing
	// Most significant byte first. 
	int j,k,iOut;
	int iLengthOfExport;
	unsigned int u;
	iLengthOfExport = 0;
	j = t->m_iLengthInInts-1;
	if (j<0)
		return 0;

	u =  t->m_aiMyInt[j];
	while (u==0)
	{
		j--;
//		if (j<=0)
		if (j < 0)		// modified by Linjq
			return 0;
		u =  t->m_aiMyInt[j];
	}

	//u!=0 now
	k = sizeof(unsigned int)-1;
	while (0==(u>>(k*8)))
		k--;

	// -------------------------------------------------------------------------------- //
	// Added by Linjq
	iOut = j*sizeof(unsigned int) + k + 1;
	while (iOut < iMinLength)
	{
		abOutBytes[iLengthOfExport++] = 0x00;
		iMinLength--;
	}
	// -------------------------------------------------------------------------------- //

	while (k>=0)
	{
		abOutBytes[iLengthOfExport] = (BYTE )(u>>(k*8));
		iLengthOfExport++;
		k--;
	}

	// Process other unsigned int
	j--;
	u =  t->m_aiMyInt[j];
	while (j>=0)
	{
		u = t->m_aiMyInt[j];
		for (k=sizeof(unsigned int)-1;k>=0;k--)
		{
//			if (k==(-1))
//				break; //
			abOutBytes[iLengthOfExport] = (BYTE )(u>>(k*8));
			iLengthOfExport++;
		}
		j--;
	}
	// return the length of abOutBytes. if none or error return 0
	return iLengthOfExport;
}

int CMpiInport(CMpi * t, BYTE *abContent, int iLength)
{
	// Write By Jing
	int i,j;
	t->m_iCarry = 0;
	t->m_iLengthInInts = 0; 
	t->m_iMySign = POSITIVE;

	if (iLength>MPI_LENGTH*sizeof(unsigned int))
	{
		return 0;
	}
	// process through the bytes, Most significant byte last
	j = 0;
	t->m_aiMyInt[t->m_iLengthInInts] = 0;
	for (i = iLength-1; i>=0 ; i--)
	{
		t->m_aiMyInt[t->m_iLengthInInts] += abContent[i]<<(8*j);
		j++;
		if (j>=sizeof(unsigned int))
		{
			j=0;
			t->m_iLengthInInts++;
			//if(m_iLengthInInts > MPI_LENGTH)
			if (t->m_iLengthInInts!=MPI_LENGTH) // This Line added for Bug 376
			{
				t->m_aiMyInt[t->m_iLengthInInts] = 0;
			}
		}
	}
	if (j!=0)  // This line added Bug No 376
		t->m_iLengthInInts++;
	return t->m_iLengthInInts;
}

int CMpiGetLengthInBytes(CMpi * t)
{
	// Write By Jing
	int i;
	unsigned int j,k;
	CMpiRegularize(t);
	if (t->m_iLengthInInts==0)  // For Bug 442, start
		return 0; // For Bug 442, end
	j = t->m_aiMyInt[t->m_iLengthInInts-1];
	k = 0xff;
	for (i=sizeof(unsigned int)-1;i>=0;i--)
	{
		if (j&(k<<(i*8)))
			break;
	}
	return i+1+(t->m_iLengthInInts-1)*sizeof(unsigned int);
}

void CMpiBitShiftLeft(CMpi * t, const int iShiftBits)
{
	int i,j,k;
	j = iShiftBits/BITS_OF_INT;
	if (j!=0)
	{
		CMpiBitShiftLeftAssign(t,j);
	}

	j = iShiftBits%BITS_OF_INT;

	if (j==0)
		return;

	k = t->m_iLengthInInts;
	if (k<MPI_LENGTH)
	{
		t->m_aiMyInt[k] = t->m_aiMyInt[k-1]>>(BITS_OF_INT-j);
		if (t->m_aiMyInt[k]!=0)
			t->m_iLengthInInts++;
	}
	else
		t->m_iCarry = t->m_aiMyInt[MPI_LENGTH-1]>>(BITS_OF_INT-j);

	for (i=k-1;i>0;i--) // Changed to k-1 for Bug No. 374
	{
		t->m_aiMyInt[i]<<=j;
		t->m_aiMyInt[i] += t->m_aiMyInt[i-1]>>(BITS_OF_INT-j);
	}

	t->m_aiMyInt[0]<<=j;

	return;
}

void CMpiBitShiftRight(CMpi * t,const int iShiftBits)
{
	int i,j;
	j = iShiftBits/BITS_OF_INT;
	if (j!=0)
	{
		CMpiBitShiftRightAssign(t,j);
	}

	j = iShiftBits%BITS_OF_INT;

	if (j==0)
		return ;

	for (i=0; i<t->m_iLengthInInts-1;i++)
	{
		t->m_aiMyInt[i] >>= j;
		t->m_aiMyInt[i] += (t->m_aiMyInt[i+1]<<(BITS_OF_INT-j));
	}

	t->m_aiMyInt[t->m_iLengthInInts-1] >>= j;

	if (t->m_aiMyInt[t->m_iLengthInInts-1]==0)
		t->m_iLengthInInts--;

	return;
}

void CMpiRegularize(CMpi * t)
{
	int i;
	for (i=t->m_iLengthInInts-1;i>=0;i--)
	{
		if (t->m_aiMyInt[i]!=0)
			break;
	}
	t->m_iLengthInInts = i+1;
	return;
}

void CMpiChangeSign(CMpi * t)
{
	t->m_iMySign *= -1;
}

void CMpiFastSquare(CMpl *temp, CMpi *t)
{
	unsigned int c[MPI_LENGTH*2] = {
		0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0
	};
	int k;
	int i, j;
	DOUBLE_INT uv, sum;
	unsigned int R0 = 0, R1 = 0, R2 = 0;
	int imax;
	int len = t->m_iLengthInInts*2;

	for (k=0; k<len; k++)
		c[k]=0;

	
	for (k = 0; k <= len-2; k++)
	{
		imax = __mpimin(k, t->m_iLengthInInts-1);
		imax = __mpimin(k/2, imax);
		for (i = imax, j = k-i; i >= 0; i--, j++)
		{
			if (j >= t->m_iLengthInInts)
				break;

			uv = t->m_aiMyInt[i];
			uv *= t->m_aiMyInt[j];
			if (i < j)
			{
				if (0x8000000000000000ull & uv)
					R2++;
				uv <<= 1;
			}
			sum = R0;
			sum += (unsigned int)uv;
			R0 = (unsigned int)sum;
			sum >>= BITS_OF_INT;

			sum += R1;
			sum += (uv >> BITS_OF_INT);
			R1 = (unsigned int)sum;
			sum >>= BITS_OF_INT;

			R2 += (unsigned int)sum;
		}
		c[k] = R0;
		R0 = R1;
		R1 = R2;
		R2 = 0;
	}

	c[len-1] = R0;

	if (len>MPI_LENGTH)
	{
		temp->l.m_iLengthInInts = MPI_LENGTH;
		temp->h.m_iLengthInInts = len - MPI_LENGTH;
	}
	else
	{
		temp->l.m_iLengthInInts = len;
		temp->h.m_iLengthInInts = 0;
	}
	for (i=0;i<temp->l.m_iLengthInInts;i++)
		temp->l.m_aiMyInt[i]=c[i];
	for (i=0;i<temp->h.m_iLengthInInts;i++)
		temp->h.m_aiMyInt[i]=c[i+MPI_LENGTH];

	return;
}

void CMpiAssignCMpi(CMpi *res, CMpi *l)
{
	int i=0;
	res->m_iCarry = l->m_iCarry;
	res->m_iMySign = l->m_iMySign;
	res->m_iLengthInInts = l->m_iLengthInInts;
	for(i=0;i<l->m_iLengthInInts;i++)
		res->m_aiMyInt[i] = l->m_aiMyInt[i];
	return;
}

void CMpiAssignCMpl(CMpi *res, CMpl *l)
{
	int i=0;
	res->m_iCarry = 0;
	res->m_iMySign = l->l.m_iMySign;
	res->m_iLengthInInts = l->l.m_iLengthInInts;
	for(i=0;i<l->l.m_iLengthInInts;i++)
		res->m_aiMyInt[i] = l->l.m_aiMyInt[i];
	return;
}

void CMpiMultiByCMpi(CMpl *temp, CMpi *t,  CMpi *m)
{
	DOUBLE_INT direg = 0,sum;
	int i,j,k,len, n;
	unsigned int r[MPI_LENGTH*2] = {
		0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0
	};

	int rlen = 0;
	len = t->m_iLengthInInts + m->m_iLengthInInts;

	for (i=0;i<MPI_LENGTH*2;i++)
		r[i]=0;

	for (k=0;k<len;k++) // k results
	{
		// Calculate the kth int
		for (i=0, n=k-i;i<=k;i++, n--)
		{
			if ((t->m_iLengthInInts>i) && m->m_iLengthInInts>n)
			{
				// multi
				direg = t->m_aiMyInt[i];
				direg *= m->m_aiMyInt[n];

				sum = direg+r[k];
				r[k] = (unsigned int)sum;
				sum >>= BITS_OF_INT;

				sum += r[k+1];
				r[k+1] = (unsigned int)sum;
				sum >>= BITS_OF_INT;

				j = k+2;
				while (sum!=0)
				{
					sum += r[j];
					r[j++] = (unsigned int)sum;
					sum >>= BITS_OF_INT;
				}
			}
			
		}
	}

	for (i=MPI_LENGTH*2-1;i>=0;i--)
	{
		if (r[i]!=0)
			break;
	}
	rlen = i+1;

	if (rlen>MPI_LENGTH)
	{
		temp->l.m_iLengthInInts = MPI_LENGTH;
		temp->h.m_iLengthInInts = rlen - MPI_LENGTH;
	}
	else
	{
		temp->l.m_iLengthInInts = rlen;
		temp->h.m_iLengthInInts = 0;
	}
	for (i=0;i<temp->l.m_iLengthInInts;i++)
		temp->l.m_aiMyInt[i]=r[i];
	for (i=0;i<temp->h.m_iLengthInInts;i++)
		temp->h.m_aiMyInt[i]=r[i+MPI_LENGTH];

	if (t->m_iMySign == m->m_iMySign)
		temp->h.m_iMySign = temp->l.m_iMySign = POSITIVE;
	else
		temp->h.m_iMySign = temp->l.m_iMySign = NEGTIVE;

	return;
}



void CMpiMultiByN(CMpi *t,  unsigned int n)
{
	register DOUBLE_INT direg;
	unsigned int icarry = 0;
	int i;
	t->m_iCarry = 0;
	if (n==0)
	{
		t->m_iMySign = POSITIVE;
		t->m_iLengthInInts=0;
		t->m_aiMyInt[0]= 0;
		return ;
	}

	for (i=0;i<t->m_iLengthInInts;i++)
	{
		direg = t->m_aiMyInt[i];
		direg *= n;
		direg += icarry;
		t->m_aiMyInt[i] = (unsigned int) direg;
		icarry = (unsigned int)(direg>>32);
	}
	if (i==MPI_LENGTH)
	{
		t->m_iCarry = icarry;
	}
	else
	{
		if ((t->m_aiMyInt[i]=icarry)!=0)
			t->m_iLengthInInts=i+1;
	}
	return;
}

int CMpiEqualN(CMpi *t,  unsigned int n)
{
	int i;
	if (t->m_iLengthInInts==0 )
	{
		if(n==0)
			return 1;
	}
	if (t->m_iLengthInInts==1 )
	{
		if(n==t->m_aiMyInt[0])
			return 1;
	}

	for (i=1;i<t->m_iLengthInInts;i++)
	{
		if (t->m_aiMyInt[i]!=0)
			return 0;
	}
	if (n==t->m_aiMyInt[0])
		return 1;
	return 0;
}

int CMpiEqualCMpi(CMpi *t,  CMpi *m)
{
	int i,j;
	j = __mpimax(t->m_iLengthInInts,m->m_iLengthInInts);
	for (i=j-1;i>=0;i--)
	{
		if (t->m_iLengthInInts>i && m->m_iLengthInInts>i)
		{
			if (t->m_aiMyInt[i]!=m->m_aiMyInt[i])
				return 0;
			else
				continue;
		}
		if (t->m_iLengthInInts<=i)
		{
			if (m->m_aiMyInt[i]!=0)
				return 0;
			else
				continue;
		}
		if (m->m_iLengthInInts<=i)
		{
			if (t->m_aiMyInt[i]!=0)
				return 0;
			else
				continue;
		}
	}
	return 1;
}

void CMpiBitShiftLeftAssign(CMpi *t,  int n)
{
	CMpl temp;
	CMplInit(&temp);

	CMplAssignCMpi(&temp,t);
	CMplBitShiftLeftAssign(&temp,n);
	CMpiAssignCMpl(t,&temp);
	t->m_iCarry = 0;
	return;
}

void CMpiBitShiftRightAssign(CMpi *t,  int n)
{
	CMpl temp;
	CMplInit(&temp);

	CMplAssignCMpi(&temp,t);
	CMplBitShiftRightAssign(&temp,n);
	CMpiAssignCMpl(t,&temp);
	t->m_iCarry = 0;
	return;
}
int CMpiABSBigger(CMpi *t,  CMpi *m)
{
	int i,j;
	j = __mpimax(t->m_iLengthInInts,m->m_iLengthInInts);
	for (i=j-1;i>=0;i--)
	{
		if (t->m_iLengthInInts>i && m->m_iLengthInInts>i)
		{
			if (t->m_aiMyInt[i]>m->m_aiMyInt[i])
				return 1;
			if (t->m_aiMyInt[i]<m->m_aiMyInt[i])
				return 0;
		}
		else
		{
			if (t->m_iLengthInInts<=i)
			{
				if (m->m_aiMyInt[i]!=0)
					return 0;
				else
					continue;
			}
			if (m->m_iLengthInInts<=i)
			{
				if (t->m_aiMyInt[i]!=0)
					return 1;
				else
					continue;
			}
		}
	}
	return 0;
}
int CMpiABSNotBigger(CMpi *t, CMpi *m)
{
	return CMpiABSBigger(m,t);
}

int CMpiBigger(CMpi *t, CMpi *m)
{
	if (t->m_iMySign!=NEGTIVE)
	{
		if (m->m_iMySign==NEGTIVE)
			return 1;
		if (t->m_iMySign==POSITIVE)
		{
			// m.m_iMySign may be INFINITE
			if (m->m_iMySign == POSITIVE)
			{
				if (CMpiABSBigger(t, m))
					return 1;
				else
					return 0;
			}
			else // m.m_iMySign be INFINITE
			{
				return 0;
			}
		}
		else // this->m_iMySign == INFINITE
			return 0;
	}
	if (t->m_iMySign==NEGTIVE)
	{
		if (m->m_iMySign!=NEGTIVE)
			return 0;
		else
		{
			if (CMpiABSNotBigger(t,m))
				return 1;
			else
				return 0;
		}
	}
	return 0; // INFINITE is not considered
}

int CMpiNotBigger(CMpi *t,  CMpi *m)
{
	return CMpiBigger(m,t);
}

void CMpiAdd(CMpi *res, CMpi *t, CMpi *m)
{
	CMpiAssignCMpi(res,t);
	CMpiAddAssign(res,m);
	return;
}

void CMpiMinus(CMpi *res,CMpi *t)
{
	CMpiAssignCMpi(res,t);
	if (t->m_iMySign == MPI_INFINITE)
		return;
	if (t->m_iMySign == POSITIVE)
		res->m_iMySign = NEGTIVE;
	else
		res->m_iMySign = POSITIVE;

	return;
}

void CMpiSubAssign(CMpi *t, CMpi *m)
{
	int i,j;
	register DOUBLE_INT direg;
	unsigned int *pm1, *pm2;
	int len2;
	CMpi temp;
	t->m_iCarry = 0;
	if (t->m_iMySign!=m->m_iMySign)
	{
		CMpiInit(&temp);
		CMpiMinus(&temp,m);
		CMpiAddAssign(t,&temp);
		return;
	}
	if (CMpiABSBigger(m,t))
	{
		pm2= t->m_aiMyInt;
		len2 = t->m_iLengthInInts;
		pm1= m->m_aiMyInt;

		if (m->m_iMySign == POSITIVE)
			t->m_iMySign = NEGTIVE;
		else
			t->m_iMySign = POSITIVE;
	}
	else
	{
		pm1 = t->m_aiMyInt;
		pm2 = m->m_aiMyInt;
		len2 = m->m_iLengthInInts;
	}
	j=__mpimax(t->m_iLengthInInts,m->m_iLengthInInts);

	direg=0x100000000ll+ pm1[0]; // pre carry
	for (i=0;i<len2;i++)
	{
		direg -= pm2[i];
		t->m_aiMyInt[i]=(unsigned int)direg;
		direg >>= 32;
		direg += pm1[i+1];
		direg += 0xffffffffL; // +100000000 - 1
	}

	for (; i < j; i++)
	{
		t->m_aiMyInt[i]=(unsigned int)direg;
		direg >>= 32;
		direg += pm1[i+1];
		direg += 0xffffffffL; // +100000000 - 1
	}

	t->m_iLengthInInts=j;
	for (i=j-1;i>=0;i--)
	{
		if (t->m_aiMyInt[i]!=0)
			break;
		t->m_iLengthInInts=i;
	}
	return;
}

void CMpiSub(CMpi *res, CMpi *t, CMpi *m)
{
	CMpiAssignCMpi(res,t);
	CMpiSubAssign(res,m);
	return;
}

void CMpiAddAssign(CMpi *t, CMpi *m)
{
	int i,j;
	register DOUBLE_INT direg;
	CMpi temp;
	t->m_iCarry = 0;
	if (t->m_iMySign == MPI_INFINITE)
		return;
	if (m->m_iMySign == MPI_INFINITE)
	{
		t->m_iMySign = MPI_INFINITE;
		return;
	}
	if (t->m_iMySign==POSITIVE)
	{
		if (m->m_iMySign!=POSITIVE)
		{
			CMpiInit(&temp);
			CMpiMinus(&temp, m);
			CMpiSubAssign(t,&temp);
			return;
		}
	}
	else
	{
		if (m->m_iMySign==POSITIVE)
		{
			CMpiInit(&temp);
			CMpiMinus(&temp,t);
			CMpiSub(t,m,&temp);
			return;
		}
	}

	j=__mpimin(t->m_iLengthInInts,m->m_iLengthInInts);
	direg=0;
	for (i=0;i<j;i++)
	{	
		direg+=t->m_aiMyInt[i];
		direg+=m->m_aiMyInt[i];
		t->m_aiMyInt[i]=(unsigned int)direg;
		direg>>=32;
	}

	if (t->m_iLengthInInts > m->m_iLengthInInts)
	{
		j = t->m_iLengthInInts;
		for (; i < j; i++)
		{
			direg+=t->m_aiMyInt[i];
			t->m_aiMyInt[i]=(unsigned int)direg;
			direg>>=32;
		}
	}
	else
	{
		j = m->m_iLengthInInts;
		for (; i < j; i++)
		{
			direg+=m->m_aiMyInt[i];
			t->m_aiMyInt[i]=(unsigned int)direg;
			direg>>=32;
		}
	}

	if (j==MPI_LENGTH)
	{
		t->m_iCarry = (unsigned int)direg;
		t->m_iLengthInInts = j;
	}
	else
	{
		t->m_aiMyInt[j]=(unsigned int)direg;
		if (t->m_aiMyInt[j]!=0)
			t->m_iLengthInInts=j+1;
		else
			t->m_iLengthInInts=j;
	}
	return;
}

void CMpiInit(CMpi *t)
{
//	t->m_aiMyInt[0] =1;
	t->m_iCarry = 0;
	t->m_iMySign = POSITIVE;
	t->m_iLengthInInts = 0;
}

void CMpiInitN(CMpi *t,unsigned int iInitial)
{
	t->m_iMySign = POSITIVE;
	
	if (iInitial==0)
		t->m_iLengthInInts = 0;
	else
		t->m_iLengthInInts = 1;
	t->m_aiMyInt[0]= iInitial;

	t->m_iCarry = 0;
}

void CMplInit(CMpl *t)
{
	t->h.m_iMySign = POSITIVE;
	t->l.m_iMySign  = POSITIVE;
	t->h.m_iLengthInInts = 0;
	t->l.m_iLengthInInts = 0;

	t->h.m_iCarry = 0;
	t->l.m_iCarry = 0;
}

void CMplAssignCMpi(CMpl *t,  CMpi *m)
{
	CMpiAssignCMpi(&(t->l),m);
	t->h.m_iMySign = m->m_iMySign;
	if (m->m_iCarry!=0)
	{
		t->h.m_aiMyInt[0]=m->m_iCarry;
		t->h.m_iLengthInInts = 1;
	}
	else
	{
		t->h.m_aiMyInt[0]=0;
		t->h.m_iLengthInInts = 0;
	}
}
void CMplAssignCMpl(CMpl *t,  CMpl *m)
{
	CMpiAssignCMpi(&(t->l),&(m->l));
	CMpiAssignCMpi(&(t->h),&(m->h));
	return;
}

void CMplBitShiftLeft(CMpl *t,  int iShiftBits)
{
	int i,j,k;
	j = iShiftBits/BITS_OF_INT;
	if (j!=0)
	{
		CMplBitShiftLeftAssign(t,j);
	}
	j = iShiftBits%BITS_OF_INT;

	if (j==0)
		return;
	// For high MPI
	k = t->h.m_iLengthInInts ;
	if (k>0)
	{
		if (k<MPI_LENGTH)
		{
			t->h.m_aiMyInt[k] = t->h.m_aiMyInt[k-1]>>(BITS_OF_INT-j);
			if (t->h.m_aiMyInt[k]!=0)
				t->h.m_iLengthInInts ++;
		}
		for (i = k-1; i>0;i--)
		{
			t->h.m_aiMyInt[i] <<= j;
			t->h.m_aiMyInt[i] += t->h.m_aiMyInt[i-1]>>(BITS_OF_INT-j);
		}
		t->h.m_aiMyInt[0] <<= j;
		t->h.m_aiMyInt[0] += t->l.m_aiMyInt[MPI_LENGTH-1]>>(BITS_OF_INT-j);
	}
	else
	{
		if (t->l.m_iLengthInInts==MPI_LENGTH)
		{
			t->h.m_aiMyInt[0] = t->l.m_aiMyInt[MPI_LENGTH-1]>>(BITS_OF_INT-j);
			if (t->h.m_aiMyInt[0]!=0)
				t->h.m_iLengthInInts = 1;
		}
	}
	// For low MPI
	k = t->l.m_iLengthInInts;
	if (k<MPI_LENGTH)
	{
			t->l.m_aiMyInt[k] = t->l.m_aiMyInt[k-1]>>(BITS_OF_INT-j);
			if (t->l.m_aiMyInt[k]!=0)
				t->l.m_iLengthInInts ++;
	}
	for (i=k-1;i>0;i--) // Changed to k-1 for Bug No. 374
	{
		t->l.m_aiMyInt[i]<<=j;
		t->l.m_aiMyInt[i] += t->l.m_aiMyInt[i-1]>>(BITS_OF_INT-j);
	}
	t->l.m_aiMyInt[0]<<=j;

	return;
}


void CMplBitShiftLeftAssign(CMpl *t,  int n) 
{
	int i,j,k,p;
	if (n<0)
		return CMplBitShiftRightAssign(t,-n);  // Bug 90
	k = t->h.m_iLengthInInts + t->l.m_iLengthInInts;
	if (k==0)
		return;
	if (k==1 && t->l.m_aiMyInt[0]==0)
		return;

	k +=n;
	if (k >= MPI_LENGTH*2)
		k = MPI_LENGTH*2;
	j = k-MPI_LENGTH;

	// Calculate High Mpi
	for (i=j-1, p=i-n; i>=0; i--, p--)
	{
		if (p>=0)
		{
			t->h.m_aiMyInt[i] = t->h.m_aiMyInt[p];
		}
		else
		{
			if ((p+MPI_LENGTH)>=0) // Valid in Low Mpi 
			// Add '=' for bug No 94
			{
				t->h.m_aiMyInt[i] = t->l.m_aiMyInt[MPI_LENGTH+p];
				continue;
			}
			else
			{
				t->h.m_aiMyInt[i]=0;
				continue;
			}
		}
	}
	// Calculate Low Mpi
	if (k>=MPI_LENGTH)
		j = MPI_LENGTH;
	else
		j = k;
	for (i=j-1, p=i-n;i>=0;i--, p--)
	{
		if (p>=0)
		{
			t->l.m_aiMyInt[i]=t->l.m_aiMyInt[p];
		}
		else
		{
			t->l.m_aiMyInt[i]=0;
		}
	}
	t->l.m_iLengthInInts = j;
	if (j>=MPI_LENGTH)
		t->h.m_iLengthInInts = k-MPI_LENGTH;
	else
		t->h.m_iLengthInInts = 0;
	return;
}

void CMplBitShiftRight(CMpl *t,  int iShiftBits)
{
	int i,j,k;
	j = iShiftBits/(BITS_OF_INT);
	if (j!=0)
	{
		CMplBitShiftRightAssign(t,j);
	}
	j = iShiftBits%(BITS_OF_INT);

	if (j==0)
		return;

	// For low MPI
	k = t->l.m_iLengthInInts;

	for (i=0; i<t->l.m_iLengthInInts-1;i++)
	{
		t->l.m_aiMyInt[i]>>=j;
		t->l.m_aiMyInt[i] += t->l.m_aiMyInt[i+1]<<(BITS_OF_INT-j);
	}
	if (k<MPI_LENGTH)
	{
		t->l.m_aiMyInt[t->l.m_iLengthInInts-1]>>=j;
		if (t->l.m_aiMyInt[t->l.m_iLengthInInts-1]==0)
			t->l.m_iLengthInInts --;
	}
	else
	{
		t->l.m_aiMyInt[t->l.m_iLengthInInts-1]>>=j;
		if (t->h.m_iLengthInInts>0)
			t->l.m_aiMyInt[t->l.m_iLengthInInts-1]+= t->h.m_aiMyInt[0]<<(BITS_OF_INT-j);
	}
	
	// For high MPI
	k = t->h.m_iLengthInInts ;
	if (k>0)
	{
		for (i =0;i< k-1; i++)
		{
			t->h.m_aiMyInt[i] >>= j;
			t->h.m_aiMyInt[i] += t->h.m_aiMyInt[i+1]<<(BITS_OF_INT-j);
		}

		t->h.m_aiMyInt[k-1] >>= j;
		if (t->h.m_aiMyInt[k-1]==0)
			t->h.m_iLengthInInts --;
	}
	return;
}


void CMplBitShiftRightAssign(CMpl *t,  int n)
{
	int i,j;
	if (n<0)
		return CMplBitShiftLeftAssign(t,-n);  // Bug 90
	// For low Mpi
	for (i=0;i<t->l.m_iLengthInInts;i++)
	{
		if ((i+n) < t->l.m_iLengthInInts)
		{
			t->l.m_aiMyInt[i] = t->l.m_aiMyInt[i+n];
		}
		else
		{
			if (t->l.m_iLengthInInts == MPI_LENGTH)
			{
				j = i+n-MPI_LENGTH;
				if (j<t->h.m_iLengthInInts)
				{
					t->l.m_aiMyInt[i] = t->h.m_aiMyInt[j];
					continue;
				}
				else
				{
					t->l.m_aiMyInt[i] = 0;
					t->l.m_iLengthInInts = i;
					t->h.m_iLengthInInts = 0;
					return;
				}
			}
			else
			{
				t->l.m_aiMyInt[i]=0;
				t->l.m_iLengthInInts = i;
				t->h.m_iLengthInInts = 0;
				return;
			}
		}
	}

	// High Mpi
	for (i=0;i<t->h.m_iLengthInInts;i++)
	{
		if ((i+n)<t->h.m_iLengthInInts)
		{
			t->h.m_aiMyInt[i] = t->h.m_aiMyInt[n+i];
		}
		else
		{
			t->h.m_aiMyInt[i]=0;
			t->h.m_iLengthInInts = i;
			return;
		}
	}
	return;
}
void CMplAddAssign(CMpl *t, CMpl *oMpl)
{
	CMpi o;
	int i;
	if (t->l.m_iMySign == MPI_INFINITE)
		return;
	if (oMpl->l.m_iMySign == MPI_INFINITE)
	{
		t->h.m_iMySign = MPI_INFINITE;
		t->l.m_iMySign = MPI_INFINITE;
		return;
	}
	CMpiAddAssign(&(t->l),&(oMpl->l));
	CMpiAddAssign(&(t->h),&(oMpl->h));

	//add by xj  -start
	if (CMpiEqualN(&(t->h),0))
		t->h.m_iMySign = t->l.m_iMySign;
	//add by xj -end
	CMpiInit(&o);
	// Deal with carry in l and sign
	if (t->l.m_iMySign == t->h.m_iMySign)
	{
		if (t->l.m_iCarry)
		{
			CMpiInitN(&o,t->l.m_iCarry);
			o.m_iMySign = t->l.m_iMySign;
			CMpiAddAssign(&(t->h),&o);
			t->l.m_iCarry = 0;
		}
	}
	else
	{
		// l.m_iCarry should be zero
		for (i=0;i<MPI_LENGTH;i++)
			o.m_aiMyInt[i]=HEX32BITS;
		o.m_iLengthInInts = MPI_LENGTH;
		o.m_iMySign =t->h.m_iMySign;
		CMpiAddAssign(&(t->l),&o);
				
		o.m_iLengthInInts = 1;
		o.m_aiMyInt[1] = 0;
		o.m_aiMyInt[0] = 1;
		o.m_iMySign = t->h.m_iMySign;
		CMpiAddAssign(&(t->l),&o);
		CMpiSubAssign(&(t->h),&o);;
	}
	//add by xj  -start           !!!!!!!!!!!!!!!!!
	if (t->l.m_iLengthInInts < MPI_LENGTH && (CMpiEqualN(&(t->h),0)== 0))
		t->l.m_iLengthInInts = MPI_LENGTH;
	//add by xj -end
	return;
}

void CMplSubAssign(CMpl *t, CMpl *oMpl)
{
	CMpl temp;
	if (t->l.m_iMySign == MPI_INFINITE)
		return;
	if (oMpl->l.m_iMySign == MPI_INFINITE)
	{
		t->h.m_iMySign = MPI_INFINITE;
		t->l.m_iMySign = MPI_INFINITE;
		return;
	}
	CMplInit(&temp);

	CMplAssignCMpl(&temp,oMpl);
	if (oMpl->l.m_iMySign == POSITIVE)
	{
		temp.l.m_iMySign = NEGTIVE;
		temp.h.m_iMySign = NEGTIVE;
	}
	else
	{
		temp.l.m_iMySign = POSITIVE;
		temp.h.m_iMySign = POSITIVE;
	}
	CMplAddAssign(t,&temp);
	return;
}

int CMplEqual(CMpl *t,  CMpl *oMpl)
{
	if (CMpiEqualCMpi(&(t->l),&(oMpl->l))==1)
	{
		if (CMpiEqualCMpi(&(t->h),&(oMpl->h))==1)
			return 1;
	}
	return 0;
}

void CMplReduction(CMpl *t, CMpi *m)
{
	// this=this%m
	CMpi odiv;
	CMpi mt;
	CMpl temp;
	CMpl tdiv;
	int i,j,sflag,mflag,len;
	unsigned int ui,uj,flag;
	DOUBLE_INT t64;

	if (m->m_aiMyInt[0] == 0xFFFFFFFF
		&& m->m_aiMyInt[1] == 0xFFFFFFFF
		&& m->m_aiMyInt[2] == 0x00000000
		&& m->m_aiMyInt[3] == 0xFFFFFFFF
		&& m->m_aiMyInt[4] == 0xFFFFFFFF
		&& m->m_aiMyInt[5] == 0xFFFFFFFF
		&& m->m_aiMyInt[6] == 0xFFFFFFFF
		&& m->m_aiMyInt[7] == 0xFFFFFFFE
		&& m->m_iLengthInInts == MPI_LENGTH)
	{//add from wuqiong pan
		CMplFastReduction(t,m);
		return;
	}



	mflag = t->l.m_iMySign;
	CMpiInit(&mt);

	CMpiAssignCMpi(&mt,m);
	
	// Make the Mpi regular 
	if (t->l.m_iMySign != m->m_iMySign)
		sflag=NEGTIVE;
	else
		sflag=POSITIVE;

	t->h.m_iMySign = POSITIVE;
	t->l.m_iMySign = t->h.m_iMySign;

	for (i=mt.m_iLengthInInts-1;i>=0;i--)
	{
		if (mt.m_aiMyInt[i]!=0)
			break;
	}
	mt.m_iLengthInInts = i+1;

	if (CMpiEqualN(&mt,0)==1)
	{
		return;
	}

	mt.m_iMySign = POSITIVE;

	// Make a long integer with local array
	CMpiInit(&odiv);

	CMpiAssignCMpi(&odiv,&mt);
	odiv.m_iMySign = POSITIVE;
	/* Now we start division *this/m */ 
	/* make m bigger. and flag mean the multiplied number */
	flag=0;
	ui=odiv.m_aiMyInt[odiv.m_iLengthInInts-1];
	
	while (!(0x80000000 & (ui << flag)))
	{
		flag++;
	}
	CMpiBitShiftLeft(&odiv,flag);

	/* mdiv = m*flag which mdiv.myint[mdiv.mylen-1]>0x80000000 */
	// calculate r = *this/mdiv from j to 0
	len = t->l.m_iLengthInInts + t->h.m_iLengthInInts -odiv.m_iLengthInInts+1;
	//add by xj  -start
	if (len <= 0)
	{
		t->h.m_iMySign = mflag;
		t->l.m_iMySign = t->h.m_iMySign;
		return;
	}
	//add by xj -end;

	// For high Mpi
	if (t->h.m_iLengthInInts<MPI_LENGTH)
		t->h.m_aiMyInt[t->h.m_iLengthInInts]=0;

	// -------------------------------------------------------------------
	// added by Linjq
	// Get the first word of odiv
	ui = odiv.m_aiMyInt[odiv.m_iLengthInInts-1]+1;
	// -------------------------------------------------------------------
	CMplInit(&temp); CMplInit(&tdiv);

	for (i = t->h.m_iLengthInInts-1, j = t->h.m_iLengthInInts + MPI_LENGTH - odiv.m_iLengthInInts; i>=0; i--, j--)
	{
		if ((i+1)>=MPI_LENGTH)
			t64 = 0;
		else
			t64 = t->h.m_aiMyInt[i+1];
		t64 <<=32 ;
		t64 += t->h.m_aiMyInt[i];
		if (ui!=0)
			uj = (unsigned int)(t64/ui);
		else
			uj = (unsigned int)(t64>>32);
		CMplAssignCMpi(&temp,&odiv);
		CMpiMultiByN(&(temp.l),uj);
		if (temp.l.m_iCarry!=0)
		{
			temp.h.m_iLengthInInts = 1;
			temp.h.m_aiMyInt[0]=temp.l.m_iCarry;
		}
		else
		{
			temp.h.m_iLengthInInts = 0;
		}
		CMplBitShiftLeftAssign(&temp,j);
		CMplAssignCMpi(&tdiv,&odiv);
		CMplBitShiftLeftAssign(&tdiv,j);
		CMplSubAssign(t,&temp);
		while (CMpiABSNotBigger(&(t->h),&(tdiv.h))==0)
		{
			CMplSubAssign(t,&tdiv);
		}
	}
	if (t->l.m_iLengthInInts < MPI_LENGTH)
		t->l.m_aiMyInt[t->l.m_iLengthInInts]=0;

	// -------------------------------------------------------------------
	// added by Linjq
	ui=odiv.m_aiMyInt[odiv.m_iLengthInInts-1]+1;
	// -------------------------------------------------------------------
	for (i=t->l.m_iLengthInInts-1, j=t->l.m_iLengthInInts-odiv.m_iLengthInInts; i>=odiv.m_iLengthInInts-1; i--, j--)
	{
		if (i == MPI_LENGTH-1)
		{
			if (t->h.m_iLengthInInts == 0)
				t64 = 0;
			else
				t64 = t->h.m_aiMyInt[0];
		}
		else
			t64=t->l.m_aiMyInt[i+1];
		t64<<=32;
		t64+=t->l.m_aiMyInt[i];

		if (ui!=0)
			uj = (unsigned int)(t64/ui);
		else
			uj = (unsigned int)(t64>>32);
		CMplAssignCMpi(&temp,&odiv);
		CMpiMultiByN(&(temp.l),uj);
		if (temp.l.m_iCarry!=0)
		{
			temp.h.m_iLengthInInts = 1;
			temp.h.m_aiMyInt[0]=temp.l.m_iCarry;
		}
		else
		{
			temp.h.m_iLengthInInts = 0;
		}
		CMplBitShiftLeftAssign(&temp,j);
		CMplAssignCMpi(&tdiv,&odiv);
		CMplBitShiftLeftAssign(&tdiv,j);
		CMplSubAssign(t,&temp);
		while ((0==CMpiABSNotBigger(&(t->l), &(tdiv.l))) ||  (t->h.m_aiMyInt[0]!=0 && t->h.m_iLengthInInts!=0)  )
		{

			CMplSubAssign(t,&tdiv);
		}
	}
	// Now we get r/mdiv
	// i.e. r=this/mdiv=this/(m*flag)+0(mdiv)
	// i.e. this -mdiv < r * mdiv <= this
	// i.e. this - mdiv  < r* m * flag <= this
	// i.e. 
	// i.e. r*flag -flag < this/m <= r*flag
	
	//r*=flag; 
	while (CMpiABSNotBigger(&(t->l),&mt) == 0)
	{
		uj=t->l.m_aiMyInt[t->l.m_iLengthInInts-1]/(mt.m_aiMyInt[mt.m_iLengthInInts-1]+1);
		if (0==uj)
			uj=1;
		CMpiAssignCMpi(&(temp.l),&mt);
		CMpiMultiByN(&(temp.l),uj);
		CMpiSubAssign(&(t->l),&(temp.l));
	}
	t->h.m_iMySign = mflag;
	t->l.m_iMySign =t->h.m_iMySign;
	return;
}

/*
void CMplReductionByTable(CMpl *t, CMpi *m)
{
	CMpl sum;
	CMpi tmp;
	CMpl typetemp; //variable for type translation
	int i;
	if (m->m_aiMyInt[0] != g_paramFieldP.m_oModulus.m_aiMyInt[0])
	{
		return CMplReduction(t,m);
	}
	else
	{
		if (CMpiEqualN(&(t->h),0) != 1)
		{
			CMplInit(&sum); CMpiInit(&tmp); CMplInit(&typetemp);

			CMpiInitN(&tmp,0);
			CMplAssignCMpi(&sum,&tmp);

			i = t->h.m_iLengthInInts - 1;
			for (; i > 0; i--)
			{
				if (0 != t->h.m_aiMyInt[i])
				{
					CMpiAssignCMpi(&tmp,&(g_tableReduction[i]));
					CMpiMultiByN(&tmp,t->h.m_aiMyInt[i]);
					CMplAssignCMpi(&typetemp,&tmp);
					CMplAddAssign(&sum,&typetemp);
				}
			}
			CMpiInitN(&(t->h),t->h.m_aiMyInt[0]);
			sum.l.m_iMySign = t->l.m_iMySign;
			sum.h.m_iMySign = sum.l.m_iMySign;
			t->h.m_iMySign = sum.h.m_iMySign;
			CMplAddAssign(t,&sum);

			if (t->h.m_iLengthInInts > 1)
			{
				CMpiInitN(&tmp,0);
				CMplAssignCMpi(&sum,&tmp);

				i = t->h.m_iLengthInInts - 1;
				for (; i > 0; i--)
				{
					if (0 != t->h.m_aiMyInt[i])
					{
						CMpiAssignCMpi(&tmp,&(g_tableReduction[i]));
						CMpiMultiByN(&tmp,t->h.m_aiMyInt[i]);
						CMplAssignCMpi(&typetemp,&tmp);
						CMplAddAssign(&sum,&typetemp);
					}
				}
				CMpiInitN(&(t->h),t->h.m_aiMyInt[0]);
				sum.l.m_iMySign = t->l.m_iMySign;
				sum.h.m_iMySign = sum.l.m_iMySign;
				t->h.m_iMySign = sum.h.m_iMySign;
				CMplAddAssign(t,&sum);
			}
			
		}

		CMplReduction(t,m);
	}
	return;
}
*/
void CMplFastReduction(CMpl *t,  CMpi *m)
{
	int i, tflag;
	CMpl tempH;

	CMplInit(&tempH);
	tflag = t->l.m_iMySign;
	t->h.m_iMySign = POSITIVE;
	t->l.m_iMySign = POSITIVE;

	i = t->h.m_iLengthInInts;
	while (--i >= 0)
	{
		while (t->h.m_aiMyInt[i])
		{
			CMpiInitN(&(tempH.h),0);
			tempH.l.m_aiMyInt[7] = tempH.l.m_aiMyInt[0] = t->h.m_aiMyInt[i];
			tempH.l.m_aiMyInt[6] = tempH.l.m_aiMyInt[5] = tempH.l.m_aiMyInt[4] = tempH.l.m_aiMyInt[2] = tempH.l.m_aiMyInt[1] = 0;
			tempH.l.m_aiMyInt[2] = 0 - t->h.m_aiMyInt[i];
			tempH.l.m_aiMyInt[3] = t->h.m_aiMyInt[i] - 1;
			tempH.l.m_iLengthInInts = 8;

			CMplBitShiftLeftAssign(&tempH,i);

			t->h.m_aiMyInt[i] = 0;

			// add
			CMplAddAssign(t,&tempH);
		}
	}

	t->h.m_iLengthInInts = 0;
	t->h.m_iMySign = tflag;

	// here, m must > 0. The field.
	if (CMpiBigger(&(t->l),m) ==1)
		CMpiSubAssign(&(t->l),m);

	if (CMpiEqualCMpi(&(t->l),m) ==1)
		CMpiInitN(&(t->l),0);
	else
		t->l.m_iMySign = tflag;

}

void CMplModAssign(CMpi*res, CMpl *t, CMpi *m)
{
	CMplReduction(t,m);
	CMpiAssignCMpi(res,&(t->l));
}

void CMplInitN(CMpl *t,unsigned int iInitial)
{
	CMpi temp ;
	CMpiInit(&(t->l)); CMpiInit(&(t->h));
	CMpiInitN(&temp,iInitial);
	CMplAssignCMpi(t, &temp);
	return;
}

int CModulusGetLengthInBytes(CModulus *t)
{
	return CMpiGetLengthInBytes(&(t->m_oModulus));
}

void CModulusInitCMpi(CModulus *t, CMpi *oMpi)
{
	if (oMpi->m_iMySign==MPI_INFINITE)
	{
		CMpiInitN(&(t->m_oModulus),0);
	}
	CMpiAssignCMpi(&(t->m_oModulus),oMpi);
	CMpiRegularize(&(t->m_oModulus));
}

void CModulusInit(CModulus *t)
{
	CMpiInitN(&(t->m_oModulus),0);
}

void CModulusBinaryInverse(CMpi *res, CModulus *t,  CMpi *oMpi)
{
	CMpi u;
	CMpi v;
	CMpi cmpitemp;
	CMpl temp;
	CMpl x1;
	CMpl x2;

	CMpiInit(&u); CMpiInit(&v); CMpiInit(&cmpitemp); 
	CMplInit(&temp); CMplInit(&x1); CMplInit(&x2);

	CMpiAssignCMpi(&u,oMpi);
	CMpiAssignCMpi(&v, &(t->m_oModulus));
	CMplInitN(&x1,1);
	CMplInitN(&x2,0);

	//while ((u != 1) && (v != 1))
	while((CMpiEqualN(&u,1)!=1) && (CMpiEqualN(&v,1)!=1))
	{
		while (!(u.m_aiMyInt[0] & 0x01))		// even
		{
			CMpiBitShiftRight(&u,1);
			if (!(x1.l.m_aiMyInt[0] & 0x01))		// even
				CMplBitShiftRight(&x1,1);
			else
			{
				CMplAssignCMpi(&temp, &(t->m_oModulus));
				CMplAddAssign(&x1,&temp);
				CMplBitShiftRight(&x1,1);
			}
		}

		while (!(v.m_aiMyInt[0] & 0x01))
		{
			CMpiBitShiftRight(&v,1);
			if (!(x2.l.m_aiMyInt[0] & 0x01))
				CMplBitShiftRight(&x2,1);
			else
			{
				CMplAssignCMpi(&temp, &(t->m_oModulus));
				CMplAddAssign(&x2,&temp);
				CMplBitShiftRight(&x2,1);
			}
		}

		if (CMpiNotBigger(&u,&v) ==1)
		{
			CMpiSubAssign(&v,&u);
			CMplSubAssign(&x2,&x1);
		}
		else
		{
			CMpiSubAssign(&u,&v);
			CMplSubAssign(&x1,&x2);
		}
	}

	if (CMpiEqualN(&u,1) ==1)
	{
		CMplModAssign(&cmpitemp,&x1,&(t->m_oModulus));
		CMplAssignCMpi(&x1,&cmpitemp);
	
		if (CMpiIsNegative(&(x1.l)) == 1)
		{
			CMplAssignCMpi(&temp,&(t->m_oModulus));
			CMplAddAssign(&x1,&temp);
		}
		CMpiAssignCMpi(res,&(x1.l));
	}
	else
	{
		CMplModAssign(&cmpitemp,&x2,&(t->m_oModulus));
		CMplAssignCMpi(&x2,&cmpitemp);
	
		if (CMpiIsNegative(&(x2.l)) == 1)
		{
			CMplAssignCMpi(&temp,&(t->m_oModulus));
			CMplAddAssign(&x2,&temp);
		}
		CMpiAssignCMpi(res,&(x2.l));
	}
	return;
}