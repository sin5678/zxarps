// GetOpt.h: interface for the CGetOpt class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_GETOPT_H__02D8B552_9210_43E0_A43D_EAFD0A51F205__INCLUDED_)
#define AFX_GETOPT_H__02D8B552_9210_43E0_A43D_EAFD0A51F205__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <windows.h>
#include <stdlib.h>

class CGetOpt  
{
protected:
	bool bSensitive;
	int m_argc;
	char **m_argv;

	int nextopt;
	char *pretstr;

public:
	CGetOpt(int argc, char **argv, bool sensitive);
	virtual ~CGetOpt();

	operator char*(){return pretstr;};

	void EnableSensitive(bool b){ bSensitive = b;}

	char *getstrbyidx(int idx);
	int getintbyidx(int idx);
	char *getstr(char *lpopt);
	int getint(char *lpopt);
	bool checkopt(char *lpopt);

	char *getnextstr(char *lpopt);
	int getnextint(char *lpopt);

	char *getnextopt();
	int getnextoptint();
};

#endif // !defined(AFX_GETOPT_H__02D8B552_9210_43E0_A43D_EAFD0A51F205__INCLUDED_)
