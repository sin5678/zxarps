// GetOpt.cpp: implementation of the CGetOpt class.
//
//////////////////////////////////////////////////////////////////////

#if defined _ZXSHELL
#include "..\zxsCommon\zxsWinAPI.h"
#endif

#include "GetOpt.h"
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CGetOpt::CGetOpt(int argc, char **argv, bool sensitive)
{
	m_argc = argc;
	m_argv = argv;
	bSensitive = sensitive;

	nextopt = 2;
}

CGetOpt::~CGetOpt()
{

}

bool CGetOpt::checkopt(char *lpopt)
{
	for(int i=1; i<m_argc; i++)
	{
		if(bSensitive)
		{
			if((m_argv[i][0] == '/' || m_argv[i][0] == '-') && m_argv[i][1]
				&& !strcmp(&m_argv[i][1], lpopt))
			{
				return true;
			}
		}else
		{
			if((m_argv[i][0] == '/' || m_argv[i][0] == '-') && m_argv[i][1]
				&& !_stricmp(&m_argv[i][1], lpopt))
			{
				return true;
			}
		}
	}

	return false;
}

char *CGetOpt::getstrbyidx(int idx)
{
	if(idx < m_argc)
		return m_argv[idx];
	else
		return NULL;
}

int CGetOpt::getintbyidx(int idx)
{
	char *p = getstrbyidx(idx);
	if(p)
		return atoi(p);
	else
		return 0;
}

char *CGetOpt::getnextopt()
{
	if(nextopt < m_argc)
		return m_argv[nextopt++];
	else
		return NULL;
}

int CGetOpt::getnextoptint()
{
	if(nextopt < m_argc)
		return atoi(m_argv[nextopt++]);
	else
		return 0;
}

int CGetOpt::getint(char *lpopt)
{
	char *pstr = getstr(lpopt);

	if(pstr)
		return atoi(pstr);
	else
		return 0;
}

int CGetOpt::getnextint(char *lpopt)
{
	char *pstr = getnextstr(lpopt);

	if(pstr)
		return atoi(pstr);
	else
		return 0;
}

char *CGetOpt::getstr(char *lpopt)
{
	pretstr = NULL;

	for(int i=2; i<m_argc; i++)
	{
		if(bSensitive)
		{
			if((m_argv[i-1][0] == '/' || m_argv[i-1][0] == '-') && m_argv[i-1][1]
				&& !strcmp(&m_argv[i-1][1], lpopt))
			{
				pretstr = m_argv[i];
				nextopt = i+1;
				break;
			}
		}else
		{
			if((m_argv[i-1][0] == '/' || m_argv[i-1][0] == '-') && m_argv[i-1][1]
				&& !_stricmp(&m_argv[i-1][1], lpopt))
			{
				pretstr = m_argv[i];
				nextopt = i+1;
				break;
			}
		}
	}

	return pretstr;
}

char *CGetOpt::getnextstr(char *lpopt)
{
	pretstr = NULL;

	for(int i=nextopt; i<m_argc; i++)
	{
		if(bSensitive)
		{
			if((m_argv[i-1][0] == '/' || m_argv[i-1][0] == '-') && m_argv[i-1][1]
				&& !strcmp(&m_argv[i-1][1], lpopt))
			{
				pretstr = m_argv[i];
				nextopt = i+1;

				break;
			}
		}else
		{
			if((m_argv[i-1][0] == '/' || m_argv[i-1][0] == '-') && m_argv[i-1][1]
				&& !_stricmp(&m_argv[i-1][1], lpopt))
			{
				pretstr = m_argv[i];
				nextopt = i+1;

				break;
			}
		}
	}

	return pretstr;
}