#include "speedctrl.h"

inline double SPEEDSCTRL::Init()
{
	return BaseTime = PrevTime = GetCurrTime();
}

inline double SPEEDSCTRL::GetCurrTime()
{
	SYSTEMTIME st;
	GetLocalTime(&st);
	return st.wHour*60*60*1000 + st.wMinute*60*1000 + st.wSecond*1000 + st.wMilliseconds;
}

inline void SPEEDSCTRL::LimitSpeed(double TotalData, DWORD Unit, double Speed_Per_Sec)
{
	if(Speed_Per_Sec == 0)
		return;
	DataUnit = Unit;
	CurrTime = GetCurrTime();
	DoDelay(BaseTime, CurrTime, TotalData - PrevSize, Speed_Per_Sec/1000);
	PrevTime = CurrTime;
	PrevSpeed = Speed_Per_Sec/1000;
}

inline void SPEEDSCTRL::DoDelay(double BaseTime, double CurrTime, double CurrData, double Speed)
{
	DWORD DelayTime;
	double Elapsed = CurrTime - BaseTime;
	double CurrSpeed = CurrData / Elapsed;

	if(Elapsed < 0)
		goto error;

	if(CurrSpeed <= Speed)
	{	
		if(PrevSpeed != Speed)
			goto error;
		else
			return;
	}

	DelayTime = (CurrData / Speed) - Elapsed;
	if(DelayTime > 1000)
	{
		if(Speed*1000 >= DataUnit)
			goto error;
		else
		{
			if((DataUnit / Speed) > (CurrTime-PrevTime))
				DelayTime = (DataUnit / Speed) - (CurrTime-PrevTime);
			else
				DelayTime = (DataUnit / Speed);
		}
	}
	Sleep(DelayTime);
	return;

error:
	Init();
	PrevSize += CurrData;
	return;
}
