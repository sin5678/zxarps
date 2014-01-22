#include <windows.H>

class SPEEDSCTRL  //控制流量、速度
{
protected:
	double BaseTime;
	double PrevTime;
	double CurrTime;
	double PrevSize;
	double PrevSpeed;
	DWORD DataUnit;
public:
	SPEEDSCTRL(){ memset(this, 0, sizeof(SPEEDSCTRL));}
	double Init();
	void LimitSpeed(double TotalData, DWORD Unit, double Speed_Per_Sec);

private:
	double GetCurrTime();
	void DoDelay(double BaseTime, double CurrTime, double CurrData, double Speed);

};

