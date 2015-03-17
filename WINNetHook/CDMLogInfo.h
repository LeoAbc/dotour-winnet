// CDMLogInfo.h: interface for the CCDMLogInfo class.
//
//////////////////////////////////////////////////////////////////////

#ifndef _CDM_LOGINFO_H_
#define _CDM_LOGINFO_H_
class CCDMLogInfo  
{
public:
	static CCDMLogInfo* GetInstance(char*m_strLogName);

private:
	CCDMLogInfo(char* strLogName);
	virtual ~CCDMLogInfo();	
private:
	void* m_hFile;
	static char m_strLogName[260];
	static CCDMLogInfo* m_pInstance;
	int   m_iRef;
	void IncreaseRef(){m_iRef++;}
public:
	void SetNotify(char*szFmt, ...);
	int  Release();
};

#endif//_CDM_LOGINFO_H_