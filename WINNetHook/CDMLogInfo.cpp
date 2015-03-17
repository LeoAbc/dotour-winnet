// CDMLogInfo.cpp: implementation of the CCDMLogInfo class.
//
//////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "CDMLogInfo.h"
#include <Windows.h>
#include <stdio.h>
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
CCDMLogInfo* CCDMLogInfo::m_pInstance = NULL;
char CCDMLogInfo::m_strLogName[] = "0";
CCDMLogInfo* CCDMLogInfo::GetInstance(char*strLogName)
{
	if(strcmp(m_strLogName, strLogName) == 0)
	{
		if(m_pInstance)
		{			
		}
		else
		{
			m_pInstance = new CCDMLogInfo(strLogName);
		}
	}
	else
	{	
		m_pInstance = new CCDMLogInfo(strLogName);
	}

	m_pInstance->IncreaseRef();

	return m_pInstance;
}

CCDMLogInfo::CCDMLogInfo(char* strLogName)
            :m_hFile(NULL)
			,m_iRef(0)
{
	memset(m_strLogName, 0, 260);
	if(strLogName)
	{		
		int iSize = strlen(strLogName);
		memcpy(m_strLogName, strLogName, iSize);
		m_hFile = (void*)fopen(strLogName, "at");
	}
}

CCDMLogInfo::~CCDMLogInfo()
{
	FILE* pFile = (FILE*)m_hFile;
	if(pFile)
	{
		fclose(pFile);
	}
	m_pInstance = NULL;
}

void CCDMLogInfo::SetNotify(char*szFmt, ...)
{
	FILE* file = (FILE*)m_hFile;	
	if(szFmt && file)
	{
		char msgBuf[1024] = "Info: ";
		try{	
			va_list argPtr;
			va_start(argPtr, szFmt);			
			int cut = wvsprintfA(msgBuf + 6, szFmt, argPtr);			
			va_end(argPtr);	
			int len = strlen(msgBuf);				
			msgBuf[len] = 0x0A;		
			fwrite(msgBuf, len + 1, 1, file);		
			fflush(file);
		}catch(...)
		{//do nothing
		
		}
	}
}

int CCDMLogInfo::Release()
{
	if(m_iRef <= 0)
		return -1;
	m_iRef--;
	if(m_iRef == 0)
	{
		delete this;
	}
	return m_iRef;
}