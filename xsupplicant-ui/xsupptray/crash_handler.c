/**
 * The XSupplicant User Interface is Copyright 2007, 2008 Identity Engines.
 * Identity Engines provides the XSupplicant User Interface under dual license terms.
 *
 *   For open source projects, if you are developing and distributing open source 
 *   projects under the GPL License, then you are free to use the XSupplicant User 
 *   Interface under the GPL version 2 license.
 *
 *  --- GPL Version 2 License ---
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License, Version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License, Version 2 for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.  
 *  You may also find the license at the following link
 *  http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt .
 *
 *
 *   For commercial enterprises, OEMs, ISVs and VARs, if you want to distribute or 
 *   incorporate the XSupplicant User Interface with your products and do not license
 *   and distribute your source code for those products under the GPL, please contact
 *   Identity Engines for an OEM Commercial License.
 **/

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <dbghelp.h>
#include "../../buildnum.h"

#pragma comment(linker, "/defaultlib:dbghelp.lib")

LPTOP_LEVEL_EXCEPTION_FILTER previousFilter = NULL;
HANDLE m_hProcess;
FILE *fh = NULL;

// A lot of the code below was taken from an MSDN Magazine article from
// March of 2002. (Fairly heavily modified) It can be found at :
//    http://msdn.microsoft.com/msdnmag/issues/02/03/hood/default.aspx
//
char *GetExceptionString( DWORD code)
{
#define EXCEPTION(x)  case EXCEPTION_##x: return _strdup(#x);

	switch (code)
	{
        EXCEPTION( ACCESS_VIOLATION )
        EXCEPTION( DATATYPE_MISALIGNMENT )
        EXCEPTION( BREAKPOINT )
        EXCEPTION( SINGLE_STEP )
        EXCEPTION( ARRAY_BOUNDS_EXCEEDED )
        EXCEPTION( FLT_DENORMAL_OPERAND )
        EXCEPTION( FLT_DIVIDE_BY_ZERO )
        EXCEPTION( FLT_INEXACT_RESULT )
        EXCEPTION( FLT_INVALID_OPERATION )
        EXCEPTION( FLT_OVERFLOW )
        EXCEPTION( FLT_STACK_CHECK )
        EXCEPTION( FLT_UNDERFLOW )
        EXCEPTION( INT_DIVIDE_BY_ZERO )
        EXCEPTION( INT_OVERFLOW )
        EXCEPTION( PRIV_INSTRUCTION )
        EXCEPTION( IN_PAGE_ERROR )
        EXCEPTION( ILLEGAL_INSTRUCTION )
        EXCEPTION( NONCONTINUABLE_EXCEPTION )
        EXCEPTION( STACK_OVERFLOW )
        EXCEPTION( INVALID_DISPOSITION )
        EXCEPTION( GUARD_PAGE )
		EXCEPTION( INVALID_HANDLE )

	default:
		return _strdup("Unknown");
	}
}

/**
 * \brief Determine the address of the modules that we crashed in.
 **/
void GetLogicalAddress(void *addr, char *fModule, DWORD buflen, DWORD *section,
					   DWORD *offset)
{
	MEMORY_BASIC_INFORMATION mbi;
	DWORD hMod;
	PIMAGE_DOS_HEADER pDosHdr;
	PIMAGE_NT_HEADERS pNtHdr;
	PIMAGE_SECTION_HEADER pSection;
	DWORD rva;
	unsigned i;
	DWORD sectionStart;
	DWORD sectionEnd;

	(*section) = 0;
	(*offset) = 0;

	if (!VirtualQuery( addr, &mbi, sizeof(mbi))) return;

	hMod = (DWORD)mbi.AllocationBase;

	if (!GetModuleFileName((HMODULE)hMod, fModule, buflen)) return;

	pDosHdr = (PIMAGE_DOS_HEADER)hMod;

	pNtHdr = (PIMAGE_NT_HEADERS)(hMod + pDosHdr->e_lfanew);

	pSection = IMAGE_FIRST_SECTION(pNtHdr);

	rva = (DWORD)addr - hMod;  

	// Locate the section that holds our address.
	for (i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++, pSection++)
	{
		sectionStart = pSection->VirtualAddress;
		sectionEnd = sectionStart + max(pSection->SizeOfRawData, pSection->Misc.VirtualSize);

		if ((rva >= sectionStart) && (rva <= sectionEnd))
		{
			// Found it.
			(*section) = i+1;
			(*offset) = rva - sectionStart;
			return;
		}
	}
}

void WriteStackDetails(PCONTEXT pContext, int writevars)
{
	DWORD dwMachineType = 0;
	STACKFRAME sf;
	unsigned char symbolBuffer[ sizeof(SYMBOL_INFO) + 1024 ];
	PSYMBOL_INFO pSymbol;
	DWORD64 symDisplacement = 0;
	char fModule[MAX_PATH];
	DWORD section = 0, offset = 0;
	IMAGEHLP_LINE lineInfo = { sizeof(IMAGEHLP_LINE) };
	DWORD dwLineDisplacement;
	IMAGEHLP_STACK_FRAME imagehlpStackFrame;

	fprintf(fh, "\nCall stack:\n");
	fprintf(fh, "Address    Frame    Function                    Source File\n");
	fprintf(fh, "===============================================================\n");

	memset(&sf, 0x00, sizeof(sf));

#ifdef _M_IX86
	sf.AddrPC.Offset = pContext->Eip;
	sf.AddrPC.Mode = AddrModeFlat;
	sf.AddrStack.Offset = pContext->Esp;
	sf.AddrStack.Mode = AddrModeFlat;
	sf.AddrFrame.Offset = pContext->Ebp;

	dwMachineType = IMAGE_FILE_MACHINE_I386;
#endif

	while (1)
	{
		if (!StackWalk( dwMachineType, m_hProcess, GetCurrentThread(), &sf, pContext,
			0, SymFunctionTableAccess, SymGetModuleBase, 0))
			break;

		if ( 0 == sf.AddrFrame.Offset)
			break;

		fprintf(fh, "%08X  %08X  ", sf.AddrPC.Offset, sf.AddrFrame.Offset);

		pSymbol = (PSYMBOL_INFO)symbolBuffer;
		pSymbol->SizeOfStruct = sizeof(symbolBuffer);
		pSymbol->MaxNameLen = 1024;

		symDisplacement = 0;

		if (SymFromAddr(m_hProcess, sf.AddrPC.Offset, &symDisplacement, pSymbol))
		{
			fprintf(fh, "%hs+%I64X", pSymbol->Name, symDisplacement);
		}
		else
		{
			GetLogicalAddress( (PVOID)sf.AddrPC.Offset, fModule, sizeof(fModule), &section, &offset);

			fprintf(fh, "%04X:%08X %s", section, offset, fModule);
		}

		if (SymGetLineFromAddr( m_hProcess, sf.AddrPC.Offset, &dwLineDisplacement, &lineInfo))
		{
			fprintf(fh, "  %s line %u", lineInfo.FileName, lineInfo.LineNumber);
		}
		fprintf(fh, "\n");

		// Consider adding the stuff below at a later date, if it makes sense.
/*
		if (writevars == 1)
		{
			imagehlpStackFrame.InstructionOffset = sf.AddrPC.Offset;
			SymSetContext( m_hProcess, &imagehlpStackFrame, 0 );

			SymEnumSymbols( m_hProcess, 0, 0, EnumerateSymbolsCallback, &sf );

			fprintf(fh, "\n");
		}
		*/
	}
}

/**
 * \brief Dump extra details not included in the minidump to a dump log text
 *        file.
 **/
void GenerateTextDump(PEXCEPTION_POINTERS pExceptionInfo)
{
	EXCEPTION_RECORD *pExceptionRecord = NULL;
	char *temp = NULL;
	char faultingModule[MAX_PATH];
	DWORD section, offset;
	PCONTEXT pCtx = NULL;
	CONTEXT trashableContext;

	fh = fopen("\\xsupui-"BUILDNUM".dmp.log", "w");
	if (fh == NULL)  return;  // Nothing we can do.

	pExceptionRecord = pExceptionInfo->ExceptionRecord;

	temp = GetExceptionString(pExceptionRecord->ExceptionCode);

	fprintf(fh, "Exception code : %08X -- %s\n", pExceptionRecord->ExceptionCode,
		temp);

	free(temp);
	temp = NULL;

	GetLogicalAddress( pExceptionRecord->ExceptionAddress,
		faultingModule, sizeof(faultingModule), &section, &offset);

	fprintf(fh, "Fault Address: %08X %02X:%08X %s\n", pExceptionRecord->ExceptionAddress,
		section, offset, faultingModule);

	pCtx = pExceptionInfo->ContextRecord;

#ifdef _M_IX86   // Only do this if we are running in an X86 machine.
	fprintf(fh, "\nRegisters :\n");
	fprintf(fh, "EAX:%02X\nEBX:%08X\nECX:%08X\nEDX:%08X\nESI:%08X\nEDI:%08X\n",
		pCtx->Eax, pCtx->Ebx, pCtx->Ecx, pCtx->Edx, pCtx->Esi, pCtx->Edi);

	fprintf(fh, "CS:EIP:%04X:%08X\n", pCtx->SegCs, pCtx->Eip);
	fprintf(fh, "SS:ESP:%04X:%08X  EBP:%08X\n", pCtx->SegSs, pCtx->Esp,
		pCtx->Ebp);
	fprintf(fh, "DS:%04X  ES:%04X  FS:%04X  GS:%04X\n", pCtx->SegDs, pCtx->SegEs,
		pCtx->SegFs, pCtx->SegGs);
	fprintf(fh, "Flags:%08X\n", pCtx->EFlags);
#endif

	SymSetOptions( SYMOPT_DEFERRED_LOADS );

	if (!SymInitialize( GetCurrentProcess(), 0, TRUE ))
	{
		fclose(fh);
		return;
	}

	trashableContext = *pCtx;

	WriteStackDetails(&trashableContext, 0 );

	fclose(fh);
}

/**
 * \brief The callback that is processed when we experience a crash.
 *
 * @param[in] pExceptionInfo   Information related to the crash, and used to generate the crash information.
 *
 * \retval LONG  A value that tells the windows handler what to do next.
 **/
LONG WINAPI crash_handler_callback(PEXCEPTION_POINTERS pExceptionInfo)
{
	HANDLE hFile;
	MINIDUMP_EXCEPTION_INFORMATION eInfo;

	// Note: BUILDNUM is a quoted string.
	hFile = CreateFileA( "\\xsupui-"BUILDNUM".dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		m_hProcess = GetCurrentProcess();
		eInfo.ThreadId = GetCurrentThreadId();
		eInfo.ClientPointers = FALSE;
		eInfo.ExceptionPointers = pExceptionInfo;

		GenerateTextDump(pExceptionInfo);

		MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpNormal, &eInfo, NULL, NULL);
		CloseHandle(hFile);
	}

	if (previousFilter)
		return previousFilter( pExceptionInfo );
	else
		return EXCEPTION_CONTINUE_SEARCH;
}

/**
 * \brief Called at the point that we want to start the crash handler.  (Which is probably the first thing
 *        we want to do.)
 **/
void crash_handler_install()
{
	previousFilter = SetUnhandledExceptionFilter(crash_handler_callback);
}
