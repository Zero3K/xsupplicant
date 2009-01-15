/**
 * Trap crashes in Windows, and create a minidump that can be used to chase the issue down.
 *
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file crash_handler.c
 *
 * \author chris@open1x.org
 **/

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <dbghelp.h>

#include "crashdump.h"

#pragma comment(linker, "/defaultlib:dbghelp.lib")

LPTOP_LEVEL_EXCEPTION_FILTER previousFilter = NULL;
HANDLE m_hProcess;
FILE *fh = NULL;
char *dumploc = NULL;

typedef enum   // Stolen from CVCONST.H in the DIA 2.0 SDK
{
    btNoType = 0,
    btVoid = 1,
    btChar = 2,
    btWChar = 3,
    btInt = 6,
    btUInt = 7,
    btFloat = 8,
    btBCD = 9,
    btBool = 10,
    btLong = 13,
    btULong = 14,
    btCurrency = 25,
    btDate = 26,
    btVariant = 27,
    btComplex = 28,
    btBit = 29,
    btBSTR = 30,
    btHresult = 31
} BasicType;

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
	HMODULE hMod;
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

	hMod = (HMODULE)mbi.AllocationBase;

	if (!GetModuleFileName(hMod, fModule, buflen)) return;

	pDosHdr = (PIMAGE_DOS_HEADER)mbi.AllocationBase;

	pNtHdr = (PIMAGE_NT_HEADERS)(hMod + pDosHdr->e_lfanew);

	pSection = IMAGE_FIRST_SECTION(pNtHdr);

	rva = (DWORD)addr - (DWORD)mbi.AllocationBase;  

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

/*    struct FINDCHILDREN : TI_FINDCHILDREN_PARAMS
    {
        ULONG   MoreChildIds[1024];
        FINDCHILDREN(){Count = sizeof(MoreChildIds) / sizeof(MoreChildIds[0]);}
    } children;
*/

char *FormatOutputValue(   char * pszCurrBuffer,
                           BasicType basicType,
                           DWORD64 length,
                           PVOID pAddress )
{
    // Format appropriately (assuming it's a 1, 2, or 4 bytes (!!!)
    if ( length == 1 )
        pszCurrBuffer += sprintf( pszCurrBuffer, " = %X", *(PBYTE)pAddress );
    else if ( length == 2 )
        pszCurrBuffer += sprintf( pszCurrBuffer, " = %X", *(PWORD)pAddress );
    else if ( length == 4 )
    {
        if ( basicType == btFloat )
        {
            pszCurrBuffer += sprintf(pszCurrBuffer," = %f", *(PFLOAT)pAddress);
        }
        else if ( basicType == btChar )
        {
            if ( !IsBadStringPtr( *(PSTR*)pAddress, 32) )
            {
                pszCurrBuffer += sprintf( pszCurrBuffer, " = \"%.31s\"",
                                            *(PDWORD)pAddress );
            }
            else
                pszCurrBuffer += sprintf( pszCurrBuffer, " = %X",
                                            *(PDWORD)pAddress );
        }
        else
            pszCurrBuffer += sprintf(pszCurrBuffer," = %X", *(PDWORD)pAddress);
    }
    else if ( length == 8 )
    {
        if ( basicType == btFloat )
        {
            pszCurrBuffer += sprintf( pszCurrBuffer, " = %lf",
                                        *(double *)pAddress );
        }
        else
            pszCurrBuffer += sprintf( pszCurrBuffer, " = %I64X",
                                        *(DWORD64*)pAddress );
    }

    return pszCurrBuffer;
}

BasicType GetBasicType( DWORD typeIndex, DWORD64 modBase )
{
    BasicType basicType;
    DWORD typeId;

    if ( SymGetTypeInfo( m_hProcess, modBase, typeIndex,
                        TI_GET_BASETYPE, &basicType ) )
    {
        return basicType;
    }

    // Get the real "TypeId" of the child.  We need this for the
    // SymGetTypeInfo( TI_GET_TYPEID ) call below.
    if (SymGetTypeInfo(m_hProcess,modBase, typeIndex, TI_GET_TYPEID, &typeId))
    {
        if ( SymGetTypeInfo( m_hProcess, modBase, typeId, TI_GET_BASETYPE,
                            &basicType ) )
        {
            return basicType;
        }
    }

    return btNoType;
}

//////////////////////////////////////////////////////////////////////////////
// If it's a user defined type (UDT), recurse through its members until we're
// at fundamental types.  When he hit fundamental types, return
// bHandled = false, so that FormatSymbolValue() will format them.
//////////////////////////////////////////////////////////////////////////////
char * DumpTypeIndex(
        char * pszCurrBuffer,
        DWORD64 modBase,
        DWORD dwTypeIndex,
        unsigned nestingLevel,
        DWORD_PTR offset,
        BOOL *bHandled )
{

    WCHAR * pwszTypeName;
    DWORD dwChildrenCount = 0;
	TI_FINDCHILDREN_PARAMS children;
	unsigned i, j;
    BOOL bHandled2;
    DWORD typeId;
    ULONG64 length;
	DWORD_PTR dwFinalOffset;
	BasicType basicType;

    bHandled = 0;

    // Get the name of the symbol.  This will either be a Type name (if a UDT),
    // or the structure member name.
    if ( SymGetTypeInfo( m_hProcess, modBase, dwTypeIndex, TI_GET_SYMNAME,
                        &pwszTypeName ) )
    {
        pszCurrBuffer += sprintf( pszCurrBuffer, " %ls", pwszTypeName );
        LocalFree( pwszTypeName );
    }

    // Determine how many children this type has.
    SymGetTypeInfo( m_hProcess, modBase, dwTypeIndex, TI_GET_CHILDRENCOUNT,
                    &dwChildrenCount );

    if ( !dwChildrenCount )     // If no children, we're done
        return pszCurrBuffer;

    // Prepare to get an array of "TypeIds", representing each of the children.
    // SymGetTypeInfo(TI_FINDCHILDREN) expects more memory than just a
    // TI_FINDCHILDREN_PARAMS struct has.  Use derivation to accomplish this.
    children.Count = dwChildrenCount;
    children.Start= 0;

    // Get the array of TypeIds, one for each child type
    if ( !SymGetTypeInfo( m_hProcess, modBase, dwTypeIndex, TI_FINDCHILDREN,
                            &children ) )
    {
        return pszCurrBuffer;
    }

    // Append a line feed
    pszCurrBuffer += sprintf( pszCurrBuffer, "\r\n" );

    // Iterate through each of the children
    for ( i = 0; i < dwChildrenCount; i++ )
    {
        // Add appropriate indentation level (since this routine is recursive)
        for ( j = 0; j <= nestingLevel+1; j++ )
            pszCurrBuffer += sprintf( pszCurrBuffer, "\t" );

        // Recurse for each of the child types
        pszCurrBuffer = DumpTypeIndex( pszCurrBuffer, modBase,
                                        children.ChildId[i], nestingLevel+1,
                                        offset, &bHandled2 );

        // If the child wasn't a UDT, format it appropriately
        if ( !bHandled2 )
        {
            // Get the offset of the child member, relative to its parent
            DWORD dwMemberOffset;
            SymGetTypeInfo( m_hProcess, modBase, children.ChildId[i],
                            TI_GET_OFFSET, &dwMemberOffset );

            // Get the real "TypeId" of the child.  We need this for the
            // SymGetTypeInfo( TI_GET_TYPEID ) call below.
            SymGetTypeInfo( m_hProcess, modBase, children.ChildId[i],
                            TI_GET_TYPEID, &typeId );

            // Get the size of the child member
            SymGetTypeInfo(m_hProcess, modBase, typeId, TI_GET_LENGTH,&length);

            // Calculate the address of the member
            dwFinalOffset = offset + dwMemberOffset;

            basicType = GetBasicType(children.ChildId[i], modBase );

            pszCurrBuffer = FormatOutputValue( pszCurrBuffer, basicType,
                                                length, (PVOID)dwFinalOffset ); 

            pszCurrBuffer += sprintf( pszCurrBuffer, "\r\n" );
        }
    }

    (*bHandled) = 1;
    return pszCurrBuffer;
}

//////////////////////////////////////////////////////////////////////////////
// Given a SYMBOL_INFO representing a particular variable, displays its
// contents.  If it's a user defined type, display the members and their
// values.
//////////////////////////////////////////////////////////////////////////////
BOOL FormatSymbolValue(
            PSYMBOL_INFO pSym,
            STACKFRAME * sf,
            char * pszBuffer,
            unsigned cbBuffer )
{
    char * pszCurrBuffer = pszBuffer;
    DWORD_PTR pVariable = 0;    // Will point to the variable's data in memory
	BOOL bHandled;
	BasicType basicType;

    // Indicate if the variable is a local or parameter
    if ( pSym->Flags & IMAGEHLP_SYMBOL_INFO_PARAMETER )
        pszCurrBuffer += sprintf( pszCurrBuffer, "Parameter " );
    else if ( pSym->Flags & IMAGEHLP_SYMBOL_INFO_LOCAL )
        pszCurrBuffer += sprintf( pszCurrBuffer, "Local " );

    // If it's a function, don't do anything.
    if ( pSym->Tag == 5 )   // SymTagFunction from CVCONST.H from the DIA SDK
        return 0;

    // Emit the variable name
    pszCurrBuffer += sprintf( pszCurrBuffer, "\'%s\'", pSym->Name );

    if ( pSym->Flags & IMAGEHLP_SYMBOL_INFO_REGRELATIVE )
    {
        // if ( pSym->Register == 8 )   // EBP is the value 8 (in DBGHELP 5.1)
        {                               //  This may change!!!
            pVariable = sf->AddrFrame.Offset;
            pVariable += (DWORD_PTR)pSym->Address;
        }
        // else
        //  return false;
    }
    else if ( pSym->Flags & IMAGEHLP_SYMBOL_INFO_REGISTER )
    {
        return 0;   // Don't try to report register variable
    }
    else
    {
        pVariable = (DWORD_PTR)pSym->Address;   // It must be a global variable
    }

    // Determine if the variable is a user defined type (UDT).  IF so, bHandled
    // will return true.
    pszCurrBuffer = DumpTypeIndex(pszCurrBuffer,pSym->ModBase, pSym->TypeIndex,
                                    0, pVariable, &bHandled );

    if ( !bHandled )
    {
        // The symbol wasn't a UDT, so do basic, stupid formatting of the
        // variable.  Based on the size, we're assuming it's a char, WORD, or
        // DWORD.
        basicType = GetBasicType( pSym->TypeIndex, pSym->ModBase );
        
        pszCurrBuffer = FormatOutputValue(pszCurrBuffer, basicType, pSym->Size,
                                            (PVOID)pVariable ); 
    }


    return 1;
}

BOOL CALLBACK
EnumerateSymbolsCallback(
    PSYMBOL_INFO  pSymInfo,
    ULONG         SymbolSize,
    PVOID         UserContext )
{

    char szBuffer[2048];

    __try
    {
        if ( FormatSymbolValue( pSymInfo, (STACKFRAME*)UserContext,
                                szBuffer, sizeof(szBuffer) ) )  
            fprintf(fh, "\t%s\r\n", szBuffer );
    }
    __except( 1 )
    {
        fprintf(fh, "punting on symbol %s\r\n", pSymInfo->Name );
    }

    return TRUE;
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
			GetLogicalAddress( (void *)sf.AddrPC.Offset, fModule, sizeof(fModule), &section, &offset);

			fprintf(fh, "%04X:%08X %s", section, offset, fModule);
		}

		if (SymGetLineFromAddr( m_hProcess, sf.AddrPC.Offset, &dwLineDisplacement, &lineInfo))
		{
			fprintf(fh, "  %s line %u", lineInfo.FileName, lineInfo.LineNumber);
		}
		fprintf(fh, "\n");

		// Consider adding the stuff below at a later date, if it makes sense.
		if (writevars == 1)
		{
			imagehlpStackFrame.InstructionOffset = sf.AddrPC.Offset;
			SymSetContext( m_hProcess, &imagehlpStackFrame, 0 );

			SymEnumSymbols( m_hProcess, 0, 0, EnumerateSymbolsCallback, &sf );

			fprintf(fh, "\n");
		}
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

	temp = (char *)malloc(strlen(dumploc)+10);
	if (temp == NULL) return;   // ACK!  Can't do anything!
	strcpy(temp, dumploc);
	strcat(temp, ".log");

	fh = fopen(temp, "w");
	if (fh == NULL)
	{
		free(temp);
		return;  // Nothing we can do.
	}

	free(temp);
	temp = NULL;

	pExceptionRecord = pExceptionInfo->ExceptionRecord;

	temp = GetExceptionString(pExceptionRecord->ExceptionCode);

	fprintf(fh, "Exception code : %08X -- %s\n", pExceptionRecord->ExceptionCode,
		temp);

	free(temp);
	temp = NULL;

	GetLogicalAddress( pExceptionRecord->ExceptionAddress,
		faultingModule, sizeof(faultingModule), &section, &offset);

	fprintf(fh, "Fault Address: %02X:%08X %s\n", section, offset, faultingModule);

	pCtx = pExceptionInfo->ContextRecord;

#ifdef _M_IX86   // Only do this if we are running in an X86 machine.
	fprintf(fh, "\nRegisters :\n");

	fprintf(fh, "EAX:%08X\n", pCtx->Eax);
	fprintf(fh, "EBX:%08X\n", pCtx->Ebx);
	fprintf(fh, "ECX:%08X\n", pCtx->Ecx);
	fprintf(fh, "EDX:%08X\n", pCtx->Edx);
	fprintf(fh, "ESI:%08X\n", pCtx->Esi);
	fprintf(fh, "EDI:%08X\n", pCtx->Edi);

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

    #ifdef _M_IX86  // X86 Only!

    fprintf(fh, "========================\r\n");
    fprintf(fh, "Local Variables And Parameters\r\n");

    trashableContext = *pCtx;
    WriteStackDetails( &trashableContext, 1 );

#if 0
    fprintf(fh, "========================\r\n");
    fprintf(fh, "Global Variables\r\n");

    SymEnumSymbols( GetCurrentProcess(),
                    (DWORD64)GetModuleHandle(faultingModule),
                    0, EnumerateSymbolsCallback, 0 );
#endif
    #endif      // X86 Only!

    SymCleanup( GetCurrentProcess() );

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

	if (pExceptionInfo == NULL) return EXCEPTION_CONTINUE_SEARCH;

	// Note: BUILDNUM is a quoted string.
	hFile = CreateFileA( dumploc, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		m_hProcess = GetCurrentProcess();
		eInfo.ThreadId = GetCurrentThreadId();
		eInfo.ClientPointers = FALSE;
		eInfo.ExceptionPointers = pExceptionInfo;

		GenerateTextDump(pExceptionInfo);

		MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpNormal, &eInfo, NULL, NULL);
	}

	CloseHandle(hFile);

	crashdump_gather_files();

	if (previousFilter)
		return previousFilter( pExceptionInfo );
	else
		return EXCEPTION_CONTINUE_SEARCH;
}

/**
 * \brief Called at the point that we want to start the crash handler.  (Which is probably the first thing
 *        we want to do.)
 **/
void crash_handler_install(char *dumpname)
{
	if (dumploc != NULL) free(dumploc);

	dumploc = _strdup(dumpname);
	previousFilter = SetUnhandledExceptionFilter(crash_handler_callback);
}

/**
 * \brief Clean up any memory the crash handler was using so that we don't leave droppings.
 **/
void crash_handler_cleanup()
{
	free(dumploc);
}
