/*
NAME
    EntryPoint.cpp

DESCRIPTION
    Handle a single entry point for NtTrace

COPYRIGHT
    Copyright (C) 2002,2003 by Roger Orr <rogero@howzatt.demon.co.uk>

    This software is distributed in the hope that it will be useful, but
    without WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    Permission is granted to anyone to make or distribute verbatim
    copies of this software provided that the copyright notice and
    this permission notice are preserved, and that the distributor
    grants the recipient permission for further distribution as permitted
    by this notice.

    Comments and suggestions are always welcome.
    Please report bugs to rogero@howzatt.demon.co.uk.
*/

static char const szRCSID[] = "$Id: EntryPoint.cpp 1442 2014-10-08 21:39:57Z Roger $";

#pragma warning( disable: 4786 ) // identifier was truncated to '255' characters

#include "EntryPoint.h"

#include <windows.h>
#include <string>
#include <vector>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>

#include "SymbolEngine.h"
#include "displayError.h"

#include "TrapNtOpcodes.h"
#include "ShowData.h"

using namespace showData;
using or2::displayError;

namespace
{
   void printStackTrace(std::ostream &os, HANDLE hProcess, HANDLE hThread, CONTEXT const & Context );
}

//////////////////////////////////////////////////////////////////////////
// Module data

extern "C" 
{
    // Function to convert NT status codes to normal NT error codes
#ifdef _M_IX86
    typedef DWORD (NTAPI * PFNRtlNtStatusToDosError)(DWORD);
#elif _M_X64
    typedef DWORD64 (NTAPI * PFNRtlNtStatusToDosError)(DWORD64);
#endif // _M_IX86
}

static PFNRtlNtStatusToDosError RtlNtStatusToDosError =
   (PFNRtlNtStatusToDosError)GetProcAddress( GetModuleHandle("NtDll"), "RtlNtStatusToDosError" );

//////////////////////////////////////////////////////////////////////////
// The various NtDll signatures

#ifdef _M_IX86

// Check for basic NT4/W2K signature...
//  B8 24 00 00 00       mov         eax,24h
//  8D 54 24 04          lea         edx,[esp+4]
//  CD 2E                int         2Eh
//  C2 20 00             ret         20h      // or just 'ret'

static unsigned char const signature1[] =
{MOVdwordEax, 5, LEA, 4, INTn, 2, 0, 0};

// Check for basic W2K3 signature...
//  B8 1E 00 00 00       mov         eax,1Eh
//  BA 00 03 FE 7F       mov         edx,7FFE0300h
//  FF D2                call        edx
//  C2 0C 00             ret         0Ch

static unsigned char const signature2[] =
{ MOVdwordEax, 5, MOVdwordEdx, 5, CallReg, 2, 0, 0};

// Check for basic W2K8/64 32-bit signature...
//  B8 1E 00 00 00       mov         eax,1Eh
//  B9 03 00 00 00       mov         ecx,03h
//  8D 54 24 04          lea         edx,[esp+4]
//  64 FF 15 C0 00 00 00 call        fs:[0c0h]
//  C2 0C 00             ret         0Ch

static unsigned char const signature3[] =
{MOVdwordEax, 5, MOVdwordEcx, 5, LEA, 4, FS, 1, CallReg, 6, 0, 0};

// Check for type-2 W2K8/64 32-bit signature...
//  B8 1E 00 00 00       mov         eax,1Eh
//  33 C9                xor         ecx,ecx
//  8D 54 24 04          lea         edx,[esp+4]
//  64 FF 15 C0 00 00 00 call        fs:[0c0h]
//  C2 0C 00             ret         0Ch

static unsigned char const signature4[] =
{MOVdwordEax, 5, XOR, 2, LEA, 4, FS, 1, CallReg, 6, 0, 0};

static unsigned char const *signatures[] = {
signature1,
signature2,
signature3,
signature4,
};

#elif _M_X64

// Check for W2K8/64 64-bit signature...
//  4c 8b d1             mov         r10,rcx
//  b8 52 00 00 00       mov         eax,0x52
//  0f 05                syscall
//  C3                   ret

static unsigned char const signature1[] =
{0x4c, 3, MOVdwordEax, 5, 0x0f, 2, 0, 0};

static unsigned char const *signatures[] = {
signature1,
};

#endif // _M_IX86

//////////////////////////////////////////////////////////////////////////
// Show the argument for the given process with the specified value.
void Argument::showArgument(std::ostream & os, HANDLE hProcess, ARG argVal, bool returnOk, bool dup) const
{
    // Don't dereference output only arguments on failure
    if ((!returnOk && outputOnly()) || dup)
    {
        switch (argType)
        {
        case argULONG_PTR:
        case argULONG:
        case argULONGLONG:
        case argENUM:
        case argMASK:
        case argBOOLEAN:
        case argACCESS_MASK:
            break;
        default:
            showPointer(os, hProcess, argVal);
            return;
        }
    }

    switch ( argType )
    {
    case argULONG_PTR:
    case argULONGLONG:
        showDword(os, argVal);
        break;

    case argULONG:
        showDword(os, (ULONG)argVal);
        break;

    case argENUM:
        showEnum(os, (ULONG)argVal, argTypeName);
        break;

    case argMASK:
        showMask(os, (ULONG)argVal, argTypeName);
        break;

    case argBOOLEAN:
        showBoolean( os, (BOOLEAN)argVal );
        break;

    case argPOINTER:
        showPointer( os, hProcess, argVal);
        break;

    case argPOBJECT_ATTRIBUTES:
        showObjectAttributes( os, hProcess, (LPVOID)argVal );
        break;

    case argPUNICODE_STRING:
        showUnicodeString( os, hProcess, (PUNICODE_STRING)argVal );
        break;

    case argPHANDLE:
        showPHandle( os, hProcess, argVal);
        break;

    case argPUSHORT:
        showPUshort( os, hProcess, argVal);
        break;

    case argPULONG:
        showPUlong( os, hProcess, argVal);
        break;

    case argACCESS_MASK:
        showAccessMask( os, hProcess, argVal);
        break;

    case argPCLIENT_ID:
        showPClientId( os, hProcess, (PCLIENT_ID)argVal );
        break;

    case argPIO_STATUS_BLOCK:
        showPIoStatus( os, hProcess, (PIO_STATUS_BLOCK)argVal );
        break;

    case argPLARGE_INTEGER:
        showPLargeInteger( os, hProcess, (PLARGE_INTEGER)argVal );
        break;

    case argPLPC_MESSAGE:
        showPLpcMessage( os, hProcess, (PLPC_MESSAGE)argVal);
        break;

    case argPFILE_BASIC_INFORMATION:
        showPFileBasicInfo( os, hProcess, (PFILE_BASIC_INFORMATION)argVal );
        break;

    case argPFILE_NETWORK_OPEN_INFORMATION:
        showPFileNetworkInfo( os, hProcess, (PFILE_NETWORK_OPEN_INFORMATION)argVal );
        break;
    }
}

//////////////////////////////////////////////////////////////////////////
// true if argument is output-only
bool Argument::outputOnly() const
{
   return (attributes & (argIN|argOUT)) == argOUT;
}

//////////////////////////////////////////////////////////////////////////
NtCall EntryPoint::insertBrkpt( HANDLE hProcess, unsigned char *address, unsigned int offset, unsigned char *setssn )
{
    // (The post-call code is at address + offset)
    // Looks like:-
    //  C2 20 00           ret         20h
    //  8B C0              mov         eax,eax  // optional padding
    //
    // or:-
    //  C3                 ret         
    //
    // or:-
    //  E9 XX XX XX XX     jmp         commonExit

    NtCall nt;

    unsigned char instruction[8];

    if (! ReadProcessMemory( hProcess, address + offset, instruction, 8, 0))
    {
        std::cerr << "Cannot read instructions for " << name << ": " << displayError() << std::endl; 
        return NtCall();
    }

    switch ( instruction[0] )
    {
    case RETn:
        nt.nArgs = ( instruction[1] + instruction[2] * 256 )/ 4;

        if ( ( instruction[3] == MOVreg ) &&
             ( instruction[4] == 0xc0 ) )
        {
            instruction[3] = instruction[2];
            instruction[2] = instruction[1];
            instruction[1] = instruction[0];
            instruction[0] = BRKPT;

            if (! WriteProcessMemory(hProcess, address + offset, instruction, 4, 0))
            {
                std::cerr << "Cannot write trap for " << name << ": " << displayError() << std::endl;
                return NtCall();
            }
            nt.trapType = NtCall::trapContinue;
        }
        else
        {
            // We must replace the return itself
            instruction[0] = BRKPT;
            if (! WriteProcessMemory(hProcess, address + offset, instruction, 1, 0))
            {
                std::cerr << "Cannot write trap for " << name << ": " << displayError() << std::endl;
                return NtCall();
            }
            nt.trapType = NtCall::trapReturn;
        }
        break;

    case RET:
        nt.nArgs = 0;

        // We must replace the return itself
        instruction[0] = BRKPT;
        if (! WriteProcessMemory(hProcess, address + offset, instruction, 1, 0))
        {
            std::cerr << "Cannot write trap for " << name << ": " << displayError() << std::endl;
            return NtCall();
        }
        nt.trapType = NtCall::trapReturn0;
        break;

    case JMP:
#ifdef _M_IX86
        nt.nArgs = 0; // UNKNOWN!

        // We must replace the jump itself
        instruction[0] = BRKPT;
        if (! WriteProcessMemory(hProcess, address + offset, instruction, 1, 0))
        {
            std::cerr << "Cannot write trap for " << name << ": " << displayError() << std::endl;
            return NtCall();
        }
        nt.trapType = NtCall::trapJump;
        nt.jumpTarget = (DWORD)( *(DWORD*)( &instruction[1] ) + address + offset + 5 );

        // If the target is a return we can work out nArgs
        if (ReadProcessMemory( hProcess, (LPVOID)nt.jumpTarget, instruction, 3, 0))
        {
            if ( instruction[0] == RETn )
            {
                nt.nArgs = *(short*)( &instruction[1] );
            }
            else if ( instruction[0] == RET )
            {
                // ret [no args]
                nt.nArgs = 0;
            }
            else
            {
                std::cerr << "Warning: unknown arg count for " << name << std::endl;
                nt.nArgs = getArgumentCount(); // "Trust me"
            }
        }
        else
        {
            std::cerr << "Warning: can't read target for " << name << " at " << nt.jumpTarget << std::endl;
        }
#else
        std::cerr << "Cannot trap " << name << " - wrong signature ('jmp' 0xE9)" << std::endl;
#endif // _M_IX86
        break;

    default:
        std::cerr << "Cannot trap " << name << " - wrong signature (expecting 'ret' 0xC2/0xC3 or 'jmp' 0xE9, found 0x" << 
            std::hex << std::setw(2) << (int)instruction[0] << std::dec << ")" << std::endl;
        return NtCall();
    }

    // Now we know the actual argument count...
    size_t nKnown( getArgumentCount() );
    if (nt.nArgs > nKnown)
    {
      setArgumentCount(nt.nArgs);
    }
    else if ( nt.nArgs < nKnown )
    {
      if (nt.nArgs > 0)
      {
        size_t nExtra = nKnown - nt.nArgs;
        std::cerr << "Warning: " << nExtra << 
          " spurious argument" << ( nExtra == 1 ? "" : "s" ) << " for " << name << std::endl;
      }
    }
    setAddress( address + offset );

    if (setssn)
    {
      instruction[0] = BRKPT;
      instruction[1] = NOP;
      instruction[2] = NOP;
      instruction[3] = NOP;
      instruction[4] = NOP;

      if (! WriteProcessMemory(hProcess, setssn, instruction, 5, 0))
      {
        std::cerr << "Cannot write trap for " << name << ": " << displayError() << std::endl;
        return NtCall();
      }
      setPreSave(setssn);
    }

    nt.entryPoint = this;

    return nt;
}

//////////////////////////////////////////////////////////////////////////
// Attempt to set a trap for the entry point in the target DLL.
NtCall EntryPoint::setNtTrap(HANDLE hProcess, HMODULE hTargetDll, bool bPreTrace, DWORD dllOffset)
{
#ifdef _M_X64
    // We need the pretrace on X64 to save the volatile registers
    bPreTrace = true;
#endif // _M_X64

    unsigned char *address;
    if (dllOffset != 0)
    {
        address = reinterpret_cast<unsigned char *>(hTargetDll) + dllOffset;
    }
    else
    {
        FARPROC pProc = GetProcAddress( hTargetDll, name.c_str() );
        if ( 0 == pProc )
        {
            DWORD errorCode = GetLastError();
            if ( errorCode == ERROR_PROC_NOT_FOUND )
            {
                // Entry points are allowed to be absent!
            }
            else
            {
                std::cerr << "Cannot resolve " << name << ": " << displayError(errorCode) << std::endl;
            }
            return NtCall();
        }
        address = reinterpret_cast<unsigned char *>( pProc );
    }

    unsigned int preamble = 0;
    static unsigned int const MAX_PREAMBLE(32);
    unsigned char instruction[MAX_PREAMBLE];
    if (ReadProcessMemory(hProcess, address, instruction, sizeof( instruction ), 0))
    {
        unsigned char * setssn = 0;
        for (unsigned int idx = 0; idx != sizeof(signatures)/sizeof(signatures[0]); idx++)
        {
           unsigned int offset = 0;
           setssn = 0;
           unsigned char const *pCheck = signatures[idx];
           for (; *pCheck != 0; pCheck += 2)
           {
              if (instruction[offset] == BRKPT)
              {
                 // already pre-trace trapping!
                 preamble = offset;
                 break;
              }
              if (instruction[offset] != pCheck[0])
                 break;
              if (instruction[offset] == MOVdwordEax)
              {
                 setssn = address + offset;
              }
              offset += pCheck[1];
           }
           if (pCheck[0] == 0)
           {
              // Check for possible esp adjustment
              if (instruction[offset] == AddEsp)
              {
                 offset += 3;
              }
              preamble = offset;
              break;
           }
       }
       if ( instruction[preamble] == BRKPT )
       {
           std::cerr << "Already trapping: " << name << std::endl;
       }
       else if (preamble == 0)
       {
           std::cerr << "Cannot trap " << name << " - wrong signature" << std::endl;
       }
       else if (setssn == 0)
       {
           std::cerr << "Cannot trap " << name << " - cannot find system service number" << std::endl;
       }
       else
       {
           memcpy(&ssn, instruction + (setssn - address) + 1, sizeof(ssn));
           return insertBrkpt(hProcess, address, preamble, bPreTrace ? setssn : 0);
       }
    }
    else
    {
        std::cerr << "Cannot trap " << name << " - unable to read memory: " << displayError() << std::endl;
    }

    return NtCall();
}


//////////////////////////////////////////////////////////////////////////
// Attempt to set a trap for the entry point in the target DLL.
bool EntryPoint::clearNtTrap(HANDLE hProcess, NtCall const & ntCall) const
{
   if (preSave)
   {
      char instruction[1 + 4];
      instruction[0] = MOVdwordEax;
      memcpy(instruction+1, &ssn, sizeof(ssn));
      if (! WriteProcessMemory(hProcess, preSave, instruction, 5, 0))
      {
        std::cerr << "Cannot clear trap for " << name << ": " << displayError() << std::endl;
        return false;
      }
   }

   if (targetAddress)
   {
      char instruction[4];
      int len(0);

      switch (ntCall.trapType)
      {
      case NtCall::trapContinue:
        instruction[0] = RETn;
        instruction[1] = static_cast<unsigned char>(ntCall.nArgs * 4);
        instruction[2] = static_cast<unsigned char>(ntCall.nArgs * 4 / 256);
        instruction[3] = MOVreg;
        len = 4;
        break;

      case NtCall::trapReturn:
         instruction[0] = RETn;
         len = 1;
         break;

      case NtCall::trapReturn0:
         instruction[0] = RET;
         len = 1;
         break;

      case NtCall::trapJump:
         instruction[0] = JMP;
         len = 1;
         break;
      }
      if (len)
      {
         if (! WriteProcessMemory(hProcess, targetAddress, instruction, len, 0))
         {
           std::cerr << "Cannot clear trap for " << name << ": " << displayError() << std::endl;
           return false;
         }
      }
   }
   return true;
}

//////////////////////////////////////////////////////////////////////////
// Eg "NtOpenFile", 2, "POBJECT_ATTRIBUTES", "ObjectAttributes", argIN
void EntryPoint::setArgument( int argNum, std::string const & argType,
                  std::string const & variableName, ArgAttributes attributes, Typedefs const & typedefs )
{
   static const struct
   {
      ArgType eArgType;
      char const *argTypeName;
   } argTypes[] =
   {
      { argULONG_PTR, "ULONG_PTR" },
      { argULONG_PTR, "LONG_PTR" },
      { argULONG_PTR, "UINT_PTR" },
      { argULONG_PTR, "INT_PTR" },
      { argULONG_PTR, "HANDLE" },
      { argULONG_PTR, "SIZE_T" },
      { argULONG_PTR, "NTSTATUS" },

      { argULONG, "ULONG" },
      { argULONG, "long" },
      { argULONG, "LONG" },
      { argULONG, "UINT" },
      { argULONG, "int" },
      { argULONG, "INT" },
      { argULONG, "DWORD" },
      { argULONG, "WORD" },
      { argULONG, "USHORT" },
      { argULONG, "WCHAR" },

      { argULONG, "LCID" },

      { argULONGLONG, "ULONGLONG" },

      { argENUM, "ALPC_MESSAGE_INFORMATION_CLASS" },
      { argENUM, "ALPC_PORT_INFORMATION_CLASS" },
      { argENUM, "ATOM_INFORMATION_CLASS" },
      { argENUM, "AUDIT_EVENT_TYPE" },
      { argENUM, "DEBUGOBJECTINFOCLASS" },
      { argENUM, "DEBUG_CONTROL_CODE" },
      { argENUM, "DEVICE_POWER_STATE" },
      { argENUM, "ENLISTMENT_INFORMATION_CLASS" },
      { argENUM, "EVENT_INFORMATION_CLASS" },
      { argENUM, "EVENT_TYPE" },
      { argENUM, "FILE_INFORMATION_CLASS" },
      { argENUM, "FS_INFORMATION_CLASS" },
      { argENUM, "HARDERROR_RESPONSE_OPTION" },
      { argENUM, "IO_SESSION_STATE" },
      { argENUM, "JOB_INFORMATION_CLASS" },
      { argENUM, "KEY_INFORMATION_CLASS" },
      { argENUM, "KEY_SET_INFORMATION_CLASS" },
      { argENUM, "KEY_VALUE_INFORMATION_CLASS" },
      { argENUM, "KPROFILE_SOURCE" },
      { argENUM, "KTMOBJECT_TYPE" },
      { argENUM, "MEMORY_INFORMATION_CLASS" },
      { argENUM, "MUTANT_INFORMATION_CLASS" },
      { argENUM, "OBJECT_INFORMATION_CLASS" },
      { argENUM, "PORT_INFORMATION_CLASS" },
      { argENUM, "POWER_ACTION" },
      { argENUM, "POWER_INFORMATION_LEVEL" },
      { argENUM, "PROCESSINFOCLASS" },
      { argENUM, "RESOURCEMANAGER_INFORMATION_CLASS" },
      { argENUM, "SECTION_INFORMATION_CLASS" },
      { argENUM, "SECTION_INHERIT" },
      { argENUM, "SHUTDOWN_ACTION" },
      { argENUM, "SEMAPHORE_INFORMATION_CLASS" },
      { argENUM, "SYSTEM_POWER_STATE" },
      { argENUM, "SYSTEM_INFORMATION_CLASS" },
      { argENUM, "THREADINFOCLASS" },
      { argENUM, "TIMER_INFORMATION_CLASS" },
      { argENUM, "TIMER_TYPE" },
      { argENUM, "TOKEN_INFORMATION_CLASS" },
      { argENUM, "TOKEN_TYPE" },
      { argENUM, "TRANSACTION_INFORMATION_CLASS" },
      { argENUM, "TRANSACTIONMANAGER_INFORMATION_CLASS" },
      { argENUM, "WAIT_TYPE" },
      { argENUM, "WORKERFACTORYINFOCLASS" },

      { argMASK, "NOTIFICATION_MASK" },
      { argMASK, "SECURITY_INFORMATION" },

      { argBOOLEAN, "BOOLEAN" },
      { argBOOLEAN, "BOOL" },

      { argACCESS_MASK, "ACCESS_MASK" },

      { argPOINTER, "PVOID" },
      { argPOINTER, "PBYTE" },
      { argPOINTER, "PSTR" },
      { argPOINTER, "PUCHAR" },
      { argPOINTER, "PWSTR" },

      { argPHANDLE, "PHANDLE" },
      { argPHANDLE, "PPVOID" },
      { argPHANDLE, "PSIZE_T" },

      { argPUSHORT, "PUSHORT" },
      { argPUSHORT, "PWORD" },

      { argPULONG, "PULONG" },
      { argPULONG, "PDWORD" },
      { argPULONG, "PINT" },
      { argPULONG, "PUINT" },
      { argPULONG, "PULONGLONG" },
      { argPULONG, "PULONG_PTR" },
      { argPULONG, "PBOOLEAN" },
      { argPULONG, "PLCID" },

      { argPCLIENT_ID, "PCLIENT_ID" },
      { argPFILE_BASIC_INFORMATION, "PFILE_BASIC_INFORMATION" },
      { argPFILE_NETWORK_OPEN_INFORMATION, "PFILE_NETWORK_OPEN_INFORMATION" },
      { argPIO_STATUS_BLOCK, "PIO_STATUS_BLOCK" },
      { argPLARGE_INTEGER, "PLARGE_INTEGER" },
      { argPLPC_MESSAGE, "PLPC_MESSAGE" },
      { argPOBJECT_ATTRIBUTES, "POBJECT_ATTRIBUTES" },
      { argPUNICODE_STRING, "PUNICODE_STRING" },
   };

   Typedefs::const_iterator it = typedefs.find(argType);
   std::string const alias = (it == typedefs.end() ? std::string() : it->second);

   ArgType eArgType = argULONG_PTR;
   bool found( false );
   for ( int idx = 0; idx != sizeof( argTypes ) / sizeof( argTypes[0] ); ++idx )
   {
      if ((argType == argTypes[ idx ].argTypeName) || (alias == argTypes[ idx ].argTypeName))
      {
         found = true;
         eArgType = argTypes[ idx ].eArgType;
         break;
      }
   }

   if ( ! found )
   {
      std::cerr << "Assuming ULONG for: " << argType << std::endl;
   }

   if ( argNum >= (int)arguments.size() )
      arguments.resize( argNum + 1 );
   arguments[ argNum ] = Argument( eArgType, argType, variableName, attributes );
}

//////////////////////////////////////////////////////////////////////////
// Eg 2nd stack argument for "POINT"
void EntryPoint::setDummyArgument(int argNum, ArgAttributes attributes)
{
   if ( argNum >= (int)arguments.size() )
      arguments.resize( argNum + 1 );
   arguments[ argNum ] = Argument( argULONG_PTR, std::string(), std::string(), attributes );
   arguments[ argNum ].dummy = true;
}

//////////////////////////////////////////////////////////////////////////
// Eg "NTSTATUS"
void EntryPoint::setReturnType(std::string const & typeName, Typedefs const & typedefs)
{
   static const struct
   {
      ReturnType eRetType;
      char const *retTypeName;
   } retTypes[] =
   {
      { retNTSTATUS, "NTSTATUS" },

      { retVOID, "VOID" },

      { retPVOID, "PVOID" },
      { retPVOID, "HANDLE" },

      { retULONG, "BOOL" },
      { retULONG, "DWORD" },
      { retULONG, "UINT" },
      { retULONG, "ULONG" },
      { retULONG, "INT" },
      { retULONG, "int" },
      { retULONG, "LONG" },
      { retULONG, "long" },
      { retULONG, "WORD" },

      { retULONG_PTR, "UINT_PTR" },
      { retULONG_PTR, "INT_PTR" },
      { retULONG_PTR, "ULONG_PTR" },
      { retULONG_PTR, "LONG_PTR" },
   };

   Typedefs::const_iterator it = typedefs.find(typeName);
   std::string const alias = (it == typedefs.end() ? std::string() : it->second);
   ReturnType eRetType = retNTSTATUS;
   bool found( false );
   for ( int idx = 0; idx != sizeof( retTypes ) / sizeof( retTypes[0] ); ++idx )
   {
      if ((typeName == retTypes[ idx ].retTypeName) || (alias == retTypes[ idx ].retTypeName ))
      {
         found = true;
         eRetType = retTypes[ idx ].eRetType;
         break;
      }
   }

   if ( ! found )
   {
      if (typeName.find('*') != std::string::npos)
      {
         retType = retPVOID;
      }
      else
      {
         std::cerr << "Assuming NTSTATUS return for: " << typeName << std::endl;
      }
   }

   retType = eRetType;
   retTypeName = typeName;
}

//////////////////////////////////////////////////////////////////////////
// Handle pre-saving register arguments before the fast call

void EntryPoint::doPreSave(HANDLE hProcess, HANDLE hThread, CONTEXT const & Context)
{
#ifdef _M_X64
  CONTEXT newContext = Context;
  newContext.ContextFlags = CONTEXT_INTEGER;
  newContext.Rax = ssn;
  if ( ! SetThreadContext( hThread, &newContext ) )
  {
    std::cerr << "Can't set thread context: " << displayError() << std::endl;
  }
  ULONG_PTR saveArea[4];
  saveArea[0] = Context.Rcx;
  saveArea[1] = Context.Rdx;
  saveArea[2] = Context.R8;
  saveArea[3] = Context.R9;
  PVOID saveTarget = (PVOID)(Context.Rsp + sizeof(ULONG_PTR));
  if (!WriteProcessMemory(hProcess, saveTarget, saveArea, sizeof(saveArea), 0))
  {
    std::cerr << "Can't save register values at " << saveTarget << ": " << displayError() << std::endl;
  }
#else
  // Unused arguments
  hProcess;
  CONTEXT newContext = Context;
  newContext.ContextFlags = CONTEXT_INTEGER;
  newContext.Eax = ssn;
  if ( ! SetThreadContext( hThread, &newContext ) )
  {
    std::cerr << "Can't set thread context: " << displayError() << std::endl;
  }
#endif // _M_X64
}

//////////////////////////////////////////////////////////////////////////
// Trace a call to the entry point
void EntryPoint::trace( std::ostream & os, HANDLE hProcess, HANDLE hThread, CONTEXT const & Context, bool bNames, bool bStackTrace, bool before) const
{
#ifdef _M_IX86
  DWORD stack = Context.Esp;
  DWORD returnCode = Context.Eax;
#elif _M_X64
  DWORD64 stack = Context.Rsp;
  DWORD64 returnCode = Context.Rax;
#endif
  os << getName() << "(";

  bool success(false);

  switch (retType)
  {
    case retNTSTATUS: success = (returnCode == ERROR_SUCCESS); break;
    case retULONG: success = ((ULONG)returnCode != 0); break;
    case retULONG_PTR: success = (returnCode != 0); break;
    default: break;
  }

  if (getArgumentCount())
  {
    std::set<Argument::ARG> args;
    std::vector<Argument::ARG> argv(getArgumentCount());
    if (!ReadProcessMemory(hProcess,
      (LPVOID)(stack + sizeof(Argument::ARG)),
      &argv[0], sizeof(sizeof(Argument::ARG)) * argv.size(), 0))
    {
      os << "read error: " << GetLastError() << std::endl;
      return;
    }

    for ( size_t i = 0, end = getArgumentCount(); i < end; i++ )
    {
      Argument::ARG argVal = argv[i];
      Argument const &argument = getArgument(i);
      os << &", "[i==0];
      if ( bNames && !argument.name.empty())
        os << argument.name << "=";
      bool const dup = ! args.insert(argVal).second;
      argument.showArgument(os, hProcess, argVal, !before && success, dup);
    }
  }

  if (before)
  {
    os << " ) ...";
  }
  else
  {
    os << " ) => ";
    showDword( os, returnCode );

    if (returnCode != 0 && retType == retNTSTATUS)
    {
      showWinError ( os, static_cast<HRESULT>(RtlNtStatusToDosError( returnCode )) );
    }
    if ( bStackTrace )
    {
      os << std::endl;
      printStackTrace( os, hProcess, hThread, Context);
    }
  }
  os << std::endl;
}

//////////////////////////////////////////////////////////////////////////
// Sort by category and then by name
bool EntryPoint::operator<( EntryPoint const & rhs ) const
{
   if ( category < rhs.category )
      return true;
   if ( category == rhs.category )
      return name < rhs.name;
   return false;
}

//////////////////////////////////////////////////////////////////////////
// Print a stack trace for the supplied thread and process
//static
void EntryPoint::stackTrace(std::ostream & os, HANDLE hProcess, HANDLE hThread)
{
   CONTEXT Context;
   Context.ContextFlags = CONTEXT_FULL;
   if ( ! GetThreadContext( hThread, &Context ) )
   {
      os << "Can't get thread context: " << displayError() << std::endl;
   }
   else
   {
      printStackTrace( os, hProcess, hThread, Context);
   }
}

namespace
{
   void printStackTrace(std::ostream &os, HANDLE hProcess, HANDLE hThread, CONTEXT const & Context )
   {
static std::map<HANDLE, or2::SymbolEngine *> engines;

       or2::SymbolEngine *pEngine = engines[hProcess];
       if (pEngine == 0 )
       {
          pEngine = new or2::SymbolEngine(hProcess);
          // Ensure ntdll.dll is in place (early on dbghelp doesn't find it)
          pEngine->LoadModule64(0, "ntdll.dll", 0, (DWORD64)GetModuleHandle("ntdll.dll"), 0);
          engines[hProcess] = pEngine;
       }
       pEngine->StackTrace( hThread, Context, os );
   }

   bool isBlankOrComment( std::string const & lbuf )
   {
      return ( ( lbuf.length() == 0 ) ||
               ( lbuf[0] == ';' ) ||
               ( lbuf[0] == '#' ) );
   }
}

// Process a typedef line (starting after the typedef)
void processTypedef(std::string lbuf, EntryPoint::Typedefs & typedefs)
{
   std::string::size_type space = lbuf.find(' ');
   if (space == std::string::npos)
   {
      std::cerr << "invalid typedef '" << lbuf << "'" << std::endl;
      return;
   }
   if (lbuf.rfind(';') == lbuf.size() - 1)
   {
      lbuf.resize(lbuf.size() - 1);
   }

   typedefs[lbuf.substr(space + 1)] = lbuf.substr(0, space);
}

//////////////////////////////////////////////////////////////////////////
//
// Read set of entry points from a configuration file with lines like:-
// NTSTATUS
// NTAPI
// NtXxx(
//   IN DWORD fred
// );
//
// or (simple) typedefs
// typedef HANDLE HKL;
//
//static
bool EntryPoint::readEntryPoints( std::istream & cfgFile, EntryPointSet & entryPoints, Typedefs & typedefs, std::string &target )
{
    typedef std::map< std::string, EntryPoint * > FunctionMap;
    FunctionMap existingFunctions; // For handling duplicate definitions
    std::string sCategory("Other");
    std::string lastTypeName;
    std::string lbuf;
    int argNum = -1;
    EntryPoint* currEntryPoint = 0;
    int lineNo = 0;
    while ( std::getline( cfgFile, lbuf ) )
    {
        lineNo++;
        if ( isBlankOrComment( lbuf ) )
        {
            continue; // Skip blank lines and comments
        }
        if ( lbuf.substr(0,2) == "//" )
        {
           size_t const len( lbuf.size() );
           if ( ( len > 4 ) && 
                ( lbuf[2] == '[' ) &&
                ( lbuf[ len - 1 ] == ']' ) )
           {
              std::string const argument = lbuf.substr(3, len - 4);
              if (argument.find('.') != std::string::npos)
              {
                 target = argument;
              }
              else
              {
                 sCategory = argument;
              }
           }
           continue; // Skip this comment
        }
        if ( argNum == -1 )
        {
            if (lbuf == "NTAPI" || lbuf == "WINUSERAPI" || lbuf == "WINAPI")
            {
                // ignore API function decorations
                continue;
            }
            if ((lbuf.find(' ') == strlen("typedef")) && (memcmp(&lbuf[0], "typedef", 7) == 0))
            {
                processTypedef(lbuf.substr(strlen("typedef") + 1), typedefs);
                continue;
            }
            std::string::size_type idx = lbuf.find( '(' );
            if ( idx == std::string::npos )
            {
                // only a name
                if (lastTypeName.empty())
                {
                    lastTypeName = lbuf;
                }
                else
                {
                    std::cerr << "unexpected input '" << lbuf << "'" << std::endl;
                }
                continue;
            }
            else
            {
                // a function prototype
                if (lbuf.find(')', idx) == std::string::npos )
                {
                    // Arguments to follow
                    argNum = 0;
                }
                lbuf = lbuf.substr(0,idx);
            }
            // just a raw name....
            std::istringstream is( lbuf );
            std::string functionName;
            is >> functionName;

            // Add the new entry point (or update the existing one)
            currEntryPoint = existingFunctions[ functionName ];
            if ( currEntryPoint == 0 )
            {
               currEntryPoint = const_cast<EntryPoint *>(&*entryPoints.insert( EntryPoint( functionName, sCategory ) ).first); // std::set constness
               existingFunctions[ functionName ] = currEntryPoint;
            }
            if (!lastTypeName.empty())
            {
               currEntryPoint->setReturnType(lastTypeName, typedefs);
               lastTypeName.resize(0);
            }
        }
        else
        {
            bool bEnded = false;
            std::string::size_type const closing_bracket = lbuf.find(')');
            if ( closing_bracket != std::string::npos )
            {
                bEnded = true;
                lbuf.resize( closing_bracket );
            }
            std::string::size_type idx = lbuf.find( ',' );
            if ( idx != std::string::npos )
            {
                lbuf.resize( idx );
            }
            std::istringstream is( lbuf );
            int attributes = argNONE;
            std::string typeName;
            std::string variableName;

            do
            {
                is >> typeName;
                if ( typeName == "IN" || typeName == "__in" || typeName == "_In_" )
                    attributes |= argIN;
                else if ( typeName == "__in_opt" || typeName == "_In_opt_" )
                    attributes |= argIN | argOPTIONAL;
                else if ( typeName == "OUT" || typeName == "__out" || typeName == "_Out_" )
                    attributes |= argOUT;
                else if ( typeName == "__out_opt" || typeName == "_Out_opt_" )
                    attributes |= argOUT | argOPTIONAL;
                else if ( typeName == "__inout" || typeName == "_Inout_" )
                    attributes |= argIN | argOUT;
                else if ( typeName == "__inout_opt" || typeName == "_Inout_opt_" )
                    attributes |= argIN | argOUT | argOPTIONAL;
                else if ( typeName == "const" || typeName == "CONST" )
                    attributes |= argCONST;
                else if ( typeName == "__reserved" || typeName == "_Reserved_" )
                    ;
                else
                    break;
            } while ( is );
            if ( bEnded && ( typeName.length() == 0 || (argNum == 0 && typeName == "VOID")))
            {
               // ignore single trailing ")" or "VOID"
            }
            else
            {
               if ( !is )
               {
                   std::cerr << "Syntax error at line " << lineNo << " reading config file" << std::endl;
                   return false;
               }
               is >> variableName;
               std::string optional;
               is >> optional;
               if ( optional == "OPTIONAL" )
                   attributes |= argOPTIONAL;

               currEntryPoint->setArgument( argNum, typeName, variableName, (ArgAttributes)attributes, typedefs );
#ifdef _M_IX86
               if (currEntryPoint->getArgument(argNum).argType == argULONGLONG)
               {
                   // Insert an unnamed dummy argument for the high dword
                   argNum++;
                   currEntryPoint->setDummyArgument( argNum, (ArgAttributes)attributes );
               }
#endif // _M_IX86
               argNum++;
            }
            if ( bEnded )
            {
		// Done with this function
                argNum = -1;
            }
        }
    }
    return true;
}

//////////////////////////////////////////////////////////////////////////
// Print self to a stream, as a function prototype
void EntryPoint::writeExport( std::ostream & os ) const
{
    if ( targetAddress == 0 )
       os << "//inactive\n";
    os << "//[" << (disabled ? "-" : "") << category << "]\n";
    if (retType == retNTSTATUS)
    {
        os << "NTSTATUS";
    }
    else
    {
        os << retTypeName;
    }
    os << "\nNTAPI\n" << name << "(\n";
    for ( size_t i = 0, end = arguments.size(); i != end; i++ )
    {
        Argument const & argument = arguments[i];
        if (argument.dummy)
        {
           continue;
        }
        os << "    ";
        if ( argument.attributes & argIN )
            os << "IN ";
        if ( argument.attributes & argOUT )
            os << "OUT ";
        if ( argument.attributes & argCONST )
            os << "const ";
        os << argument.argTypeName << " " << argument.name;
        if ( argument.attributes & argOPTIONAL )
            os << " OPTIONAL";
        if ( i != end - 1 )
            os << ",";
        os << "\n";
    }
    os << "    );" << std::endl;
}
