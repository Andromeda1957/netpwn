#!/usr/bin/python
"""Opcode table."""

from termcolor import colored


def list_opcodes():
    """List Opcodes."""
    print colored('x86 Opcodes', 'green')
    print colored(
        '''00 ADD   01 ADD   02 ADD   03 ADD   04 ADD'''
        '''   05 ADD   06 PUSH   07 POP''', 'green')
    print colored(
        '''08 OR    09 OR    0A OR    0B OR    0C OR'''
        '''    0D OR    0E PUSH   0F TWOBYTE''', 'green')
    print colored(
        '''10 ADC   11 ADC   12 ADC   13 ADC   14 ADC'''
        '''   15 ADC   16 PUSH   17 POP''', 'green')
    print colored(
        '''18 SBB   19 SBB   1A SBB   1B SBB   1C SBB'''
        '''   1D SBB   1E PUSH   1F POP''', 'green')
    print colored(
        '''20 AND   21 AND   22 AND   23 AND   24 AND'''
        '''   25 AND   26 ES:    27 DAA''', 'green')
    print colored(
        '''28 SUB   29 SUB   2A SUB   2B SUB   2C SUB'''
        '''   2D SUB   2E CS:    2F DAS''', 'green')
    print colored(
        '''30 XOR   31 XOR   32 XOR   33 XOR   34 XOR'''
        '''   35 XOR   36 Ss:    37 AAA''', 'green')
    print colored(
        '''38 CMP   39 CMP   3A CMP   3B CMP   3C CMP'''
        '''   3D CMP   3E DS:    3F AAS''', 'green')
    print colored(
        '''40 INC   41 INC   42 INC   43 INC   44 INC'''
        '''   45 INC   46 INC    47 INC''', 'green')
    print colored(
        '''48 DEC   49 DEC   4A DEC   4B DEC   4C DEC'''
        '''   4D DEC   4E DEC    4F DEC''', 'green')
    print colored(
        '''50 PUSH  51 PUSH  52 PUSH  53 PUSH  54 PUSH'''
        '''  55 PUSH  56 PUSH   57 PUSH''', 'green')
    print colored(
        '''58 POP   59 POP   5A POP   5A POP   5B POP'''
        '''   5C POP   5D POP    5E POP''', 'green')
    print colored(
        '''5F POP   60 PUSHA 61 POPA  62 BOUND 63 ARPL'''
        '''  64 ES:   65 GS:    66 OPSIZE:''', 'green')
    print colored(
        '''68 PUSH  69 IMUL  6A PUSH  6B IMUL  6C INSB'''
        '''  6D INSW  6E OUTSB  6F OUTSW''', 'green')
    print colored(
        '''70 JO    71 JNO   72 JB    73 JNB   74 JZ'''
        '''    75 JNZ   76 JBE    77 JA''', 'green')
    print colored(
        '''78 JS    79 JNS   7A JP    7B JNP   7C JNP'''
        '''   7D JNL   7E JLE    7F JNLE''', 'green')
    print colored(
        '''80 ADD   81 ADD   82 SUB   83 SUB   84 TEST'''
        '''  85 TEST  86 XCHG   87 XCHG''', 'green')
    print colored(
        '''88 MOV   89 MOV   8A MOV   8B MOV   8C MOV'''
        '''   8D LEA   8E MOV    8F POP''', 'green')
    print colored(
        '''90 NOP   91 XCHG  92 XCHG  93 XCHG  94 XCHG'''
        '''  95 XCHG  96 XCHG   97 XCHG''', 'green')
    print colored(
        '''98 CBW   99 CWD   9A CALL  9B WAIT  9C PUSHF'''
        ''' 9D POPF  9E SAHF   9F LAHF''', 'green')
    print colored(
        '''A0 MOV   A1 MOV   A2 MOV   A3 MOV   A4 MOVSB'''
        ''' A5 MOVSW A6 CMPSB  A7 CMPSW''', 'green')
    print colored(
        '''A8 TEST  A9 TEST  AA STOSB AB STOSW AC LODSB'''
        ''' AD LODSW AE SCASB  AF SCASW''', 'green')
    print colored(
        '''B0 MOV   B1 MOV   B2 MOV   B3 MOV   B4 MOV'''
        '''   B5 MOV   B6 MOV    B7 MOV''', 'green')
    print colored(
        '''B8 MOV   B9 MOV   BA MOV   BB MOV   BC MOV'''
        '''   BD MOV   BE MOV    BF MOV''', 'green')
    print colored(
        '''C0 #2    C1 #2    C2 RETN  C3 RETN  C4 LES'''
        '''   C5 LDS   C6 MOV    C7 MOV''', 'green')
    print colored(
        '''C8 ENTER C9 LEAVE CA RETF  CB RETF  CC INT3'''
        '''  CD INT   CE INTO   CF IRET''', 'green')
    print colored(
        '''D0 #2    D1 #2    D2 #2    D3 #2    D4 AAM '''
        '''  D5 AAD   D6 SALC   D7 XLAT''', 'green')
    print colored(
        '''D8 ESC   D9 ESC   DA ESC   DB ESC   DC ESC'''
        '''   DD ESC   DE ESC    DF ESC''', 'green')
    print colored(
        '''E1 LOOPZ E2 LOOP  E3 JCXZ  E4 IN    E5 IN'''
        '''    E6 OUT   E7 OUT    E8 CALL''', 'green')
    print colored(
        '''E9 JMP   EA JMP   EB JMP   EC IN    ED IN'''
        '''    EE OUT   EF OUT    F0 LOCK:''', 'green')
    print colored(
        '''F1 INT1  F2 REPNE F3 REP:  F4 HLT   F5 CMC'''
        '''   F6 #3    F7 #3     F8 CLC''', 'green')
    print colored(
        '''F9 STC   FA CLI   FB STI   FC CLD   FD STD'''
        '''   FE #4    FF #5''', 'green')
