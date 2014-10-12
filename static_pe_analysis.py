'''
    Static analysis framework for 32 bit Windows binaries (Portable Executables).
    Performs PE header analysis, entropy analysis, plaintext extraction
    and then disassembles the binary, finds procedures and builds the call
    graph. You WILL have to add your own analysis functions. Currently, the only
    analysis is that the five procedures with the most incoming calls are (partially)
    printed. PE header analysis, entropy analysis, plaintext extraction is generic and should
    work fine on any 32 bit Windows binary

    This framework was built to analyse a few particular binaries and worked very well for that.
    I have removed the functionality specific to those binaries. Not much testing has been performed
    outside those binaries, but it SHOULD (...) work on any Win 32 binary.

    Dependencies:
    distorm3 disassembler library, https://code.google.com/p/distorm/
    pefile PE header library, https://code.google.com/p/pefile/
'''

__author__ = '0xeffab1e'

import sys
import math
import hashlib
import re
import ntpath

# Not part of standard library. See README!
import pefile
import distorm3

from code_container import CodeContainer



def H(data):
    if not data:
        return 0

    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)

    return entropy

def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def H_chunks(data):
    return [H(x) for x in chunks(data,2044)]

def tohex(val, nbits=32):
  return hex((val + (1 << nbits)) % (1 << nbits)).strip('L')

def do_static_analysis(buf):

    interesting=['MoveFileExW','WriteFile','ReadFile','DeleteFileW','SetFileTime','CreateProcessW','ReadProcessMemory',
                 'Thread32Next','CreateThread','GetCommandLineA','SetConsoleCtrlHandler','GetTimeFormatA',
                 'GetDateFormatA','FlushFileBuffers','GetProcessHeap','FindClose','FindFirstFileW','FindNextFileW',
                 'GetFile','GetVolumeInformationW','MapViewOfFile','GetDisk','GetDriveTypeW','CreateEventA',
                 'CreateNamedPipeA','CreatePipe','ChangeNotification','Path',' GetOEMCP','GetVersion']

    dangerous=['SetFileTime','Write','ReadFile','GetModule','GetVolume','ProcessMemory','OpenProcess','OpenThread',
           'SuspendThread','SetThreadContext','Thread32Next',
           'Thread32First','TerminateProcess','TerminateThread','CreateToolhelp32Snapshot',
           'DeviceIoControl','GetDiskFreeSpace','GetFileSize','LoadLibrary','VirtualAlloc ','CreateRemoteThread',
           'CreateUserThread']


    pe = pefile.PE(data=buf)

    imagebase = pe.OPTIONAL_HEADER.ImageBase
    codebase = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.BaseOfCode
    database = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.BaseOfData
    entrypoint = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    sizeofcode=pe.OPTIONAL_HEADER.SizeOfCode


    print "\nImage base: %s Code base: %s Entry point: %s Size of code: %s\n" % \
          (hex(imagebase),hex(codebase),hex(entrypoint),sizeofcode)

    fmtstr="{:<12}{:<12}{:<12}{:<12}{:<12}{:<12}{:<12}{:<12}"
    print fmtstr.format('Section', 'V address', 'V size', 'R size','Contains','Max entr','Min entr','Avg entr')
    for section in pe.sections:
        sec_type=""
        if section.IMAGE_SCN_CNT_CODE:
            sec_type+='Code '
        if section.IMAGE_SCN_MEM_EXECUTE:
            sec_type+='EX '
        if section.IMAGE_SCN_CNT_INITIALIZED_DATA:
            sec_type+='IData '
        if section.IMAGE_SCN_CNT_UNINITIALIZED_DATA:
            sec_type+='UIData '
        if section.IMAGE_SCN_MEM_READ:
            sec_type+='R'
        if section.IMAGE_SCN_MEM_WRITE:
            sec_type+='W '

        H_list=H_chunks(buf[section.VirtualAddress:section.VirtualAddress+section.SizeOfRawData])

        if len(H_list) > 0:
            H_avg="%.2f" % (sum(H_list)/len(H_list))
            H_max="%.2f"% max(H_list)
            H_min="%.2f"% min(H_list)
        else:
            H_avg='--'
            H_max='--'
            H_min='--'

        pargs=(section.Name.strip("\x00"),
        hex(section.VirtualAddress),
        hex(section.Misc_VirtualSize),
        section.SizeOfRawData,sec_type,H_max,H_min,H_avg)

        print fmtstr.format(*pargs)

        # Prints entropy table
        #print '\n'
        #for h in H_list:
        #    sys.stdout.write(str(h)+';')
        #print '\n'

    print '\nIMPORTS'
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print 'Import:',entry.dll

        for imp in sorted(entry.imports):
            if imp.name:
                impname=imp.name.strip()
                for sdll in dangerous:
                    if impname.upper().find(sdll.upper())>=0:
                        print 'Dangerous imported function:', hex(imp.address), impname

        for imp in sorted(entry.imports):
            if imp.name:
                impname=imp.name.strip()
                for sdll in interesting:
                    if impname.upper().find(sdll.upper())>=0:
                        print 'Interesting imported function:', hex(imp.address), impname


    print '\n'

def print_file_info(name,buf):

    print '\nFile name: %s Size: %d bytes' % (name,len(buf))
    print 'SHA-1: %s' % hashlib.sha1(buf).hexdigest()
    print 'MD5: %s' % hashlib.md5(buf).hexdigest()

def plaintext_extraction(buf):

    max_lines_of_plaintext=5

    print '----Plaintext found in binary (4 or more printable unicode chars in sequence.----'
    print '(only prints five first strings found. Change function plaintext_extraction to see more.)\n'

    regexp='([ -~]\x00[ -~]\x00[ -~]\x00([ -~]\x00)*)'
    p=re.compile(regexp)
    results=p.findall(buf)
    for str,foo in results[:min(max_lines_of_plaintext,len(results))]:
        print str.decode('utf-16')

    print '---------- End of plaintext extraction -------------------------------\n'

def dissasemble_and_analyze(buf):

    print 'Disassembling binary'
    pe = pefile.PE(data=buf)

    imagebase = pe.OPTIONAL_HEADER.ImageBase
    codebase = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.BaseOfCode
    sizeofcode=pe.OPTIONAL_HEADER.SizeOfCode

    code_buf=buf[codebase-imagebase:codebase-imagebase+sizeofcode]
    dis_asm2 = distorm3.Decompose(codebase,code_buf, distorm3.Decode32Bits)
    cc=CodeContainer(dis_asm2,imagebase,codebase,sizeofcode,buf)

    print 'Analyzing procedure calls'
    cc.analyze_proc_calls()
    print 'Building procedures'
    cc.build_procs()
    print 'Perfoming analysis'
    cc.perform_analysis()

    # Code container now contains a functions/procs with cross references.
    # You need to add your own code to "perform_analysis" function.
    # Currently, it only list the five procs with most incoming calls.


def analyze_one_file(filename):
    f = open(filename,'r+b')
    buf=f.read()
    f.close()
    print_file_info(filename,buf)
    do_static_analysis(buf)
    plaintext_extraction(buf)
    dissasemble_and_analyze(buf)


if __name__ == '__main__':

    if len(sys.argv) != 2:
        print 'Usage: \npython %s <windows binary file>' % ntpath.basename(sys.argv[0])
        exit(0)

    analyze_one_file(sys.argv[1])










