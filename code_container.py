

__author__ = '0xeffab1e'

import sys

hex_address_to_index={}

index_to_hex_address={}

total_code_list=[]

def tohex(val, nbits=32):
  return hex((val + (1 << nbits)) % (1 << nbits)).strip('L')

def tobin(n):
    return ''.join(str(1 & int(n) >> i) for i in range(32)[::-1])

def toint(hexstring):
    return int(hexstring,16)

class Procedure:
    def __init__(self,start_hex,code_list,caller_list):

        self.my_code=[]
        self.my_callers=caller_list
        self.id=start_hex
        self.length=0
        self.ending=''
        self.goes_to=''
        self.incoming_jmp=[]
        self.incoming_call=[]
        self.outgoing_jmp=[]
        self.outgoing_call=[]
        self.dead_end_calls=[]
        self.start_addr=''
        self.end_addr=''
        self.absorbed=False
        self.code_segments=[]

        if start_hex in hex_address_to_index:
            i=hex_address_to_index[start_hex]

            while code_list[i].mnemonic != 'RET' and code_list[i].mnemonic != 'JMP':
                sinstr=code_list[i]
                haddr=tohex(sinstr.address).strip('L')
                iaddr=toint(haddr)
                iaddr2=iaddr-0x400000

                i+=1

            self.my_code=code_list[hex_address_to_index[start_hex]:i+1] #max(i+1,start_ix+300)
            self.my_callers=caller_list
            self.id=start_hex
            self.length=len(self.my_code)
            self.start_addr=start_hex
            self.end_addr=tohex(self.my_code[-1].address)

            if code_list[i].mnemonic == 'RET':
                self.ending='RET'
            else:
                self.ending=str(code_list[i].operands[0])

            if self.length>490:
                first=self.my_code[:490]
                last=self.my_code[-490]
                pass
        else:
            self.length=-1

    def set_incoming(self,tot_proc_dict):
        for instr in self.my_code:
            if instr.mnemonic=='CALL' and str(instr.operands[0]) in tot_proc_dict:
                self.outgoing_call.append(str(instr.operands[0]))
                tot_proc_dict[str(instr.operands[0])].add_incoming_call(self.id)
            elif instr.mnemonic=='JMP' and str(instr.operands[0]) in tot_proc_dict:
                if not(toint(self.start_addr) <= toint(str(instr.operands[0])) <= toint(self.end_addr)):
                    self.outgoing_jmp.append(str(instr.operands[0]))
                    tot_proc_dict[str(instr.operands[0])].add_incoming_jmp(self.id)
            elif instr.mnemonic=='JNZ' and str(instr.operands[0]) in tot_proc_dict:
                if not(toint(self.start_addr) <= toint(str(instr.operands[0])) <= toint(self.end_addr)):
                    self.outgoing_jmp.append(str(instr.operands[0]))
                    tot_proc_dict[str(instr.operands[0])].add_incoming_jmp(self.id)
            elif instr.mnemonic=='CALL' or instr.mnemonic=='JMP':
                self.dead_end_calls.append(str(instr.operands[0]))
        pass

    def absorb_segments(self,tot_proc_dict):

        has_absorbed=0
        out_cpy=self.outgoing_jmp
        self.outgoing_jmp=[]
        for jmp in out_cpy:
            if tot_proc_dict[jmp].is_orphan():
                self.code_segments.append(tot_proc_dict[jmp])
                tot_proc_dict[jmp].absorbed=True
                has_absorbed+=1
            else:
                self.outgoing_jmp.append(jmp)
        return has_absorbed


    def add_incoming_jmp(self,from_proc):
        if self.start_addr and self.end_addr and not(toint(self.start_addr) <= toint(from_proc) <= toint(self.end_addr)):
            self.incoming_jmp.append(from_proc)

    def add_incoming_call(self,from_proc):
        self.incoming_call.append(from_proc)

    def is_orphan(self):
        if self.outgoing_jmp==[] and len(self.incoming_jmp)==1 and self.incoming_call==[]:
            return True
        else:
            return False

    def __repr__(self):

        res= self.id+' Calls: '+str(len(self.my_callers))+' Len:'+str(self.length)

        if self.absorbed:
            res=res+' A'
        elif self.incoming_jmp != []:
            res=res+' IJ'
        elif self.incoming_jmp == [] and self.outgoing_jmp == []:
            res=res+' COMP'
        else:
            res=res+' NC'
        return res

    def print_outgoing(self,procedures):

        for x in self.outgoing_call:
            procedures[x].print_code(procedures)
        print '---'
        for x in self.code_segments:
            x.print_outgoing(procedures)

    def print_code(self,procedures):

        for x in self.my_code:
            print tohex(x.address),x

        print '---'
        for x in self.code_segments:
            x.print_code(procedures)

        print '---'
        self.print_outgoing(procedures)


class CodeContainer:
    def __init__(self,code_list,offset,code_start,code_size,whole_bin):
        self.decoded_instr=[]
        self.proc_call_dict={}
        self.procedures={}
        self.proclist=[]
        self.code_list=code_list
        self.offset=tohex(offset)
        self.code_start=tohex(code_start)
        self.code_size=code_size
        self.whole_bin=whole_bin

        for index,item in enumerate(self.code_list):
            hex_address_to_index[tohex(item.address)]=index
            index_to_hex_address[index]=tohex(item.address)
            total_code_list.append((tohex(item.address),index,item))

    def perform_analysis(self):
        most_called_procs=[(repr(x),len(x.incoming_call),x) for x in self.procedures.values() if x.length>0]
        most_called_procs=sorted(most_called_procs,key=lambda x:x[1],reverse=True)
        print '\nMost called procs:\n'
        for rep,calls,proc in most_called_procs[:min(5,len(most_called_procs))]:
            print rep
            for cl in proc.my_code[:min(5,len(proc.my_code))]:
                print '   ',cl
            print '   ......\n'


    def analyze_proc_calls(self):
        for i in self.code_list:
            # op,arg1,arg2,arg3,arg1mod,arg2mod,arg3mod,ilen,comment=self.decode_instr(i)
            if toint(self.code_start) <= i.address <= toint(self.code_start)+self.code_size:
                if i.mnemonic=='CALL' and i.operands[0].type=='Immediate' or \
                    i.mnemonic=='JMP' and i.operands[0].type=='Immediate' or \
                    i.mnemonic=='JNZ' and i.operands[0].type=='Immediate':
                    hex_addr=tohex(i.operands[0].value)
                    htmp=tohex(i.address)
                    if hex_addr in self.proc_call_dict:
                        num_calls,call_list=self.proc_call_dict[hex_addr]
                        call_list.append(tohex(i.address))
                        self.proc_call_dict[hex_addr]=(num_calls+1,call_list)
                    else:
                        self.proc_call_dict[hex_addr]=(1,[tohex(i.address)])


    def build_procs(self):

        for p_addr in self.proc_call_dict:
            self.procedures[p_addr]=Procedure(p_addr,self.code_list,self.proc_call_dict[p_addr][1])


        for proc in self.procedures:
            if self.procedures[proc].ending in self.procedures:
                self.procedures[proc].goes_to=self.procedures[proc].ending

        for proc_id in self.procedures:
            self.procedures[proc_id].set_incoming(self.procedures)

        num_absorbed=1
        tot_absorbed=0
        while num_absorbed>0:
            num_absorbed=0
            for proc_id in self.procedures:
                num_absorbed+=self.procedures[proc_id].absorb_segments(self.procedures)
            tot_absorbed+=num_absorbed

        proclist=sorted(self.proc_call_dict.items(),key=lambda item:item[1][0],reverse=True)
        proclist=proclist[:100]


    def print_byte_string(self,string):
        for x in string:
            sys.stdout.write(tohex((ord(x))))
            sys.stdout.write(' ')
        sys.stdout.write('\n')

    def print_whole_bin_from_hex(self,hexaddr,num_to_print,offset=0):
        byteindex=toint(hexaddr)-toint(self.offset)
        for char in self.whole_bin[byteindex+offset:byteindex+num_to_print+offset]:
            sys.stdout.write(tohex((ord(char))))
            sys.stdout.write(' ')
        print '\n'

    def print_index(self,index):
        i=self.code_list[index]
        print tohex(i.address),i

    def print_from_hex(self,hexaddr,num_to_print,offset=0):

        foo=hex_address_to_index
        if hexaddr not in hex_address_to_index:
            print "Address not found"
        else:
            startix=hex_address_to_index[hexaddr]
            for x in xrange(startix+offset,startix+num_to_print+offset):
                self.print_index(x)


