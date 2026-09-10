from dataclasses import dataclass,field
from sympy import symbols, simplify, solve, Lt, Eq, Gt
from sys import stdout
from utils import *
import time 
from structures import *

class Emulator:
    def __init__(self, arch, mode,debugFile=None, debug=True):
        self.debugFile = debugFile
        self.debug = debug
        self.arch = arch
        self.mem = {} #memory of interest
        self.reg = {} #register
        self.first_push = True
        self.symbolic_count = 0
        self.mode = mode
        # whether the binary being emulated contains a heap 'free' function.
        # True  -> UAF-class workload  (uaf-msp/uaf-arm compare_to_base authority)
        # False -> OVF-class workload  (ovf compare_to_base authority)
        self.hasFree = True
        self.logFile = open('./logs/Emulator.log', 'w')
        conditional_print('---- Emulator.log ----', file=self.logFile, flag=self.debug)
        self.logFile.close()
        conditional_print(f"Setting up emulator of arch={self.arch.type} exploit={mode}", flag=self.debug)
        self.mem_accesses = 0
        self.sr = {'N':0, 'Z':0, 'C':0, 'V':0}
        self.total_instrs = 0

        if self.arch.type == 'elf32-msp430':
            if mode == 'ret-exploit':
                #voi is stack pointer
                self.base= 'x-2' #variable of interest
                self.type = 1 # type --> 1:mem, 0:reg
                self.size = 2
                self.reg['r1'] = self.base    
            elif mode == 'rda':
                # set stack pointer
                f = open("./objs/.sp", "r")
                sp_val = f.read()[:-1]
                f.close()
                if len(sp_val) > 0:
                    self.reg['r1'] = str(int(sp_val,16))
                
            elif mode == 'call-exploit':
                #voi is the call reg
                self.base= 'x' #
                self.type = 1 # type --> 1:mem, 0:reg
                self.size = 2
                self.reg['r1'] = self.base  # start off with sp as base... this will change
            else:
                # others?
                conditional_print("todo", flag=self.debug)
        else: #arm mode
            if mode == 'rda':
                # set sp/lr init values
                f = open("./objs/.sp", "r")
                sp_val = f.read()[:-1]
                f.close()
                if len(sp_val) > 0:
                    self.reg['sp'] = str(int(sp_val,16))
                # print(f"Set SP as {self.reg['sp']}")
                else:
                    #voi is stack pointer
                    self.base= 'x' 
                    self.type = 1 # type --> 1:mem, 0:reg
                    self.size = 4
                    self.reg['sp'] = self.base 
                self.reg['lr'] = '0xfeffffff';

            else: #if mode == 'ret-exploit':
                # for now the inputs are in the global data...

                #read .data.objs to get the sizes of data objects
                # iterate through .data to assign objects
                f = open('./objs/.data.objs', 'r')
                objs = []
                for line in f:
                    objs.append(line[:-1].split(' ')) #[addr, size(in hex)]
                f.close()

                f = open('./objs/.data', 'r')
                data_bytes = f.read().replace('\n', '')
                f.close()
                # print(data_bytes)

                # print(f"from '.data'...")
                for base,size in objs:
                    base = int(base,16)
                    size = int(size,16)
                    b = ''
                    for i in range(0, 2*size):
                        b += data_bytes[i]
                    if len(b) > 8:
                        for k in range(0, len(b), 8):
                            word = b[k:k+8]
                            word =  ''.join(reversed([word[j:j+2] for j in range(0, len(word), 2)]))
                            # print(f"setting {hex(base+int(k/2))} to {word} ({len(word)})")
                            self.mem[str(base+int(k/2))] = str(int(word,16))
                    else:
                        # print(f"setting {hex(base)} to {b} ({size})")
                        self.mem[str(base)] = str(int(b,16))
                    data_bytes = data_bytes[size:]    
                # a = input()

                f = open('./objs/.rodata.start')
                rodata_start = f.read().replace('\n', '')
                f.close()

                f = open('./objs/.rodata', 'r')
                conditional_print(f"from '.rodata'...", flag=self.debug)
                rodata_hex = f.read().replace('\n', '')
                f.close()
                b = ''
                if len(rodata_start) > 0:
                    rodata_addr = int(rodata_start,16)
                    for i in range(0, len(rodata_hex)):
                        b += rodata_hex[i]
                        if i % 8 == 7:
                            self.mem[str(rodata_addr)] = b
                            # conditional_print(f"setting {hex(rodata_addr)} to {self.mem[str(rodata_addr)]}", file=self.debugFile, flag=self.debug)
                            rodata_addr += 4
                            b = ''
                    if b != '':
                        # conditional_print(f"setting {hex(rodata_addr)} to {b}", file=self.debugFile, flag=self.debug)
                        self.mem[str(rodata_addr)] = b

                #voi is stack pointer
                self.base= 'x' 
                self.type = 1 # type --> 1:mem, 0:reg
                self.size = 4
                self.reg['sp'] = self.base 
                # print(f"Set sp as {self.base}")
                # a = input()

            # store .words into mem
            f = open("./objs/.words", "r")
            for line in f:
                addr, val = line.split(',')
                self.mem[str(int(addr, 16))] = str(int(val, 16))
            f.close()
            # a = input()

            #read .bss.objs to determine memory addresses to init as 0
            #set as many 0's as specified size
            f = open('./objs/.bss.objs', 'r')
            # print(f"from '.bss'...")
            bss_objs = []
            for line in f:
                bss_objs.append(line[:-1].split(' '))
            f.close()
            for base,size in bss_objs:
                base = int(base,16)
                size = int(size,16)
                # print(f"base: {base}, size: {size}")
                b = '00'*size
                if len(b) > 8:
                    for k in range(0, len(b), 8):
                        word = b[k:k+8]
                        # print(f"setting {hex(base+int(k/2))} to {word} ({len(word)})")
                        self.mem[str(base+int(k/2))] = int(word,16)    
                else:
                    self.mem[str(base)] = str(int(b,16))
                    # print(f"setting {hex(base)} : {self.mem[str(base)]}")
            # a = input()   

    def __repr__(self)-> str:
        string = ''
        
        string += 'Memory of Interest:\n'
        for key in self.mem.keys():
            try:
                string += f"{hex(int(key))} ({key}) : "
            except ValueError:
                string += f"{key} : "
            try:
                string += f"{hex(int(self.mem[key]))} ({self.mem[key]})\n"
            except ValueError:
                string += f"{self.mem[key]}\n"
        string += 'Regs of Interest:\n'
        for key in self.reg.keys():
            try:
                string += f"{key} : {hex(int(self.reg[key]))} ({self.reg[key]})\n"
            except ValueError:
                string += f"{key} : {self.reg[key]}\n"

        return string+'\n\n'

    def set_base(self, base_reg, offset, isWrite):
        if isWrite: # if its a write, base_reg is the input register
            reg_val = self.get_reg(base_reg)
            expr = reg_val
        else:
            #need to set the reg value
            #for ex, if the base is -4(r4), then x = r4-4, offset = -4 and base = r4
            #need to set equiv of this in reg, r4 = x+4
            # print("setting base")
            reg_val = self.get_reg(base_reg)
            if int(offset) > 0:
                # if positive, need to make negative
                # print(f"Evaluating '{reg_val+'+'+offset}'")
                expr = self.evaluate_expression(reg_val+'+'+offset)
            else:
                #need to make positive
                # print(f"Evaluating '{reg_val+offset}'")
                expr = self.evaluate_expression(reg_val+offset)
            #set this mem_addr as the base
        self.base = expr
        # if 'x' in expr:
            # print(f"INITIALIZED BASE: {expr}")
        # else:
            # print(f"INITIALIZED BASE: {hex(int(expr))}")
        # a = input()
        conditional_print(f"INITIALIZED BASE: {base_reg} = {reg_val}", file=self.debugFile, flag=self.debug)

    def get_reg(self, reg):
        if self.arch.type == 'elf32-msp430':
            #renaming for msp430 r10-15
            if reg == 'r10':
                reg_val =  self.reg['ra']
            elif reg == 'r11':
                reg_val = self.reg['rb']
            if reg == 'r12':
                reg_val = self.reg['rc']
            elif reg == 'r13':
                reg_val = self.reg['rd']
            if reg == 'r14':
                reg_val = self.reg['re']
            elif reg == 'r15':
                reg_val = self.reg['rf']
            else:
                reg_val = self.reg[reg]
        else:
            # print(f"Trying to get reg: {reg}")
            reg_val = self.reg[reg]

        if 'x' in reg_val:
            return reg_val

        if '-' in reg_val:
            #take two's compliment
            reg_val =   reg_val.replace('-', '')
            reg_val = str((0xffff ^ int(reg_val)) + 0x1)

        return reg_val

    def get_mem(self, addr):
        try:
            return self.mem[addr]
        except KeyError:
            return None

    def compare_to_base(self, mem_addr):
        if self.mode == 'ret-exploit' or self.mode == 'call-exploit':
            # OVF-class workloads (no 'free' in the binary) use the OVF MSP430
            # authority: a write is valid while accessed_addr <= base.
            if not self.hasFree and self.arch.type == 'elf32-msp430':
                if 'x' in mem_addr:
                    accessed_addr = simplify(mem_addr)
                    base_addr = simplify(self.base)
                    sol = solve(accessed_addr <= base_addr)
                else:
                    sol = True
                return sol
            if 'y' not in mem_addr:
                if 'x' in mem_addr:
                    if self.arch.type == "armv8-m33":
                        accessed_addr = simplify(mem_addr)
                        base_upper = simplify(self.base+"-"+str(self.size)+' + 1') # plus one bc overlap
                        base_lower = simplify(self.base)
                        # print(f"Evluating: {accessed_addr} <= {base_addr}")
                        conditional_print(f"Evluating: {accessed_addr} == {base_lower}",file=self.debugFile, flag=self.debug)
                        eq_sol = accessed_addr == base_lower
                        conditional_print(eq_sol,file=self.debugFile, flag=self.debug)
                        conditional_print(f"Evluating: {accessed_addr} > {base_upper}",file=self.debugFile, flag=self.debug)
                        u_sol = solve(accessed_addr > base_upper)
                        conditional_print(u_sol,file=self.debugFile, flag=self.debug)
                        conditional_print(f"Evluating: {accessed_addr} < {base_lower}",file=self.debugFile, flag=self.debug)
                        l_sol = solve(accessed_addr < base_lower)
                        conditional_print(l_sol,file=self.debugFile, flag=self.debug)
                        violation = u_sol and (l_sol or eq_sol)
                        conditional_print(f"violation = {violation}",file=self.debugFile, flag=self.debug)
                        sol = not violation
                        # print(f'Result: {accessed_addr} <= {base_addr} == {sol}')
                    else:
                        accessed_addr = simplify(mem_addr)
                        base_lower = simplify(self.base) # in msp430 its back the "Upper" has a smaller addr
                        base_upper = simplify(self.base+"-"+str(self.size)+' + 1')
                        # print(f"Evluating: {accessed_addr} <= {base_addr}")
                        conditional_print(f"Evluating: {accessed_addr} == {base_lower}",file=self.debugFile, flag=self.debug)
                        eq_sol = accessed_addr == base_lower
                        conditional_print(eq_sol,file=self.debugFile, flag=self.debug)
                        conditional_print(f"Evluating: {accessed_addr} > {base_lower}",file=self.debugFile, flag=self.debug)
                        u_sol = solve(accessed_addr > base_lower)
                        conditional_print(u_sol,file=self.debugFile, flag=self.debug)
                        conditional_print(f"Evluating: {accessed_addr} < {base_upper}",file=self.debugFile, flag=self.debug)
                        l_sol = solve(accessed_addr < base_upper)
                        conditional_print(l_sol,file=self.debugFile, flag=self.debug)
                        violation = u_sol and (l_sol or eq_sol)
                        conditional_print(f"violation = {violation}",file=self.debugFile, flag=self.debug)
                        sol = not violation
                else:
                    conditional_print("Reached the 'x not in mem_addr' case",file=self.debugFile, flag=self.debug)
                    accessed_addr = simplify(mem_addr)
                    if 'x' in self.base:
                        base_lower = simplify(self.base) # in msp430 its back the "Upper" has a smaller addr
                        base_upper = simplify(self.base+"-"+str(self.size)+' + 1')
                        # print(f"Evluating: {accessed_addr} <= {base_addr}")
                        conditional_print(f"Evluating: {accessed_addr} == {base_lower}",file=self.debugFile, flag=self.debug)
                        eq_sol = accessed_addr == base_lower
                        conditional_print(eq_sol,file=self.debugFile, flag=self.debug)
                        conditional_print(f"Evluating: {accessed_addr} > {base_lower}",file=self.debugFile, flag=self.debug)
                        u_sol = solve(accessed_addr > base_lower)
                        conditional_print(u_sol,file=self.debugFile, flag=self.debug)
                        conditional_print(f"Evluating: {accessed_addr} < {base_upper}",file=self.debugFile, flag=self.debug)
                        l_sol = solve(accessed_addr < base_upper)
                        conditional_print(l_sol,file=self.debugFile, flag=self.debug)
                        violation = u_sol and (l_sol or eq_sol)
                        conditional_print(f"violation = {violation}",file=self.debugFile, flag=self.debug)
                        sol = not violation
                    else: 
                        # we can treat everything as ints
                        accessed_addr = int(mem_addr)
                        base_upper = int(self.base)
                        base_lower = int(self.base)-self.size+1
                        # print(f"base_upper : {base_upper}, base_lower : {base_lower}")
                        conditional_print(f"Evluating: {accessed_addr} == {base_upper}",file=self.debugFile, flag=self.debug)
                        eq_sol =  accessed_addr == base_upper
                        conditional_print(f"Evluating: {accessed_addr} > {base_lower}",file=self.debugFile, flag=self.debug)
                        u_sol =  accessed_addr > base_lower
                        conditional_print(f"Evluating: {accessed_addr} < {base_upper}",file=self.debugFile, flag=self.debug)
                        l_sol =  accessed_addr < base_upper
                        violation = u_sol and (l_sol or eq_sol)
                        conditional_print(f"violation = u_sol and (l_sol or eq_sol) = {u_sol} and ({l_sol} or {eq_sol}) = {violation}",file=self.debugFile, flag=self.debug)
                        sol = not violation
            else:
                sol = True
        else:
            sol = True
        return sol

    def update_sr(self, expr):
        # print("Updating SR")
        try:
            #Symbol is a true int
            # print(f"expr: {expr} {type(expr)}")#, file=self.debugFile, flag=self.debug)
            symb = int(expr)
            # print(f"symb: {symb} {type(expr)}")#, file=self.debugFile, flag=self.debug)
            lt_expr = Lt(symb, 0)
            # print(f"lt_expr: {lt_expr} {type(lt_expr)}")#, file=self.debugFile, flag=self.debug)
            self.sr['N'] = int(bool(lt_expr))
            eq_expr = Eq(symb, 0)
            # print(f"eq_expr: {eq_expr} {type(eq_expr)}")#, file=self.debugFile, flag=self.debug)
            self.sr['Z'] = int(bool(eq_expr))
        except ValueError:
            #Symobl is an expression
            conditional_print(f'Symbol is an expression: {expr}', file=self.debugFile, flag=self.debug)

    def step(self, asm_inst):
        self.total_instrs += 1
        valid = True
        addr = asm_inst.addr
        instr = asm_inst.instr
        aarg = asm_inst.arg
        conditional_print(f"Instruction ({addr}): {instr} {aarg}",file=self.debugFile, flag=self.debug)

        reg_change = False
        mem_change = False

        if self.arch.type == 'armv8-m33':
            if 'cmp' in instr or 'cmn' in instr:
                #determine if cmp to reg or imm
                x, y = aarg.split(', ')
                conditional_print(f"x: {x}",file=self.debugFile, flag=self.debug)
                conditional_print(f"y: {y}",file=self.debugFile, flag=self.debug)
                if 'r' in y:
                    # y is reg
                    for q in (x, y):
                        if q not in self.reg:
                            self.reg[q] = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                    diff = self.evaluate_expression(self.reg[x]+' - '+self.reg[y])           
                else:
                    # y is imm
                    y = y.replace('#','')
                    if x not in self.reg:
                        self.reg[x] = 'y'+str(self.symbolic_count)
                        self.symbolic_count += 1
                    diff = self.evaluate_expression(self.reg[x]+' - '+y)
            
                conditional_print(f"diff: {diff}",file=self.debugFile, flag=self.debug)
                self.update_sr(diff)
                conditional_print(self.sr, file=self.debugFile, flag=self.debug)
                #comparison
                return valid

            if 'bl' in instr and self.arch.instrumentation_handle not in aarg:
                #update lr
                self.reg['lr'] = addr+'+ 4'

            elif instr in self.arch.return_instrs or instr in self.arch.indr_calls or instr in self.arch.call_instrs or instr in self.arch.unconditional_br_instrs or instr in self.arch.conditional_br_instrs:
                # branch instruction so continue
                return valid

            if 'ldr' in instr:
                reg_change = True
                self.mem_accesses += 1
                if 'lsl' in aarg:
                    # special variant of form ldr Rt, [Rn, Rm, LSL #imm]
                    # imm is a shift value on Rm
                    # Rt = mem[Rn + (Rm << imm)]
                    # Shift(x, imm) = x * (2**imm)
                    dest,args = aarg.split(', [')
                    # dest = Rt, args = 'Rn, Rm, LSL #imm]'
                    base, shift_base, shift_val  = args.split(', ')
                    # base = Rn, shift_base = Rm, shift_val = 'LSL #imm]''
                    shift_val =  shift_val.replace('lsl ', '').replace(']', '').replace('#', '')
                    # shift_val == imm
                    offset = self.evaluate_expression(self.reg[shift_base]+' * '+str(2**int(shift_val)))
                else:
                    dest,src = aarg.split(', [')
                    src = src.replace(']','')
                    # print(f"loading value from {src} into {dest}")
                    base,offset = src.split(',')
                    offset = offset.replace('#','')

                if 'pc' in base:
                    base = addr
                    # for pc-relative addressing, need to add 4 and clear bit[1] because .... arm
                    # https://stackoverflow.com/questions/70491482/understanding-cortex-m-assembly-ldr-with-pc-offset
                    mem_addr = self.evaluate_expression(str(int(base,16))+'+'+offset+'+4')
                    # print(f"trying access ... ({hex(int(mem_addr))}) ({type(mem_addr)})")
                    mem_addr = str(int(mem_addr)&(-4))
                    try:
                        self.reg[dest] = self.mem[mem_addr]
                    except KeyError:
                        self.mem[mem_addr] = 'y'+str(self.symbolic_count)
                        self.symbolic_count += 1
                        self.reg[dest] = self.mem[mem_addr]
                else:
                    try:
                        base = self.reg[base]
                    except KeyError:
                        self.reg[base] = 'y'+str(self.symbolic_count)
                        self.symbolic_count += 1
                        base = self.reg[base]

                    # print(f"base: {base} {type(base)}")
                    mem_addr = self.evaluate_expression(base+'+'+offset)
                    try:
                        if 'ldrb' in instr:
                            if 'x' not in mem_addr and 'y' not in mem_addr:
                                byte = int(mem_addr)%4
                                # print(f'byte = {byte};  [2*byte:2*(byte+1)] = [{2*byte}:{2*(byte+1)}]', file=self.debugFile)
                                mem_addr = str(int(mem_addr)-byte)
                                # print(f'mem_addr = {mem_addr}; mem[{mem_addr}] = {(hex(int(self.mem[mem_addr]))[2:])}', file=self.debugFile)
                                val = self.mem[mem_addr]
                                if isinstance(val,int):
                                    hex_val = hex(int(val))[2:]
                                    if len(hex_val) < 8:
                                        # need all 32 bits to do byte access
                                        hex_val = '0'*(8-len(hex_val))+hex_val
                                    byte_val = str(int(hex_val[2*byte:2*(byte+1)],16))
                                    try:
                                        val_str = hex(int(byte_val))
                                    except ValueError:
                                        val_str = byte_val
                                    conditional_print(f"writing {val_str} to {dest}", file=self.debugFile, flag=self.debug)
                                    self.reg[dest] = byte_val
                                else:
                                    self.reg[dest] = val
                                # a = input()
                            else:
                                try:
                                    val_str = hex(int(self.mem[mem_addr]))
                                except ValueError:
                                    val_str = self.mem[mem_addr]
                                # might need to fix
                                self.reg[dest] = self.mem[mem_addr]
                                conditional_print(f"writing val_str into {dest}", file=self.debugFile, flag=self.debug)
                        else:
                            self.reg[dest] = self.mem[mem_addr]
                    except KeyError:
                        # if key error, it is a mem value not defined by .word in the asm file
                        # so we need to add to .mem as symbolic value, then assign value to .reg[dest]
                        # print(f"keyerror at ldr: {addr} --> Dont have mem[{mem_addr}]", file=self.debugFile)
                        # self.mem[mem_addr] = 'y_'+mem_addr+'_'+addr
                        self.mem[mem_addr] = 'y'+str(self.symbolic_count)
                        self.symbolic_count += 1
                        self.reg[dest] = self.mem[mem_addr]
                        # a = input()

                    # print(f"base: {base} {type(base)}")
                    # print(f"offset: {offset}")
                    # print(f"mem_addr: {hex(int(mem_addr))}")
                
            elif 'mov' in instr:
                reg_change = True
                #dest is always register
                #src could be imm or reg
                dest,src = aarg.split(', ')
                if '#' in src:
                    # src is imm
                    self.reg[dest] = src.replace('#','')
                else:
                    #src is another reg
                    try:
                        self.reg[dest] = self.reg[src]
                    except KeyError:
                        self.reg[src] = 'y'+str(self.symbolic_count)
                        self.symbolic_count += 1
                        self.reg[dest] = self.reg[src]


            elif 'str' in instr:
                self.mem_accesses += 1
                mem_change = True
                src,dest = aarg.split(', [')
                dest = dest.replace(']','')
                base,offset = dest.split(',')
                offset = offset.replace('#','')
                try:
                    base = self.reg[base]
                except KeyError:
                    self.reg[base] = 'y'+str(self.symbolic_count)
                    self.symbolic_count += 1
                    base = self.reg[base]

                # print(f"base: {base} {type(base)}")
                mem_addr = self.evaluate_expression(base+'+'+offset)

                if 'strb' in instr:
                    if 'x' not in mem_addr and 'y' not in mem_addr and 'y' not in self.reg[src]:
                        byte = int(mem_addr)%4
                        # print(f'byte = {byte}')
                        mem_addr = str(int(mem_addr)-byte)
                        src_val = hex(int(self.reg[src]))[2:]
                        try:
                            mem_val = hex(int(self.mem[mem_addr]))[2:]
                            if len(mem_val) < 8:
                                # need all 32 bits to do byte access
                                mem_val = '0'*(8-len(mem_val))+mem_val
                            if byte == 0:
                                new_val = src_val + mem_val[2:]
                            elif byte == 4:
                                new_val = mem_val[:6] + src_val
                            else:
                                new_val = mem_val[:2*byte] + src_val + mem_val[2*byte+1:]
                            # convert to int first since in hex form
                            self.mem[mem_addr] = str(int(new_val, 16))
                        except KeyError:
                            self.mem[mem_addr] = self.reg[src]
                            new_val = self.reg[src]
                        try:
                            val_str = hex(int(new_val))
                        except ValueError:
                            val_str = new_val
                        try:
                            mem_addr_str = hex(int(mem_addr))
                        except ValueError:
                            mem_addr_str = mem_addr
                        conditional_print(f'STORING {val_str} to {mem_addr_str}', file=self.debugFile, flag=self.debug)
                    else:
                        try:
                            val_str = hex(int(self.reg[src]))
                        except ValueError:
                            val_str = self.reg[src]
                        try:
                            mem_addr_str = hex(int(mem_addr))
                        except ValueError:
                            mem_addr_str = mem_addr
                        # might need to fix
                        self.mem[mem_addr] = self.reg[src]
                        conditional_print(f"STORING {val_str} in {mem_addr_str}", file=self.debugFile, flag=self.debug)
                        
                else:
                    try:
                        self.mem[mem_addr] = self.reg[src]
                    except KeyError:
                        self.reg[src] = 'y'+str(self.symbolic_count)
                        self.symbolic_count += 1
                        self.mem[mem_addr] = self.reg[src]

                    conditional_print(f"STORING {self.reg[src]} in {mem_addr}", file=self.debugFile, flag=self.debug)

                valid = self.compare_to_base(mem_addr)

            elif 'sub' in instr:
                reg_change = True
                args = aarg.split(', ')
                if len(args) == 2:
                    # of the form src -= imm
                    src,imm = args
                    imm = imm.replace('#', '')
                    self.reg[src] += '-'+imm

                else:
                    #of the form sub r3, r1, r2 --> r3 = r1-r2
                    dest,src1,src2 = args
                    if src1 not in self.reg.keys():
                        self.reg[src1] = 'y'+str(self.symbolic_count)
                        self.symbolic_count += 1

                    if src2 not in self.reg.keys():
                        self.reg[src2] = 'y'+str(self.symbolic_count)
                        self.symbolic_count += 1

                    diff = self.evaluate_expression(self.reg[src1]+' - ('+self.reg[src2]+')')
                    conditional_print(f"{self.reg[src1]} - ({self.reg[src2]}) = {diff}", file=self.debugFile, flag=self.debug)
                    self.reg[dest] = diff

            elif 'add' in instr:
                reg_change = True
                args = aarg.split(', ')
                if len(args) == 2:
                    # of the form src += imm
                    dest,imm = args
                    imm = imm.replace('#', '')
                    self.reg[dest] = self.reg[dest]+'+'+imm
                else:
                    # len of arg is 3: add dest, src1, src2
                    #src2 could be imm or reg
                    dest,src1,src2 = args
                    if '#' in src2:
                        src2 = src2.replace('#', '')
                        self.reg[dest] = self.reg[src1]+'+'+src2
                    else:
                        self.reg[dest] = self.reg[src1]+'+'+self.reg[src2]

            elif 'push' in instr or ('stmdb' in instr and 'sp!' in aarg):
                reg_change = True
                mem_change = True
                #push is pseudo_instr. of stmdb.w sp!, {regs}
                #so can be written as both

                # of the format push {r1, r2, ..., r8}
                # is pushed onto the stack like:
                # ------------
                # |    r1    |
                # ------------
                # |    r2    |
                # ------------
                # ...
                # ------------
                # |    r8    |
                # ------------
                args = (aarg.replace('{','')).replace('}','')
                args = args.split(', ')
                args.reverse()

                # print(f"First push: {self.first_push}")
                if self.first_push and self.mode != 'rda':
                    # offset = 4*(len(args)-1)
                    self.reg['sp'] = self.base
                    self.first_push = False

                # print(args, self.debugFile)
                mem_addr = []
                for i in range(0, len(args)):
                    a = args[i]
                    # print(f'trying reg[{a}]')
                    try:
                        reg_val = self.reg[a]
                    except KeyError:
                        # reg_val = 'y_'+a+'_'+addr
                        reg_val = 'y'+str(self.symbolic_count)
                        self.reg[a] = reg_val
                        self.symbolic_count += 1
                        conditional_print(f"keyerror at push handled:", file=self.debugFile, flag=self.debug)
                    
                    # print(f"pushing {reg_val} onto mem[{self.reg['sp']}]")
                    self.mem[self.reg['sp']] = reg_val
                    self.mem_accesses += 1
                    mem_addr.append(self.reg['sp'])
                    valid |= self.compare_to_base(self.reg['sp'])
                    self.reg['sp'] = self.evaluate_expression(self.reg['sp']+'- 4')

                # a = input()

            elif 'pop' in instr or ('ldmia' in instr and 'sp!' in aarg):
                reg_change = True
                #pop is pseudo_instr. or ldmia.w sp!, {regs}
                #so can be written as both
                args = (aarg.replace('{','')).replace('}','')
                args = args.split(', ')
                if 'ldmia' in instr:
                    args = args[1:]
                # print(args)
                for a in args:
                    self.mem_accesses += 1
                    sp_val = self.evaluate_expression(self.reg['sp']+'+ 4')
                    try:
                        mem_val = self.mem[sp_val]
                    except KeyError:
                        # mem_val = 'y_'+sp_val+'_'+addr
                        mem_val = 'y'+str(sp_val)
                        self.symbolic_count += 1
                        self.mem[sp_val] = mem_val
                        print(f"keyerror at pop: {addr}", file=self.debugFile)
                        # a = input()

                    self.reg[a] = mem_val
                    self.reg['sp'] = sp_val
                    # conditional_print(f"popping {hex(int(mem_val))} from mem[{hex(int(self.reg['sp']))}] into {a}", file=self.debugFile, flag=self.debug)
                # a = input()

            elif 'ldm' in instr:
                # ldm = load multiple
                if 'ia' in instr:
                    #increase after
                    base,args = aarg.split(', {')
                    args = args.replace('}','')
                    args = args.split(', ')
                    # print(f"base: {base} : {hex(int(self.reg[base]))}")
                    # print(f"args: {args}")
                    for i in range(0, len(args)):
                        self.mem_accesses += 1
                        try:
                            mem_addr = self.evaluate_expression(self.reg[base]+'+'+str(4*i))
                            self.reg[args[i]] = self.mem[mem_addr]
                        except KeyError:
                            # self.mem[mem_addr] = 'y_'+mem_addr+'_'+addr
                            self.mem[mem_addr] = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                            self.reg[args[i]] = self.mem[mem_addr]

            elif 'stm' in instr:
                mem_change = True
                # stm = store multiple
                if 'ia' in instr:
                    #increase after
                    base,args = aarg.split(', {')
                    args = args.replace('}','')
                    args = args.split(', ')
                    # print(f"base: {base} : {self.reg[base]  }")
                    # print(f"args: {args}")
                    for i in range(0, len(args)):
                        self.mem_accesses += 1
                        mem_addr = self.evaluate_expression(self.reg[base]+'+'+str(4*i))
                        # print(f"storing {args[i]}={self.reg[args[i]]} into {mem_addr}")
                        self.mem[mem_addr] = self.reg[args[i]]
                        valid |= self.compare_to_base(mem_addr)
            
            elif 'lsl' in instr:
                reg_change = True
                dest,src,shift = aarg.split(', ')
                if 'y' not in self.reg[src]:
                    old_val = int(self.reg[src])
                    if '#' in shift:
                        shift = shift.replace('#', '')
                        new_val = old_val<< int(shift)
                    else: # shift by reg
                        if 'y' in self.reg[shift]:
                            new_val = str(old_val) + '**' + self.reg[shift]
                        else:
                            new_val = old_val << int(self.reg[shift])
                    conditional_print(f"{dest} = {src} << {shift} = {old_val} << {shift}", file=self.debugFile, flag=self.debug)
                    conditional_print(f"{dest} = {new_val}", file=self.debugFile, flag=self.debug)
                    self.reg[dest] = str(new_val)
                else:
                    self.reg[dest] = self.evaluate_expression(self.reg[src]+'*(2 ** '+str(shift)+')')

            elif 'orr' in instr:
                reg_change = True
                dest,src = aarg.split(', ')

                conditional_print(f"dest = {self.reg[dest]} {'y' in self.reg[dest]}", flag=self.debug)
                conditional_print(f"src = {self.reg[src]} {'y' in self.reg[src]}", flag=self.debug)

                # start = time.perf_counter()
                if 'y' not in self.reg[dest] and 'y' not in self.reg[src]:
                    result = int(self.reg[dest]) | int(self.reg[src])
                    conditional_print(f'{hex(result)} = {hex(int(self.reg[dest]))} | {hex(int(self.reg[src]))}', file=self.debugFile, flag=self.debug)
                    self.reg[dest] = str(result)
                    # print("if")
                else:
                    # print("else")
                    # or using add and mult
                    # self.reg[dest] = self.evaluate_expression('('+self.reg[dest]+'+'+self.reg[src]+')'+'+ ('+self.reg[dest]+'*'+self.reg[src]+')')
                    # might need to do another thing
                    self.reg[dest] = 'y'+str(self.symbolic_count)
                    self.symbolic_count += 1
                stop = time.perf_counter()
                # print(self.reg[dest])
                # print(f"if-else time: {1000*(stop-start)}")
                # a = input()

            elif 'mvn' in instr:
                reg_change = True
                dest,src = aarg.split(', ')
                if 'y' not in self.reg[src]:
                    # print(f'{dest} = ~{src} = {hex(int(self.reg[src]) ^ 0xffffffff)}', file=self.debugFile)
                    self.reg[dest] = str(int(self.reg[src]) ^ 0xffffffff)

            elif 'uxtb' in instr:
                reg_change = True
                dest,src = aarg.split(', ')
                if 'y' not in self.reg[src]:
                    byte_val = self.reg[src]
                    extended_val = '0x000000'+hex(int(byte_val))[2:]
                    conditional_print(f'{dest} = {extended_val} <-- byte extend {byte_val}', file=self.debugFile, flag=self.debug)
                    self.reg[dest] = str(int(extended_val,16))
                else:
                    self.reg[dest] = self.reg[src]

            else:
                self.logFile = open('./logs/Emulator.log', 'a')
                conditional_print(f"INSTRUCTION NOT SUPPORTED --({addr}): {instr} {aarg}", file=self.logFile, flag=self.debug)
                self.logFile.close()
                # a = input()

        elif self.arch.type == 'elf32-msp430':
            arg = aarg.replace('r10', 'ra')
            arg = arg.replace('r11', 'rb')
            arg = arg.replace('r12', 'rc')
            arg = arg.replace('r13', 'rd')
            arg = arg.replace('r14', 're')
            arg = arg.replace('r15', 'rf')

            if 'clr' in instr:
                new_instr = AssemblyInstruction(addr,'mov',f'#0,{aarg}')
                # print(f"remapping {asm_inst} --> {new_instr}")
                # a = input()
                valid = self.step(new_instr)

            if 'rla' in instr:
                new_instr = AssemblyInstruction(addr,'add',f'{aarg},{aarg}')
                # print(f"remapping {asm_inst} --> {new_instr}")
                # a = input()
                valid = self.step(new_instr)

            elif 'call' in instr:
                #call moves sp up the stack
                sp_val = self.evaluate_expression(self.reg['r1']+'- 2')
                self.reg['r1'] = sp_val
                reg_change = True

            elif 'ret' in instr:
                #call moves sp down the stack
                sp_val = self.evaluate_expression(self.reg['r1']+'+ 2')
                self.reg['r1'] = sp_val
                reg_change = True

            elif 'cmp' in instr:
                #determine if cmp to reg or imm
                y,x = arg.split(',')
                conditional_print(f"x: {x}",file=self.debugFile, flag=self.debug)
                conditional_print(f"y: {y}",file=self.debugFile, flag=self.debug)
                # print(f"x : {x}")
                # print(f"y : {y}")
                try:
                    reg_val_1 = self.reg[x]
                except KeyError:
                    reg_val_1 = f'y{self.symbolic_count}'
                    self.reg[x] = reg_val_1
                    self.symbolic_count+=1

                if 'r' in y:
                    # y is reg
                    try:
                        reg_val_2 = self.reg[y]
                    except KeyError:
                        reg_val_2 = f'y{self.symbolic_count}'
                        self.reg[y] = reg_val_2
                        self.symbolic_count+=1

                    diff = self.evaluate_expression(reg_val_1+' - '+reg_val_2)           
                else:
                    # y is imm
                    y = y.replace('#','')
                    diff = self.evaluate_expression(reg_val_1+' - '+y)
            
                conditional_print(f"diff: {diff}",file=self.debugFile, flag=self.debug)
                self.update_sr(diff)
                conditional_print(self.sr, file=self.debugFile, flag=self.debug)
                #comparison
                # return valid

            elif 'mov' in instr:
                src,dest = arg.split(",")
                if '@' in src or '(' in src:
                    self.mem_accesses += 1
                    # src is mem ref
                    conditional_print("src from reg mem ref", file=self.debugFile, flag=self.debug)
                    if '@' in src:
                        idx = '0'
                        b = src.replace('@', '')
                    else:
                        idx,b = src[:-1].split('(')
                        if '-' not in idx:
                            idx = '+'+idx
                    mem_addr = self.evaluate_expression(self.reg[b]+"+"+idx)
                    conditional_print(f"trying to lookup {mem_addr} in mem[]", file=self.debugFile, flag=self.debug)
                    if '.b' in instr:
                        # source is a byte
                        try:
                            src_val = self.mem[mem_addr]
                        except KeyError:
                            conditional_print(f"cant find {mem_addr} in mem[]", file=self.debugFile, flag=self.debug)
                            src_val = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                            self.mem[mem_addr] = src_val
                        conditional_print(f"byte src_val = {src_val}", file=self.debugFile, flag=self.debug)
                    else:
                        # source is a word 
                        mem_addr_upper = self.evaluate_expression(self.reg[b]+idx+'- 1')
                        mem_addr_lower = self.evaluate_expression(self.reg[b]+idx)
                        conditional_print(f"word mem_addr_upper = {mem_addr_upper}", file=self.debugFile, flag=self.debug)
                        conditional_print(f"word mem_addr_lower = {mem_addr_lower}", file=self.debugFile, flag=self.debug)
                        if mem_addr_lower in self.mem.keys() and mem_addr_upper in self.mem.keys():
                            src_val_upper = self.mem[mem_addr_upper]
                            src_val_lower = self.mem[mem_addr_lower]
                            if 'y' not in src_val_lower and 'y' not in src_val_upper:
                                src_val = int(src_val_upper) | int(src_val_lower)
                                conditional_print(f"word src_val = {hex(src_val)}", file=self.debugFile, flag=self.debug)
                                src_val = str(src_val)
                            else:
                                src_val = 'y'+str(self.symbolic_count)
                                self.symbolic_count += 1 
                        else:
                            src_val = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1 

                elif 'r' in src:
                    #reg that isn't a mem ref
                    conditional_print("src from reg", file=self.debugFile, flag=self.debug)
                    try:
                        src_val = self.reg[src]
                    except KeyError:
                        src_val = "y"+str(self.symbolic_count)
                        self.symbolic_count += 1
                        self.reg[src] = src_val
                elif '#' in src:
                    conditional_print("src from imm", file=self.debugFile, flag=self.debug)
                    src_val = src.replace("#", '')
                    if '-' in src_val:
                        src_val = int(src_val) % (2**16)
                        conditional_print(f"src_val = {hex(src_val)}", file=self.debugFile, flag=self.debug)
                        src_val = str(src_val)
                    conditional_print(f"src_val = {src_val}", file=self.debugFile, flag=self.debug)
                elif '&' in src:
                    self.mem_accesses += 1
                    conditional_print("src from fixed mem ref", file=self.debugFile, flag=self.debug)
                    # fixed mem_addr reference --> also in hex
                    mem_addr = str(int(src.replace('&', ' '), 16))
                    try:
                        src_val = self.mem[mem_addr]
                    except KeyError:
                        src_val = 'y'+str(self.symbolic_count)
                        self.symbolic_count += 1
                        self.mem[mem_addr] = src_val

                if '@' in dest or '(' in dest:
                    self.mem_accesses += 1
                    # src is mem ref
                    conditional_print("dest is reg mem ref", file=self.debugFile, flag=self.debug)
                    if '@' in dest:
                        idx = '0'
                        b = dest.replace('@', '')
                    else:
                        idx,b = dest[:-1].split('(')
                        if '-' not in idx:
                            idx = '+'+idx
                        if b not in self.reg.keys():
                            self.reg[b] = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                    conditional_print(f"idx = {idx}, b={self.reg[b]}", file=self.debugFile, flag=self.debug)
                    mem_change = True
                    if '.b' in instr or 'x' in src_val: 
                        # byte operation
                        mem_addr = self.evaluate_expression(self.reg[b]+"+"+idx)
                        self.mem[mem_addr] = src_val
                        conditional_print(f"wrote mem[{mem_addr}] = {src_val}", file=self.debugFile, flag=self.debug)
                        # need to check validity of val is not static 
                        # if 'r' in src:
                        valid = self.compare_to_base(mem_addr)
                    else:
                        # word operation
                        mem_addr_lower = self.evaluate_expression(self.reg[b]+idx)
                        mem_addr_upper = self.evaluate_expression(self.reg[b]+idx+'- 1') # minus is "up" for msp430
                        if 'y' in src_val:
                            src_val_upper = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                            src_val_lower = 'y'+str(self.symbolic_count)
                            self.symbolic_count += 1
                            src_val_uppper_str = src_val_upper
                            src_val_lower_str = src_val_lower
                        else:
                            src_val_upper = str(int(src_val) & 0xff00)
                            src_val_lower = str(int(src_val) & 0x00ff)
                            src_val_uppper_str = hex(int(src_val_upper))
                            src_val_lower_str = hex(int(src_val_lower))
                        
                        self.mem[mem_addr_lower] = src_val_lower
                        self.mem[mem_addr_upper] = src_val_upper
                        
                        conditional_print(f"wrote mem[{mem_addr_lower}] = {src_val_uppper_str}", file=self.debugFile, flag=self.debug)
                        conditional_print(f"wrote mem[{mem_addr_upper}] = {src_val_lower_str}", file=self.debugFile, flag=self.debug)
                        # need to check validity of val is not static 
                        if 'r' in src:
                            valid_lower = self.compare_to_base(mem_addr_lower)
                            valid_upper = self.compare_to_base(mem_addr_upper)
                            valid = (valid_lower and valid_upper)

                        mem_addr = [mem_addr_lower, mem_addr_upper]

                elif 'r' in dest:
                    conditional_print("dest is reg", file=self.debugFile, flag=self.debug)
                    self.reg[dest] = src_val
                    reg_change = True
                    conditional_print(f"wrote {dest} = {src_val}", file=self.debugFile, flag=self.debug)

                elif '&' in dest:
                    self.mem_accesses += 1
                    conditional_print("dest is fixed mem ref", file=self.debugFile, flag=self.debug)
                    mem_addr = str(int(dest.replace('&', ' '), 16))
                    if '.b' in instr:
                        self.mem[mem_addr] = src_val
                        mem_change = True
                        conditional_print(f"wrote mem[{mem_addr}] = {src_val}", file=self.debugFile, flag=self.debug)
                        # need to check validity of val is not static 
                        if 'r' in src:
                            valid = self.compare_to_base(mem_addr)

            elif 'incd' in instr:
                if '(' in arg:
                    idx,b = arg[:-1].split('(')
                    if '-' not in idx:
                        idx = '+'+idx
                    mem_addr = self.evaluate_expression(self.reg[b]+"+"+idx)
                    try:
                        self.mem[mem_addr] = self.mem[mem_addr] + " + 2"
                    except:
                        self.mem[mem_addr] = f'y{self.symbolic_count}'
                        self.mem[mem_addr] = self.mem[mem_addr] + " + 2"
                        self.symbolic_count += 1
                    valid = self.compare_to_base(mem_addr)
                    mem_change = True
                    self.mem_accesses += 1
                else:
                    self.reg[arg] += '+ 2' 
                    reg_change = True
            
            elif 'decd' in instr:
                if '(' in arg:
                    idx,b = arg[:-1].split('(')
                    if '-' not in idx:
                        idx = '+'+idx
                    mem_addr = self.evaluate_expression(self.reg[b]+"+"+idx)
                    try:
                        self.mem[mem_addr] = self.mem[mem_addr] + " - 2"
                    except:
                        self.mem[mem_addr] = f'y{self.symbolic_count}'
                        self.mem[mem_addr] = self.mem[mem_addr] + " - 2"
                        self.symbolic_count += 1
                    valid = self.compare_to_base(mem_addr)
                    mem_change = True
                    self.mem_accesses += 1
                else:
                    self.reg[arg] += '- 2' 
                    reg_change = True

            elif 'inc' in instr:
                if '(' in arg:
                    idx,b = arg[:-1].split('(')
                    if '-' not in idx:
                        idx = '+'+idx
                    mem_addr = self.evaluate_expression(self.reg[b]+"+"+idx)
                    try:
                        self.mem[mem_addr] = self.mem[mem_addr] + " + 1"
                    except:
                        self.mem[mem_addr] = f'y{self.symbolic_count}'
                        self.mem[mem_addr] = self.mem[mem_addr] + " + 1"
                        self.symbolic_count += 1
                    valid = self.compare_to_base(mem_addr)
                    mem_change = True
                    self.mem_accesses += 1
                else:
                    self.reg[arg] += '+1' 
                    reg_change = True

            elif 'add' in instr:
                src,dest = arg.split(",")

                ## parse src to get add value
                if '#' in src: #add imm
                    src = src.replace('#', '')
                    if '-' not in src:
                        src = '+ '+src
                    add_val = src
                    # self.reg[dest] += src

                elif '(' in src: #add from mem
                    idx,b = src[:-1].split('(')
                    if '-' not in idx:
                        idx = '+'+idx
                    mem_addr = self.evaluate_expression(self.reg[b]+"+"+idx)
                    add_val = '+ ('+self.mem[mem_addr]+')'
                    self.mem_accesses += 1
                    # self.reg[dest] += '+ ('+self.mem[mem_addr]+')'

                elif 'r' in src:
                    add_val = '+ '+self.reg[src]

                ## parse dest to get destination
                if '(' in dest:
                    idx,b = dest[:-1].split('(')
                    if '-' not in idx:
                        idx = '+'+idx
                    mem_addr = self.evaluate_expression(self.reg[b]+"+"+idx)
                    self.mem[mem_addr] += add_val
                    self.mem_accesses += 1
                    valid = self.compare_to_base(mem_addr)
                    mem_change = True
                
                elif 'r' in dest:
                    self.reg[dest] += add_val
                    reg_change = True

            elif 'sub' in instr:
                src,dest = arg.split(",")
                if '#' in src:
                    src = src.replace('#', '')
                elif '(' in src: # sub from mem
                    idx,b = src[:-1].split('(')
                    if '-' not in idx:
                        idx = '+'+idx
                    mem_addr = self.evaluate_expression(self.reg[b]+"+"+idx)
                    src = self.mem[mem_addr]
                    self.mem_accesses += 1
                else: # src is a reg
                    src = self.reg[src]
                self.reg[dest] += '-('+src+')'
                reg_change = True

            elif 'push' in instr:
                if self.mode == 'ret-exploit' and self.first_push:
                    self.first_push = False
                else:
                    # in msp430, push to mem @ sp
                    try:
                        self.mem[self.reg['r1']] = self.reg[arg]
                    except KeyError:
                        self.mem[self.reg['r1']] = arg
                    self.mem_accesses += 1
                    mem_addr = self.reg['r1']
                    # valid = self.compare_to_base(self.reg['r1'])
                    sp_val = self.evaluate_expression(self.reg['r1']+'- 2')
                    self.reg['r1'] = sp_val
                    conditional_print(f"self.reg['r1'] = {self.reg['r1']}", file=self.debugFile, flag=self.debug)
                    mem_change = True
                    reg_change = True

            elif 'pop' in instr:    
                # in msp430, push to mem @ sp
                #reverse of push, so incr r1 first
                sp_val = self.evaluate_expression(self.reg['r1']+'+ 2')
                self.reg['r1'] = sp_val
                #then fetch val from mem
                try:
                    self.reg[arg] = self.mem[self.reg['r1']]
                except KeyError:
                    conditional_print(f"No result for mem[{self.reg['r1']}]", file=self.debugFile, flag=self.debug)
                    self.mem[self.reg['r1']] = 'y'+str(self.symbolic_count)
                    self.reg[arg] = self.mem[self.reg['r1']]
                    self.symbolic_count += 1
                reg_change = True
                self.mem_accesses += 1


        if reg_change:
            self.update_regs()
        if mem_change:
            if isinstance(mem_addr, str):
                mem_addr = [mem_addr]
            # print(len(mem_addr))
            self.update_mem(mem_addr)
        conditional_print(self,file=self.debugFile, flag=self.debug)

        return valid

    def update_regs(self):
        # start = time.perf_counter()
        conditional_print("updating regs...", file=self.debugFile)
        for key in self.reg.keys():
            for k in self.reg.keys():
                if key == k:
                    continue

                if isinstance(self.reg[k], int):
                    self.reg[k] = str(self.reg[k])

                if key in self.reg[k]:
                    conditional_print(f"\treplace {key} with {self.reg[key]} in self.reg[{k}]", file=self.debugFile, flag=self.debug)
                    self.reg[k] = self.reg[k].replace(key, self.reg[key])

            # print(f"trying {key} = simplify({self.reg[key]})", file=self.debugFile)
            self.reg[key] = self.evaluate_expression(self.reg[key])
        # self.reg = dict(sorted(self.reg.items()))
        # stop = time.perf_counter()
        # print(f"Update reg time: {1000*(stop-start)}")

    def update_mem(self, mem_addrs):
        # start = time.perf_counter()
        conditional_print("updating mem...", file=self.debugFile, flag=self.debug)
        # mk_list = list(self.mem.keys())
        for mk in mem_addrs:
            if 'r' in mk:
                for rk in self.reg.keys():
                    if rk in mk:
                        new_mk = mk.replace(rk, self.reg[rk])
                        new_mk = self.evaluate_expression(new_mk)
                        self.mem[new_mk] = self.mem.pop(mk)
            elif 'sp' in mk:
                rk = 'sp'
                new_mk = mk.replace(rk, self.reg[rk])
                new_mk = self.evaluate_expression(new_mk)
                self.mem[new_mk] = self.mem.pop(mk)
            else:
                self.mem[mk] = self.evaluate_expression(self.mem[mk])
        self.mem = dict(sorted(self.mem.items()))
        # stop = time.perf_counter()
        # print(f"Update mem time: {1000*(stop-start)}")

    def evaluate_expression(self, expr):
        # start = time.perf_counter()
        x = symbols('x')
        
        try:
            simplified = simplify(expr)
            # stop = time.perf_counter()
            # print(f"Evalute time: {1000*(stop-start)}")
            # print(f"{expr} --> {str(simplified)}")
            return str(simplified)
        except Exception as e:
            # print(f'Exception: {e}', file=self.debugFile)
            # print(f'\texpr: {expr}', file=self.debugFile)
            # a = input()
            return expr

    def get_cond_branch_dest(self, asm_inst):
        ## Should return 0 for not taken, 1 for taken

        addr = asm_inst.addr
        instr = asm_inst.instr
        aarg = asm_inst.arg
        conditional_print(f"Getting dest from ({addr}): {instr} {aarg}",file=self.debugFile, flag=self.debug)
        if self.arch.type == 'armv8-m33':
            if 'beq' in instr:
                return self.sr['Z']
            elif 'bne' in instr:
                return self.sr['Z'] ^ 1
            elif 'bgt' in instr:
                return self.sr['N'] ^ 1
            elif 'bge' in instr:
                return (self.sr['N'] ^ 1) | self.sr['Z']
            elif 'blt' in instr:
                return self.sr['N']
            elif 'ble' in instr:
                return self.sr['N'] | self.sr['Z']
            else:
                conditional_print(f'Support for {instr} not in get_cond_branch_dest()', file=self.debugFile, flag=self.debug)
                return 0

        elif self.arch.type == 'elf32-msp430':
            if 'jeq' in instr or 'jz' in instr:
                return self.sr['Z']
            elif 'jne' in instr or 'jnz' in instr:
                return self.sr['Z'] ^ 1
            elif 'jge' in instr:
                return (self.sr['N'] ^ 1) | self.sr['Z']
            elif 'jl' in instr:
                return self.sr['N']
            else:
                conditional_print(f'Support for {instr} not in get_cond_branch_dest()', file=self.debugFile, flag=self.debug)
                return 0

