#!/bin/python3
"""
BDMDecoder

Tool to analyze and parse the csv output of the BDMAnalyzer logic2 plugin.
Zetier 2024-2025
"""

import csv
import argparse
from capstone import *

def read_csv_to_dict(file_path):
    """
    Reads a CSV file and returns its contents as a list of dictionaries.
    Each row in the CSV becomes a dictionary, with keys from the header row.

    :param file_path: Path to the CSV file.
    :return: List of dictionaries representing the CSV contents.
    """
    data = []

    try:
        with open(file_path, mode='r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                data.append(row)

    except FileNotFoundError:
        print(f"Error: File not found at path '{file_path}'.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return data



def hex_to_bytes(hex_str):
    """
    Converts a string representing a 32-bit hexadecimal value to a bytes object.

    :param hex_str: A string representing a 32-bit hex value (e.g., "deadbeef").
    :return: A bytes object representing the hexadecimal value.
    """
    try:
        return bytes.fromhex(hex_str)
    except ValueError as e:
        print(f"Invalid hex string: {e}")
        return b""


SPR = {
    # User level SPR
    "0x1": "XER",
    "0x8": "LR",
    "0x9": "CTR",
    "0x40": "CR",
    "0x42": "MSR", 
    "0x12": "DSISR", 
    "0x13": "DAR", 
    "0x16": "DEC", 
    "0x1a": "SRR0",
    "0x1b": "SRR1",
    "0x110": "SPRG0",
    "0x111": "SPRG1",
    "0x112": "SPRG2",
    "0x113": "SPRG3", 
    "0x50": "EIE",
    "0x51": "EID",
    "0x52": "NRI",
    "0x277": "DPIR", 
    "0x27e": "IMMR",
    "0x230": "IC_CST", 
    "0x231": "IC_ADR",
    "0x232": "IC_DAT",
    "0x238": "DC_CST",
    "0x239": "DC_ADR",
    "0x23a": "DC_DAT",
    "0x310": "MI_CTR",
    "0x312": "MI_AP",
    "0x313": "MI_EPN",
    "0x315": "MI_TWC",
    "0x316": "MI_RPN",
    "0x330": "MI_CAM",
    "0x331": "MI_RAM0",
    "0x332": "MI_RAM1",
    "0x318": "MD_CTR",
    "0x319": "M_CASID",
    "0x31a": "MD_AP",
    "0x31b": "MD_EPN",
    "0x31c": "M_TWB",
    "0x31d": "MD_TWC",
    "0x31e": "MD_RPN",
    "0x31f": "M_TW",
    "0x180": "TB",
    "0x181": "TBU", 
    "0x183": "PVR", 
    #mpc860 specific debug registers
    "0x90": "CMPA", #Comparator A-H --> breakpoint comparisons
    "0x91": "CMPB",
    "0x92": "CMPC",
    "0x93": "CMPD",
    "0x98": "CMPE",
    "0x99": "CMPF",
    "0x9a": "CMPG",
    "0x9b": "CMPH",
    "0x94": "ICR", #Interrupt Cause Register
    "0x95": "DER", #Debug Enable Register
    "0x96": "COUNTA", #breakpoint counter value and control registers
    "0x97": "COUNTB", # //
    "0x9c": "LCTRL1", #Load/Store Support Comparators Control Register 1
    "0x9d": "LCTRL2", # // 2
    "0x9e": "ICTRL", #Instruction Support Control Register
    "0x9f": "BAR", #Breakpoint Address Register
    "0x276": "DPDR", #Development Port Data Register
    #Option Registers,
    "0x104": "OR0",
    "0x10c": "OR1",
    "0x114": "OR2",
    "0x11c": "OR3",
    "0x124": "OR4",
    "0x12c": "OR5",
    "0x134": "OR5",
    "0x13c": "OR7"
}

class Entry:
    def __init__(self, decoded, entry):
        self.decoded = decoded
        self.entry = entry

class DecodedBlock:
    def __init__(self, start, last_entry, idx):
        self.start = start
        self.last_entry = last_entry
        self.DSDI_entries = []
        self.DSDO_entries = []
        self.idx = idx #the nth block 

    def add_dsdi_entry(self, entry):
        self.DSDI_entries.append(entry)

    def add_dsdo_entry(self, entry):
        self.DSDO_entries.append(entry)

    def format_combined(self):
        out_str = ""
        combined = zip([entry.decoded for entry in self.DSDI_entries], [entry.decoded for entry in self.DSDO_entries])
        if self.idx > 0:
            out_str += "\n\n"
        out_str += "##################################################"
        out_str +=  f"\n##################### BLOCK {self.idx} ####################"
        out_str += f"\nLAST: {self.last_entry} ____________ THIS: {self.start}"
        out_str += "\n= PC ===== DSDI ============================= DSDO "

        for com in combined:
            dsdi_len = len(com[0])
            dsdo_len = len(com[1])
            space = "-" * (50-(dsdo_len + dsdi_len))
            out_str += "\n" + com[0] + space + com[1]

        return out_str
    
    def format_exported_instructions(self):
        out_str = ""
        instructions = self.export_dsdi_instructions()
        out_str += "instructions = [\n"
        for ins in instructions:
            if ins is not None:
                out_str += " " * 4 +  str(ins).replace('\'', '') + ',\n'

        out_str += ']'
        return out_str


    def export_dsdi_instructions(self):
        instructions = [
                (
                    dsdi["Mode"],
                    dsdi["Control"],
                    dsdi["Instruction"]
                         ) if dsdi is not None else None
                 for dsdi in [entry.entry for entry in self.DSDI_entries]
                 ]

        return instructions

        
def decode_ppc_instruction(ins, pc):
    ret = ""
    md = Cs(CS_ARCH_PPC, CS_MODE_32| CS_MODE_BIG_ENDIAN)
    for instruction in md.disasm(ins, pc):
        regs = instruction.op_str.split(',')
        op_str = instruction.op_str
        rawbytes = ''
        if len(regs) > 1:
            reg1 = instruction.op_str.split(',')[0]
            reg2 = instruction.op_str.split(',')[1].strip(' ')
            if reg1 in SPR.keys():
                op_str = op_str.replace(reg1, SPR[reg1])
            if reg2 in SPR.keys():
                op_str = op_str.replace(reg2, SPR[reg2])

        ret +=  f"0x{instruction.address:04x}:	{instruction.mnemonic}	{op_str} {rawbytes}"
        
    return ret

def breakdown_unk_instruction(ins):
    num = int(ins, 16)
    opcode = num >> 26
    xo = (num & 0x7fe) >> 1
    return (opcode, xo)

def decode_dbg_cmd(ins):
    num = int(ins, 16)
    opcode = num & 0x1f
    xo = num >> 5
    xo_1 = xo>>1;
    xo_2 = xo & 0x1;
    ret = ""

    if opcode == 0:
        #NOP
        ret = "NOP"
    elif opcode == 1:
        #HRESET REQUEST
        ret = "HRESET_REQ"
    elif opcode == 2:
        #SRESET REQUEST
        ret = "SRESET_REQ"
    elif opcode == 3:
        if xo_1 == 0:
            #reserved
            ret = "RESERVED"
        elif xo_1 == 1 and xo_2 == 0:
            #end download procedure
            ret = "END_DOWNLOAD"
        elif xo_1 == 1 and xo_2 == 1:
            #start download procedure
            ret = "START_DOWNLOAD"
        else:
            #err
            pass
    elif opcode == 0x1f:
        if xo_2 == 0:
            #negate maskable breakpoint
            ret = "NEG_MASK_BREAK" 
        elif xo_2 == 1:
            #assert masable breakpoint
            ret = "ASRT_MASK_BREAK"
        elif xo_1 == 0:
            #negate nonmaskable breakpoint
            ret = "NEG_NMASK_BREAK"
        elif xo_1 == 1:
            #assert nonmaskable breakpoint
            ret = "ASRT_NMASK_BREAK"

    return ret


def align_dsdo(block, align):
    if align:
        block.add_dsdo_entry(Entry("", None))
    

def decode(data, args):
    total_idx = 0
    DSDI_idx = 0
    DSDO_idx = 0
    last_timestamp = 0
    blocks = []
    cur_block = None
    for entry in data:
        decoded = ""

        current_timestamp = float(entry["start_time"])

        if cur_block == None and last_timestamp == 0:
            cur_block = DecodedBlock(current_timestamp, last_timestamp, len(blocks))
            last_timestamp = current_timestamp
        if current_timestamp - last_timestamp > args.block_timing:
            align_dsdo(cur_block, args.align)
            blocks.append(cur_block)
            cur_block = DecodedBlock(current_timestamp, last_timestamp, len(blocks))
            last_timestamp = current_timestamp
        
        if entry["type"] == "DSDI":
            decoded = decode_dsdi(entry, args, DSDI_idx)
            if (DSDI_idx == 0 or len(cur_block.DSDI_entries) == 0) and args.align:
                #add empty DSDI entry to align responses
                cur_block.add_dsdi_entry(Entry("", None))
            DSDI_idx += 1
            cur_block.add_dsdi_entry(Entry(decoded, entry))

        elif entry["type"] ==  "DSDO":
            decoded = decode_dsdo(entry, args)
            cur_block.add_dsdo_entry(Entry(decoded,entry))

        total_idx += 1
        last_timestamp = current_timestamp

    align_dsdo(cur_block, args.align)
    blocks.append(cur_block)
    return blocks





def decode_dsdi(entry, args, DSDI_idx):
    mode = entry["Mode"]
    control = entry["Control"]
    instruction_data = entry["Instruction"]
    ins_bytes = hex_to_bytes(instruction_data.replace('0x',''))
    cur_pc = f"0x{DSDI_idx:04x}"


    if mode == "0x00" and control == "0x00":
        #core instruction
        decoded = decode_ppc_instruction(ins_bytes, DSDI_idx).rstrip()
        if decoded == '': #if decode failed, show raw
            (opc, xo) = breakdown_unk_instruction(instruction_data)
            decoded = f"{cur_pc}: UNK: {instruction_data} opc:{opc} xo:{xo}"
        if args.raw:
            decoded = f"{cur_pc}: {instruction_data}"
        

    elif mode == "0x00" and control == "0x01":
        #core data
        decoded = f"{cur_pc}: CORE_DATA: {instruction_data}"

    elif mode == "0x01" and control == "0x00":
        #trap enable bits
        decoded = f"{cur_pc}: TRAP_DATA: {instruction_data}"

    elif mode == "0x01" and control == "0x01":
        #dbg command
        cmd = decode_dbg_cmd(instruction_data)
        decoded = f"{cur_pc}: {cmd} {instruction_data}"

    else:
        decoded = "DSDI_ERROR"
    
    decoded = decoded.replace('\t', "    ")
    return decoded

def decode_dsdo(entry, args):
    status_1 = entry["Status 1"]
    status_2 = entry["Status 2"]
    data = entry["Data"]

    if status_1 == "0x00" and status_2 == "0x00": 
        #data
        decoded = data
    elif status_1 == "0x00" and status_2 == "0x01" :
        #sequencing error
        decoded = "SEQUENCING ERROR"
    elif status_1 == "0x01" and status_2 == "0x00" :
        #core interrupt
        decoded = "CORE INTERRUPT"
        if args.raw:
            decoded += " " + data
    elif status_1 == "0x01" and status_2 == "0x01": 
        #null
        decoded = "NULL"
        if args.raw:
            decoded += " " + data
    else:
        decoded = "DSDO ERROR"
    

    decoded = decoded.replace('\t', "    ")
    return decoded


def dump(blocks, args):

    if args.show_block is None:
        pass
    else:
        if args.show_block < len(blocks):
            d = blocks[args.show_block].format_exported_instructions()
            print(d)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read a CSV file and process its contents.")
    parser.add_argument('file_path', type=str, help="Path to the CSV file.")
    parser.add_argument("--show_block", "-b", type=int, help="Show nth block")
    parser.add_argument("--raw", "-r", action='store_true', help="show raw instruction bytes")
    parser.add_argument("--align", "-a", action='store_true', help="align dsdo responses to dsdi instruction. Default behavior will align signals in the order of processing")
    parser.add_argument("--dump_instructions", "-d", action='store_true', help="dump python array of tuples representing the instructions sent over DSDI. When used in conjunction with --show_block, it will only output the selected block")
    parser.add_argument("--block_timing", "-bt", type=float, help="timing delta to divide blocks by", default=0.1)

    args = parser.parse_args()

    csv_data = read_csv_to_dict(args.file_path)
    
    blocks = decode(csv_data, args)
    if args.show_block is None:
        for block in blocks:
            print(block.format_combined())
    else:
        if args.show_block < len(blocks):
            print(blocks[args.show_block].format_combined())

    if args.dump_instructions:
        dump(blocks, args)

    
