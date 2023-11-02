/*
 * CS 261 PA3: Mini-ELF disassembler
 *
 * Name: 
 */

#include "p3-disas.h"

/**********************************************************************
 *                         REQUIRED FUNCTIONS
 *********************************************************************/

y86_inst_t fetch (y86_t *cpu, byte_t *memory)
{
    y86_inst_t ins;
    size_t size = sizeof(y86_inst_t);
    memset(&ins, 0x00, sizeof(ins));
    if(memory == NULL || cpu->pc >= MEMSIZE || cpu->pc < 0)
    {
        ins.icode = INVALID;
        cpu->stat = ADR;
        return ins;
    } 
    uint64_t *p;
    uint8_t byte1 = memory[cpu->pc];
    uint8_t byte2;
    switch(byte1) 
    {
        case (0x00): 
            ins.icode = HALT; 
            cpu->stat = INS;
            size = 1; 
            ins.valP = cpu->pc + size;
            break;
        case (0x10): 
            ins.icode = NOP; 
            size = 1; 
            ins.valP = cpu->pc + size;
            cpu->stat = INS;
            break;
        case (0x20):
        case (0x21):
        case (0x22):
        case (0x23):
        case (0x24):
        case (0x25):
        case (0x26):
            ins.icode = CMOV;
            size = 2;
            ins.ifun.cmov = byte1 & 0x0F;
            cpu->stat = AOK;
            ins.valP = cpu->pc + size;
            // Out of bounds
            if (cpu->pc + size >= MEMSIZE)
            {
                ins.icode = INVALID;
                cpu->stat = ADR;
                break;
            }
       
            // Set and check registers
            byte2 = memory[cpu->pc + 1];
            ins.ra = ((byte2 & 0xF0) >> 4);
            ins.rb = (byte2 & 0x0F);
            if (ins.ra >= NUMREGS || ins.rb >= NUMREGS)
            {
                ins.icode = INVALID;
                cpu->stat = INS;
            }
            break;
        case (0x30):
            ins.icode = IRMOVQ;
            size = 10;
            cpu->stat = AOK;
            ins.valP = cpu->pc + size;
            if (cpu->pc + size >= MEMSIZE)
            {
                ins.icode = INVALID;
                cpu->stat = ADR;
                break;
            }
            byte2 = memory[cpu->pc + 1];
            ins.rb = (byte2 & 0x0F);
            if (((byte2 & 0xF0) >> 4) != 0x0F || ins.rb >= NUMREGS)
            {
                ins.icode = INVALID;
                cpu->stat = INS;
                break;
            }
            p = (uint64_t *) &memory[cpu->pc + 2];
            ins.valC.v = *p;
            break;

        case (0x40):
            ins.icode = RMMOVQ;

            size = 10;
            if(cpu->pc + size >= MEMSIZE)
            {
                ins.icode = INVALID;
                cpu->stat = ADR;
                break;
            }
            byte2 = memory[cpu->pc + 1]; 
            ins.ra = ((byte2 & 0xF0) >> 4);  
            ins.rb = (byte2 & 0x0F);
            ins.valP = cpu->pc + size;
            ins.ifun.op = byte1 & 0x0F;
            p = (uint64_t *) &memory[cpu->pc + 2]; 
            ins.valC.d = *p;
            break;
        case (0x50):
            ins.icode = MRMOVQ;
            size = 10;
            byte2 = memory[cpu->pc + 1];  
            ins.ra = ((byte2 & 0xF0) >> 4); 
            ins.rb = (byte2 & 0x0F); 
            ins.valP = cpu->pc + size;
            ins.ifun.op = byte1 & 0x0F;
            p = (uint64_t *) &memory[cpu->pc + 2]; 
            ins.valC.d = *p;
            break;
        case (0x60):
        case (0x61):
        case (0x62):
        case (0x63):
            ins.icode = OPQ;
            size = 2;
            byte2 = memory[cpu->pc + 1];  
            ins.ra = ((byte2 & 0xF0) >> 4); 
            ins.rb = (byte2 & 0x0F); 
            ins.valP = cpu->pc + size;
            ins.ifun.op = byte1 & 0x0F;
            break;
        case (0x70):
        case (0x71):
        case (0x72):
        case (0x73):
        case (0x74):
        case (0x75):
        case (0x76):
            ins.icode = JUMP;
            size = 9;
            byte2 = memory[cpu->pc + 1];  
            ins.ra = ((byte2 & 0xF0) >> 4); 
            ins.rb = (byte2 & 0x0F); 
            ins.valP = cpu->pc + size;
            ins.ifun.op = byte1 & 0x0F;
            p = (uint64_t *) &memory[cpu->pc + 1]; 
            ins.valC.dest = *p;
            break;
        case (0x80):
            ins.icode = CALL;
            size = 9;
             if(cpu->pc + size >= MEMSIZE)
            {
                ins.icode = INVALID;
                cpu->stat = ADR;
            }
            byte2 = memory[cpu->pc + 1];  
            ins.ra = ((byte2 & 0xF0) >> 4); 
            ins.rb = (byte2 & 0x0F); 
            ins.valP = cpu->pc + size;
            ins.ifun.op = byte1 & 0x0F;
            p = (uint64_t *) &memory[cpu->pc + 1]; 
            ins.valC.dest = *p;
            break;
        case (0x90): 
            ins.icode = RET; 
            size = 1; 
            ins.valP = cpu->pc + size;
            cpu->stat = INS;
            break; 
        case (0xA0):
            ins.icode = PUSHQ;
            size = 2;
            cpu->stat = AOK;
            ins.valP = cpu->pc + size;
            if (cpu->pc + size >= MEMSIZE)
            {
                ins.icode = INVALID;
                cpu->stat = ADR;
                break;
            }
            byte2 = memory[cpu->pc + 1];
            ins.ra = ((byte2 & 0xF0) >> 4);
            if (((byte2 & 0x0F)) != 0x0F || ins.ra >= NUMREGS)
            {
                ins.icode = INVALID;
                cpu->stat = INS;
            }
            break;
        case (0xB0):
            ins.icode = POPQ;
            size = 2;
            cpu->stat = AOK;
            ins.valP = cpu->pc + size;
            if (cpu->pc + size >= MEMSIZE)
            {
                ins.icode = INVALID;
                cpu->stat = ADR;
                break;
            }
            byte2 = memory[cpu->pc + 1];
            ins.ra = ((byte2 & 0xF0) >> 4);
            if (((byte2 & 0x0F)) != 0x0F || ins.ra >= NUMREGS)
            {
                ins.icode = INVALID;
                cpu->stat = INS;
            }
            break;
        case (0xC0):
        case (0xC1):
        case (0xC2):
        case (0xC3):
        case (0xC4):
        case (0xC5):
            ins.icode = IOTRAP;
            size = 1;
            byte2 = memory[cpu->pc + 1];  
            ins.valP = cpu->pc + size;
            ins.ifun.op = byte1 & 0x0F;
            break;
        default: 
            ins.icode = INVALID;
            cpu->stat = INS;
    }
    return ins;
}

/**********************************************************************
 *                         OPTIONAL FUNCTIONS
 *********************************************************************/

void usage_p3 (char **argv)
{
    printf("Usage: %s <option(s)> mini-elf-file\n", argv[0]);
    printf(" Options are:\n");
    printf("  -h      Display usage\n");
    printf("  -H      Show the Mini-ELF header\n");
    printf("  -a      Show all with brief memory\n");
    printf("  -f      Show all with full memory\n");
    printf("  -s      Show the program headers\n");
    printf("  -m      Show the memory contents (brief)\n");
    printf("  -M      Show the memory contents (full)\n");
    printf("  -d      Disassemble code contents\n");
    printf("  -D      Disassemble data contents\n");
}

bool parse_command_line_p3 (int argc, char **argv,
        bool *print_header, bool *print_phdrs,
        bool *print_membrief, bool *print_memfull,
        bool *disas_code, bool *disas_data, char **filename)
{
    //checks the args
    if (argv == NULL || print_header == NULL || print_phdrs == NULL ||
    print_membrief == NULL || print_memfull == NULL || disas_code == NULL || 
    disas_data == NULL || filename == NULL) 
    {
        return false;
    }
 
    // parameter parsing w/ getopt()
    int c;
    while ((c = getopt(argc, argv, "hHmMsaf")) != -1) 
    {
        switch (c) 
        {
            case 'h':
                usage_p3(argv);
                return true;
            case 'H':
                *print_header = true;
                break;
            case 'm':
                *print_membrief = true;
                break;
            case 'M':
                *print_memfull = true;
                break;
            case 's':
                *print_phdrs = true;
                break;
            case 'a':
                *print_header = true;
                *print_phdrs = true;
                *print_membrief = true;
                break;
            case 'f':
                *print_header = true;
                *print_phdrs = true;
                *print_memfull = true;
                break;
            case 'd': 
                *disas_code = true; 
                break;
            case 'D': 
                *disas_data = true; 
                break;
            default:
                usage_p3(argv);
                return false;
        }
    }
    //if memfull and membrief are true print usage
    if (*print_memfull && *print_membrief) 
    {
        usage_p3(argv);
        return false;
    }
 
    if (optind != argc-1) 
    {
        // no filename (or extraneous input)
        usage_p3(argv);
        return false;
    }
    *filename = argv[optind];   // save filename
    return true;
}


void printReg(uint32_t b) 
{
    // //register printing helper method
    // switch(b)
    // {
    //     case 0x00: printf("%%rax"); break;
    //     case 0x01: printf("%%rcx"); break;
    //     case 0x02: printf("%%rdx"); break;
    //     case 0x03: printf("%%rbx"); break;
    //     case 0x04: printf("%%rsp"); break;
    //     case 0x05: printf("%%rbp"); break;
    //     case 0x06: printf("%%rsi"); break;
    //     case 0x07: printf("%%rdi"); break;
    // }

}

void disassemble (y86_inst_t *inst) 
{
}

void disassemble_code (byte_t *memory, elf_phdr_t *phdr, elf_hdr_t *hdr)
{
}

void disassemble_data (byte_t *memory, elf_phdr_t *phdr)
{
}

void disassemble_rodata (byte_t *memory, elf_phdr_t *phdr)
{
}

