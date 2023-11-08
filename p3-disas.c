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
    //initialize the variables being used
    y86_inst_t ins;
    size_t size = sizeof(y86_inst_t);
    memset(&ins, 0x00, sizeof(ins));
    //check the params
    if(memory == NULL || cpu->pc >= MEMSIZE || cpu->pc < 0)
    {
        ins.icode = INVALID;
        cpu->stat = ADR;
        return ins;
    }
    //get each byte of the data 
    uint64_t *p;
    uint8_t byte1 = memory[cpu->pc];
    uint8_t byte2;
    switch(byte1) 
    {
        //get each case and set the values
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
            //out of bound
            if (cpu->pc + size >= MEMSIZE)
            {
                ins.icode = INVALID;
                cpu->stat = ADR;
                break;
            }
            byte2 = memory[cpu->pc + 1];
            ins.ra = ((byte2 & 0xF0) >> 4);
            ins.rb = (byte2 & 0x0F);
            //check the register
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
            //check if size is valid
            if (cpu->pc + size >= MEMSIZE)
            {
                ins.icode = INVALID;
                cpu->stat = ADR;
                break;
            }
            byte2 = memory[cpu->pc + 1];
            ins.rb = (byte2 & 0x0F);
            //check if the first byte is f and the rest of the register
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
            //check size
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
            //check the size 
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
            //check the size
            if (cpu->pc + size >= MEMSIZE)
            {
                ins.icode = INVALID;
                cpu->stat = ADR;
                break;
            }
            byte2 = memory[cpu->pc + 1];
            ins.ra = ((byte2 & 0xF0) >> 4);
            //check to see if the first byte is f and the rest of the register
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
            //check size
            if (cpu->pc + size >= MEMSIZE)
            {
                ins.icode = INVALID;
                cpu->stat = ADR;
                break;
            }
            byte2 = memory[cpu->pc + 1];
            ins.ra = ((byte2 & 0xF0) >> 4);
            //check to see if the first byte is f and the rest of the register
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
    while ((c = getopt(argc, argv, "hHmMsafdD")) != -1) 
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

//prints the register based of the hex value
void printRegister(uint32_t s) 
{
    switch(s)
    {
        case 0x00: 
            printf("%%rax"); 
            break;
        case 0x01: 
            printf("%%rcx"); 
            break;
        case 0x02: 
            printf("%%rdx"); 
            break;
        case 0x03: 
            printf("%%rbx"); 
            break;
        case 0x04: 
            printf("%%rsp"); 
            break;
        case 0x05: 
            printf("%%rbp"); 
            break;
        case 0x06: 
            printf("%%rsi"); 
            break;
        case 0x07: 
            printf("%%rdi"); 
            break;
        case 0x08: 
            printf("%%r8"); 
            break;
        case 0x09: 
            printf("%%r9"); 
            break;
        case 0x0A: 
            printf("%%r10");
            break;
        case 0x0B: 
            printf("%%r11"); 
            break;
        case 0x0C: 
            printf("%%r12"); 
            break;
        case 0x0D: 
            printf("%%r13"); 
            break;
        case 0x0E: 
            printf("%%r14"); 
            break;
    }
}

void disassemble (y86_inst_t *inst) 
{
    //print each icode
    switch(inst->icode)
    {
        case HALT: 
            printf("halt"); 
            break;
        case NOP: 
            printf("nop"); 
            break;
        case CMOV: 
            switch(inst->ifun.cmov)
            {
                case RRMOVQ: 
                    printf("rrmovq "); 
                    break; 
                case CMOVLE: 
                    printf("cmovle "); 
                    break;
                case CMOVL: 
                    printf("cmovl "); 
                    break;
                case CMOVE: 
                    printf("cmove ");
                    break;
                case CMOVNE: 
                    printf("cmovne "); 
                    break;
                case CMOVGE: 
                    printf("cmovge " ); 
                    break;
                case CMOVG: 
                    printf("cmovg "); 
                    break;
                case BADCMOV: 
                    return; 
            } 
            printRegister(inst->ra);
            printf(", ");
            printRegister(inst->rb);
            break; 
        //print the icode and the registers  
        case IRMOVQ: 
            printf("irmovq "); 
            printf("%#lx, ", (uint64_t) inst->valC.v); 
            printRegister(inst->rb);
            break;   
        //print the icode, and correct register and memory 
        case RMMOVQ: 
            printf("rmmovq "); 
            printRegister(inst->ra);
            printf(", %#lx", (uint64_t) inst->valC.d); 
            if(inst->rb < 15)
            {
                printf("(");
                printRegister(inst->rb);
                printf(")");
            }
            else 
            {
                printRegister(inst->rb);
            }
            break;
        case MRMOVQ: 
            printf("mrmovq "); 
            printf("%#lx", (uint64_t) inst->valC.d); 
            if(inst->rb < 15)
            {
                printf("(");
                printRegister(inst->rb);
                printf("), ");
            }
            else 
            {
                printf(", ");
                printRegister(inst->rb);
            }    
            printRegister(inst->ra);
            break;
        case OPQ:
            switch(inst->ifun.op)
            {
                case ADD: 
                    printf("addq "); 
                    break;
                case SUB: 
                    printf("subq "); 
                    break;
                case AND: 
                    printf("andq "); 
                    break;
                case XOR: 
                    printf("xorq "); 
                    break;
                case BADOP:
                    return;
            }
            printRegister(inst->ra);
            printf(", ");
            printRegister(inst->rb);
            break;   
        case JUMP: 
            switch(inst->ifun.jump)
            {
                case JMP: 
                    printf("jmp "); 
                    break;
                case JLE: 
                    printf("jle "); 
                    break;
                case JL: 
                    printf("jl "); 
                    break;
                case JE: 
                    printf("je "); 
                    break;
                case JNE: 
                    printf("jne "); 
                    break;
                case JGE: 
                    printf("jge "); 
                    break;
                case JG: 
                    printf("jg "); 
                    break;
                case BADJUMP: 
                    return;

            }
            printf("%#lx", (uint64_t) inst->valC.dest);
            break;    
        case CALL: 
            printf("call "); 
            printf("%#lx", (uint64_t) inst->valC.dest); 
            break;
        case RET: 
            printf("ret"); 
            break;
        case PUSHQ: 
            printf("pushq "); 
            printRegister(inst->ra); 
            break;
        case POPQ: 
            printf("popq "); 
            printRegister(inst->ra); 
            break;
        case IOTRAP:
            printf("iotrap ");
            printf("%i", inst->ifun.trap);
            break;
        case INVALID: 
            break;
     }
}

void disassemble_code (byte_t *memory, elf_phdr_t *phdr, elf_hdr_t *hdr)
{

    y86_t cpu;
    y86_inst_t ins;
    uint32_t addr = phdr->p_vaddr;
    cpu.pc = addr;
    printf("  0x%03lx:         %31s%03lx code", (uint64_t) cpu.pc, "| .pos 0x", (uint64_t) cpu.pc);
    printf("\n");
    while(cpu.pc < addr + phdr->p_size) 
    {
        if(cpu.pc == hdr->e_entry)
        {
            printf("  0x%03lx:         %31s", (uint64_t) cpu.pc, "| _start:");
            printf("\n");
        }
        size_t size = sizeof(y86_inst_t);
        ins = fetch(&cpu, memory);
        switch(ins.icode) {
            case (INVALID):
                size = 1;
                break;
            case (HALT):
            case (NOP):
            case (RET):
            case (IOTRAP):
                size = 1;
                break;
            case (CMOV):
            case (OPQ):
            case (PUSHQ):
            case (POPQ):
                size = 2;
                break;
            case (JUMP):
            case (CALL):
                size = 9;
                break;
            case (IRMOVQ):
            case (RMMOVQ):
            case (MRMOVQ):
                size = 10;
                break;
        }
        if(ins.icode == INVALID)
        {
            printf("Invalid opcode: %#02x\n\n", (ins.icode | 0xF0));
            cpu.pc += size;
            return;
        }
        printf("  0x%03lx: ", (uint64_t) cpu.pc);
        for(int i = cpu.pc; i < cpu.pc + size; i++)
        {
            printf("%02x ", memory[i]);
           
        }
        int spaces = 10 - size;
        for(int i = 0; i < spaces; i++)
        {
            printf("   ");
        }
        printf("|   ");
        disassemble(&ins);
        cpu.pc += size;
        printf("\n");
    }
    printf("\n");
}

void disassemble_data (byte_t *memory, elf_phdr_t *phdr)
{
    //set the variables
    y86_t cpu;
    uint32_t addr = phdr->p_vaddr;
    cpu.pc = addr;
    //print the pos
    printf("  0x%03lx:", (uint64_t) cpu.pc);
    printf("%40s%03lx data\n","| .pos 0x", (uint64_t) cpu.pc);
    //print the rest of instructions
    while(cpu.pc < addr + phdr->p_size)
    {
        printf("  0x%03lx: ", (uint64_t) cpu.pc);
        for(int i = cpu.pc; i < cpu.pc + 8; i++)
        {
            printf("%02x ", memory[i]);
        }
        printf("%7s","|"); 
        printf("   .quad ");
        uint64_t *p;
        //print the memory of the pc
        p = (uint64_t *) &memory[cpu.pc];
        printf("%p", (void *) *p);
        cpu.pc += 8;
        printf("\n"); 
    }
    printf("\n");
}

void disassemble_rodata (byte_t *memory, elf_phdr_t *phdr)
{
    //set the variables
    y86_t cpu;
    uint32_t addr = phdr->p_vaddr;
    cpu.pc = addr;
    int i;
    //print pos
    printf("  0x%03lx:           ", (uint64_t) cpu.pc);
    printf("%29s%03lx rodata\n","| .pos 0x", (uint64_t) cpu.pc);
    while(cpu.pc <  addr + phdr->p_size)
    {
        printf("  0x%03lx: ", (uint64_t) cpu.pc);
        for(i = cpu.pc; i < cpu.pc + 10; i++)
        {
            printf("%02x ", memory[i]);
            if(memory[i] == 0x00)
            {
                int space = 10 - (i - (cpu.pc - 1));
                for (int i = 0; i < space; i++) {
                    printf("   ");
                }
                break;
            } 
        }
        i = cpu.pc;
        //print the memory
        printf("|   .string \"");
        while(memory[i] != 0x00)
        {
            printf("%c", memory[i++]);
        }
        int bytes = (i - cpu.pc) + 1;
        printf("\"");
        cpu.pc += bytes; 
        printf("\n");
    }
    printf("\n");
}

