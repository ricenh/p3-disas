/*
 * CS 261: Main driver
 *
 * Name: 
 */

#include "p1-check.h"
#include "p2-load.h"
#include "p3-disas.h"

int main (int argc, char **argv)
{
// parse command-line options
    bool print_header = false;
    bool print_phdr = false;
    bool print_membrief = false;
    bool print_memfull = false;
    bool disas_code = false;
    bool disas_data = false;
    char *fn = NULL;
    if (!parse_command_line_p3(argc, argv, &print_header, &print_phdr, &print_membrief, &print_memfull, &disas_code, &disas_data, &fn)) 
    {
        exit(EXIT_FAILURE);
    }
 
    if (fn != NULL) 
    {
 
        // open Mini-ELF Header in binary
        FILE *f = fopen(fn, "r");
        if (!f) 
        {
            printf("Failed to read file\n");
            exit(EXIT_FAILURE);
        }
 
        // P1: load and check Mini-ELF header
        elf_hdr_t hdr;
        if (!read_header(f, &hdr)) 
        {
            printf("Failed to read file\n");
            exit(EXIT_FAILURE);
        }
        
        //P2: load and check the phdr
        elf_phdr_t phdr[hdr.e_num_phdr];
        for(int i = 0; i < hdr.e_num_phdr; i++) 
        {
            uint16_t offset = hdr.e_phdr_start + (i * sizeof(elf_phdr_t));   
            if(!read_phdr(f, offset, &phdr[i]))
            {
	            printf("Failed to read file\n");
                exit(EXIT_FAILURE);
            }
        }

        //allocates 4kb of memory
        byte_t* memory = (byte_t*)calloc(MEMSIZE, 1);
        for(int i = 0; i < hdr.e_num_phdr; i++) 
        {
            //load the segment in memory
            if(!load_segment(f, memory, &phdr[i])) 
            {
                printf("Failed to read file\n");
                free(memory);
                exit(EXIT_FAILURE);
            }
        }
        
        // P1 output
        if (print_header) 
        {
            dump_header(&hdr);
        }

        //dump all phdrs in file
        if(print_phdr) 
        {
            dump_phdrs(hdr.e_num_phdr, phdr);
        }
        
        //dump the full memory
        if(print_memfull) 
        {
            dump_memory(memory, 0, MEMSIZE);
        }

        //drump the brief memory
        if(print_membrief) 
        {
            for(int i = 0; i < hdr.e_num_phdr; i++)
            {
                //dumps the memory starting at the virtual address to the end of the virtual address + size
                dump_memory(memory, phdr[i].p_vaddr, phdr[i].p_vaddr + phdr[i].p_size); 
            }   
        }

        if(disas_code)
        {
            printf("Disassembly of executable contents:\n");
            for(int i = 0; i < hdr.e_num_phdr; i++)
            {
                if(phdr[i].p_type == CODE)
                {   
                    disassemble_code(memory, &phdr[i], &hdr);
                }
            }   
        }

        if(disas_data) 
        {
            printf("Disassembly of data contents:\n");
            for(int i = 0; i < hdr.e_num_phdr; i++)
            {
                if(phdr[i].p_type == DATA && phdr[i].p_flags == 4)
                {
                    disassemble_rodata(memory, &phdr[i]);
                }
                else if(phdr[i].p_type == DATA && phdr[i].p_flags == 6)
                {
                    disassemble_data(memory, &phdr[i]);   
                }
            }  
        }

        fclose(f);
        free(memory);
 
    }

    return EXIT_SUCCESS;

}

