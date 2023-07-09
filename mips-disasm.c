#include <sys/types.h>
#include <byteswap.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>

#define TARGET "./target.bin"
#define BASE_ADDR 0x400540
uint32_t pc = BASE_ADDR;

#define MAX_OPERANDS 3
enum m32_opc{
    m32_nop = 0x00,
    m32_jr = 0x08,
    m32_addiu = 0x09,
    m32_jalr = 0x09,
    m32_syscall = 0x0c,
    m32_lui = 0x0f,
    m32_bal = 0x11,
    m32_add = 0x20,
    m32_addu = 0x21,
    m32_lw = 0x23,
    m32_or = 0x25,
    m32_xor = 0x26,
    m32_sw = 0x2b
};

char *m32_reg_strtab[] = {
    "zero\0",
    "at\0",
    "v0\0",
    "v1\0",
    "a0\0",
    "a1\0",
    "a2\0",
    "a3\0",
    "t0\0",
    "t1\0",
    "t2\0",
    "t3\0",
    "t4\0",
    "t5\0",
    "t6\0",
    "t7\0",
    "s0\0",
    "s1\0",
    "s2\0",
    "s3\0",
    "s4\0",
    "s5\0",
    "s6\0",
    "s7\0",
    "t8\0",
    "t9\0",
    "k0\0",
    "k1\0",
    "gp\0",
    "sp\0",
    "fp\0",
    "ra\0"
};

char *m32_insnR_strtab[] = {
    "nop\0",
    [0x08] = "jr\0",
    [0x09] = "jalr\0",
    [0x0c] = "syscall\0",
    [0x20] = "add\0",
    [0x21] = "addu\0",
    [0x25] = "or\0",
    [0x26] = "xor\0"
};

char *m32_insnI_strtab[] = {
    [0x09] = "addiu\0",
    [0x0f] = "lui\0",
    [0x23] = "lw\0",
    [0x2b] = "sw\0"
};

char *m32_regimmI_strtab[] = {
    [0x11] = "bal\0"
};

typedef struct mips32_r_insn{
    uint8_t func:6;
    uint8_t sa:5;
    uint8_t rd:5;
    uint8_t rt:5;
    uint8_t rs:5;
    uint8_t opcode:6;
}m32_insn_R;

typedef struct{
    uint8_t reg:1;
    uint8_t imm:1;
    uint8_t off:1;
    uint8_t iindex:1;
    uint8_t base:1;
    uint8_t __unused_bits:3;
}m32_optype;

typedef struct{
    m32_optype type;
    uint32_t value;
}m32_operand;

typedef struct{
    char *mnemonic;
    uint8_t operand_count;
    m32_operand operands[MAX_OPERANDS];
}m32_insn;

off_t get_fsize(char *path){
    struct stat dst;
    if(stat(path, &dst) < 0){
        fprintf(stderr, "stat(): %s\n", strerror(errno));
        return -1;
    }
    return dst.st_size;
}

uint8_t get_opcode(uint32_t insn){
    return (insn>>(32-6))&0x3f;
}

m32_insn *disasm_m32_insnR(uint32_t insn){
    m32_insn_R *insn_r = (m32_insn_R *)&insn;
    m32_insn *dis = NULL;

    dis = (m32_insn *)malloc(sizeof(m32_insn));
    if(!dis) return NULL;
    memset(dis, 0, sizeof(m32_insn));

    switch(insn&0x3f){
        case m32_syscall:
            dis->mnemonic = m32_insnR_strtab[m32_syscall];
            return dis;
        case m32_nop:
            if(insn == 0){
                dis->mnemonic = m32_insnR_strtab[m32_nop];
                return dis;
            }
            free(dis);
            return NULL;

        case m32_jr:
        case m32_jalr:
            dis->mnemonic = m32_insnR_strtab[insn_r->func];
            dis->operand_count = 1;

            dis->operands[0].type.reg = 1;
            dis->operands[0].value = (insn>>21)&31;
            return dis;

        case m32_addu:
        case m32_add:
        case m32_or:
        case m32_xor:
            dis->mnemonic = m32_insnR_strtab[insn_r->func];
            dis->operand_count = 3;

            dis->operands[0].value = (insn>>11)&31;
            dis->operands[0].type.reg = 1;

            dis->operands[1].value = (insn>>21)&31;
            dis->operands[1].type.reg = 1;
            
            dis->operands[2].value = (insn>>16)&31;
            dis->operands[2].type.reg = 1;
            return dis;

        default:
            free(dis);
            return NULL;
        
    }
    return NULL;
}

m32_insn *disasm_m32_insnI(uint32_t insn){
    m32_insn *dis = NULL;

    dis = (m32_insn *)malloc(sizeof(m32_insn));
    if(!dis) return NULL;
    memset(dis, 0, sizeof(m32_insn));

    if(get_opcode(insn) == 1){
        switch((insn>>16)&31){
            case m32_bal:
                dis->mnemonic = m32_regimmI_strtab[(insn>>16)&31];
                dis->operand_count = 1;

                dis->operands[0].type.off = 1;
                dis->operands[0].value = pc+4+((insn&0xffff)<<2);
                return dis;
        }
    }

    switch((insn>>(32-6)&0x3f)){
        case m32_lui:
            dis->mnemonic = m32_insnI_strtab[(insn>>(32-6)&0x3f)];
            dis->operand_count = 2;

            dis->operands[0].value = (insn>>16)&31;
            dis->operands[0].type.reg = 1;

            dis->operands[1].value = (insn&0xffff);
            dis->operands[1].type.imm = 1;
            break;
        case m32_addiu:
            dis->mnemonic = m32_insnI_strtab[(insn>>(32-6)&0x3f)];
            dis->operand_count = 3;

            dis->operands[0].type.reg = 1;
            dis->operands[0].value = ((insn>>16)&31);

            dis->operands[1].type.reg = 1;
            dis->operands[1].value = ((insn>>21)&31);

            dis->operands[2].type.imm = 1;
            dis->operands[2].value = (insn&0xffff);
            break;
        case m32_lw:
        case m32_sw:
            dis->mnemonic = m32_insnI_strtab[(insn>>(32-6)&0x3f)];

            dis->operand_count = 3;
            dis->operands[0].type.reg = 1;
            dis->operands[0].value = (insn>>16)&31;

            dis->operands[1].type.base = 1;
            dis->operands[1].value = (insn>>21)&31;

            dis->operands[2].type.off = 1;
            dis->operands[2].value = insn&0xffff;
            break;
    }

    return dis;
}

void print_m32_insn(m32_insn *insn, uint32_t enc){
    uint8_t operand_index = 0;
    m32_operand *cur_operand = NULL;
    if(insn){
        printf("0x%x:    %08x    ", pc, enc);
        if(insn->mnemonic){
            printf("%s ", insn->mnemonic);
            for(operand_index = 0; operand_index < insn->operand_count; operand_index++){
                cur_operand = &insn->operands[operand_index];
                if(cur_operand->type.reg) printf("%s", m32_reg_strtab[cur_operand->value]);
                else if(cur_operand->type.base){
                    if((operand_index+1) < insn->operand_count){
                        printf("%d(%s)", (int16_t)(insn->operands[++operand_index].value), m32_reg_strtab[cur_operand->value]);
                    }
                }
                else printf("0x%x", cur_operand->value);

                if((operand_index+1) < insn->operand_count) printf(", ");
            }
        }
        printf("\n");
    }
}

void disasm_mips32(uint8_t *buf, long size){
    uint32_t *insns = (uint32_t *)buf;
    long index = 0;
    uint32_t insn = 0;
    m32_insn *dis = NULL;

    if(!buf || size <= 0) return;
    for(; index < (size/4); index++){
        insn = bswap_32(insns[index]);

        switch(get_opcode(insn)){
            case 0:
                dis = disasm_m32_insnR(insn);
                break;

            case 1:
            case m32_lui:
            case m32_lw:
            case m32_sw:
            case m32_addiu:
                dis = disasm_m32_insnI(insn);
                break;
        }

        if(dis){
            print_m32_insn(dis, insn);
            free(dis);
            dis = NULL;
        }
        pc += 4;
    }

    return;
}

int main(void){
    uint8_t *insn_buf = NULL;
    off_t fsize = 0;
    int fd = -1;

    if((fsize = get_fsize(TARGET)) < 0) return 1;
    printf("Instructions: %ld\n", (fsize/4));
    
    if((fd = open(TARGET, O_RDONLY)) < 0){
        fprintf(stderr, "open(): %s\n", strerror(errno));
        return 1;
    }

    insn_buf = (uint8_t *)malloc(fsize);
    if(!insn_buf){
        fprintf(stderr, "malloc(): %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    memset(insn_buf, 0, fsize);
    if(read(fd, insn_buf, fsize) != fsize){
        fprintf(stderr, "read(): Failed to read %ld bytes\n", fsize);
        free(insn_buf);
        close(fd);
        return 1;
    }
    close(fd);

    disasm_mips32(insn_buf, fsize);
    return 0;
}