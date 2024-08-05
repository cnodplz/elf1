#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
*   Custom Readelf implementation
*
*   linux command to show macros:  cpp -dM /dev/null
*                                  readelf --section-headers elf
*/

#define RED "\e[0;31m"
#define GRN "\e[0;32m"
#define YEL "\e[0;33m"
#define WHT "\e[0;37m"
#define PRP "\e[0;95m"
#define CLR "\e[0m"

char *get_exec_type(int a) {
    char *arr[] = {"No file type", "Relocatable file", "Executable file", "Shared object file", "Core file", "Operating system-specific", "Operating system-specific", "Processor-specific", "Processor-specific"};
    switch (a) {
        case 0:
            return arr[0];
        case 1:
            return arr[1];
        case 2:
            return arr[2];
        case 3:
            return arr[3];
        case 4:
            return arr[4];
        case 0xfe00:
            return arr[5];
        case 0xfeff:
            return arr[6];
        case 0xff00:
            return arr[7];
        case 0xffff:
            return arr[8];
        default:
            return "";
    }
}

char *get_machine_arch(int a) {

    char *arr[] = {"No machine", "AT&T WE 32100", "SPARC", "Intel 80386", "Motorola 68000", "Motorola 88000", "Reserved for future use (was EM_486)", "Intel 80860", "MIPS I Architecture", "IBM System/370 Processor", "MIPS RS3000 Little-endian", "Reserved for future use", "Reserved for future use", "Reserved for future use", "Reserved for future use", "Hewlett-Packard PA-RISC", "Reserved for future use", "Fujitsu VPP500", "Enhanced instruction set SPARC", "Intel 80960", "PowerPC", "64-bit PowerPC", "IBM System/390 Processor", "Reserved for future use", "Reserved for future use", "Reserved for future use", "Reserved for future use", "Reserved for future use", "Reserved for future use", "Reserved for future use", "Reserved for future use", "Reserved for future use", "Reserved for future use", "Reserved for future use", "Reserved for future use", "Reserved for future use", "NEC V800", "Fujitsu FR20", "TRW RH-32", "Motorola RCE", "Advanced RISC Machines ARM", "Digital Alpha", "Hitachi SH", "SPARC Version 9", "Siemens TriCore embedded processor", "Argonaut RISC Core, Argonaut Technologies Inc.", "Hitachi H8/300", "Hitachi H8/300H", "Hitachi H8S", "Hitachi H8/500", "Intel IA-64 processor architecture", "Stanford MIPS-X", "Motorola ColdFire", "Motorola M68HC12", "Fujitsu MMA Multimedia Accelerator", "Siemens PCP", "Sony nCPU embedded RISC processor", "Denso NDR1 microprocessor", "Motorola Star*Core processor", "Toyota ME16 processor", "STMicroelectronics ST100 processor", "Advanced Logic Corp. TinyJ embedded processor family", "AMD x86-64 architecture", "Sony DSP Processor", "Digital Equipment Corp. PDP-10", "Digital Equipment Corp. PDP-11", "Siemens FX66 microcontroller", "STMicroelectronics ST9+ 8/16 bit microcontroller", "STMicroelectronics ST7 8-bit microcontroller", "Motorola MC68HC16 Microcontroller", "Motorola MC68HC11 Microcontroller", "Motorola MC68HC08 Microcontroller", "Motorola MC68HC05 Microcontroller", "Silicon Graphics SVx", "STMicroelectronics ST19 8-bit microcontroller", "Digital VAX", "Axis Communications 32-bit embedded processor", "Infineon Technologies 32-bit embedded processor", "Element 14 64-bit DSP Processor", "LSI Logic 16-bit DSP Processor", "Donald Knuths educational 64-bit processor", "Harvard University machine-independent object files", "SiTera Prism", "Atmel AVR 8-bit microcontroller", "Fujitsu FR30", "Mitsubishi D10V", "Mitsubishi D30V", "NEC v850", "Mitsubishi M32R", "Matsushita MN10300", "Matsushita MN10200", "picoJava", "OpenRISC 32-bit embedded processor", "ARC Cores Tangent-A5", "Tensilica Xtensa Architecture", "Alphamosaic VideoCore processor", "Thompson Multimedia General Purpose Processor", "National Semiconductor 32000 series", "Tenor Network TPC processor", "Trebia SNP 1000 processor", "STMicroelectronics (www.st.com) ST200 microcontroller"};
    return arr[a];
}

struct custom_elf32 {
    // ELF header is 52 or 64 bytes for 32 or 64 bit binaries
    /*
      4  0x00-0x03 : e_ident[EI_MAG0-EI_MAG3]  # magic number 0x7F + 0x45 0x4C 0x46 (ELF)
      1  0x04      : e_ident[EI_CLASS]         # value 1 = 32, 2 = 64
      1  0x05      : e_ident[EI_DATA]
      1  0x06      : e_ident[EI_VERSION]
      1  0x07      : e_ident[EI_OSABI]
      1  0x08      : e_ident[EI_ABIVERSION]
      7  0x09-0x0F : e_ident[EI_PAD]
      2  0x10      : e_type
      2  0x12      : e_machine
      4  0x14      : e_version
      4  0x18      : e_entry
      4  0x1C      : e_phoff
      4  0x20      : e_shoff
      4  0x24      : e_flags
      2  0x28      : e_ehsize
      2  0x2A      : e_phentsize
      2  0x2C      : e_phnum
      2  0x2E      : e_shentsize
      2  0x30      : e_shnum
      2  0x32      : e_shstrndx
    */

    // e_ident: array of bytes specifies how to interpret file
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct custom_elf64 {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
    unsigned char e_pad64[12];
};

void print64(struct custom_elf64 **a) {
    printf("e_type      : %-8d : %s\n"
           "e_machine   : %-8d : %s\n"
           "e_version   : %-8d : \n"
           "e_entry     : %-8x : Virtual address\n"
           "e_phoff     : %-8d : Program header offset (bytes)\n"
           "e_shoff     : %-8d : Section header offset (bytes)\n"
           "e_flags     : %-8d : \n"
           "e_ehsize    : %-8d : ELF header size (bytes)\n"
           "e_phentsize : %-8d : \n"
           "e_phnum     : %-8d : \n"
           "e_shentsize : %-8d : \n"
           "e_shnum     : %-8d : \n"
           "e_shstrndx  : %-8d : \n",
            (*a)->e_type, get_exec_type((*a)->e_type), (*a)->e_machine, get_machine_arch((*a)->e_machine), (*a)->e_version,(*a)->e_entry,
            (*a)->e_phoff, (*a)->e_shoff, (*a)->e_flags, (*a)->e_ehsize,
            (*a)->e_phentsize, (*a)->e_phnum, (*a)->e_shentsize, (*a)->e_shnum,
            (*a)->e_shstrndx);
}

// function to read and return bytes in a file
void f_readbytes(char* fileName, int CHUNKSIZE, int offset_start, int offset_end) {
    FILE* file1;
    unsigned char chunk[CHUNKSIZE];
    char c;
    int i = 0;
    int j = 0;
    int range_start = offset_start;
    int range_end = offset_end;
    printf(YEL"[%s]\n"CLR, __func__);

    file1 = fopen(fileName, "r");
    if (file1 == NULL) {
        printf("ERR: fileread %s\n", fileName);
        exit(1);
    }

    fseek(file1, 4, SEEK_SET);
    char e1 = fgetc(file1);
    if (e1 == 1) {
        printf("e_ident[EI_CLASS] == %d # 32-bit\n", e1);
        fseek(file1, 0, SEEK_SET);
    }
    else if (e1 == 2) {
        printf("e_ident[EI_CLASS] == %d # 64-bit\n", e1);
        fseek(file1, 0, SEEK_SET);
    }
    else {
        fseek(file1, 0, SEEK_SET);
    }

    for (i = 0, j = 0; i <= range_end && c != EOF; i++) {
        c = fgetc(file1);
        if (i >= range_start) {
            chunk[j] = c;
            if (c != 0) {
                printf(RED"%02X "CLR, c);
            }
            else {
                printf(PRP"%02X "CLR, c);
            }
            j++;
        }
    }
    printf("\n");

    fclose(file1);
}

int main(int argc, char** argv) {
    f_readbytes("a32.out", 16, 0, 15);
    printf("\n");
    f_readbytes("a.out", 16, 0, 15);

    struct custom_elf32* custom_elf1;
    custom_elf1 = calloc(0, sizeof(custom_elf1));
    struct custom_elf64* custom_elf2;
    custom_elf2 = calloc(0, sizeof(custom_elf2));

    printf(YEL"\n[%s]\n"CLR, __func__);
    printf("sizeof custom_elf1 (%d)\n", sizeof(*custom_elf1));
    printf("sizeof custom_elf2 (%d)\n", sizeof(*custom_elf2));
    free(custom_elf1);
    free(custom_elf2);

    // try reading header sized stream into matching struct
    unsigned char bytesbuf[64];
    char* fileName2 = "a.out";
    FILE* file2;
    file2 = fopen(fileName2, "rb");
    if (file2 == NULL) {
        printf("ERR: fileread2 %s\n", fileName2);
        exit(1);
    }

    struct custom_elf64* custom_elf3;
    custom_elf3 = calloc(0, sizeof(custom_elf3));
    printf("fread(%d) bytes --> struct custom_elf64* custom_elf3\n", fread(custom_elf3, 1, 64, file2));
    print64(&custom_elf3);

    return 0;
}
