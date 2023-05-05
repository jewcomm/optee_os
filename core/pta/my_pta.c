#include <config.h>
#include <crypto/crypto.h>
#include <kernel/linker.h>
#include <kernel/pseudo_ta.h>
#include <kernel/ts_store.h>
#include <kernel/user_mode_ctx.h>
#include <mm/file.h>
#include <stdlib.h>
#include <string.h>
#include <tee/entry_std.h>
#include <tee/tee_fs.h>
#include <tee/tee_pobj.h>
#include <tee/uuid.h>
#include <utee_defines.h>
#include <mm/core_mmu.h>

#include <mm/core_memprot.h>

#define PTA_NAME "my_pta.pta"

#define PAGE_SIZE 4096

#define MY_PTA_UUID { 0x2a38dd39, 0x3414, 0x4b58, \
		{ 0xa3, 0xbd, 0x73, 0x91, 0x8a, 0xe6, 0x2e, 0x68 } }

#define PTA_SYS_CALL_SAVER 1
#define PTA_SYS_CALL_GETTER 2

uint32_t compat_syscall_count = 0;
uint32_t syscall_phys = 0;

static TEE_Result sys_call_receiver(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	TEE_Result res = TEE_SUCCESS;

	if (param_types != exp_param_types){
		DMSG("[\"%s\"]ERROR PARAM", PTA_NAME);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if(compat_syscall_count || syscall_phys){
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	syscall_phys = params[0].value.a;
	compat_syscall_count = params[0].value.b;

	DMSG("[\"%s\"]SYSCALL COUNT: %ld", PTA_NAME, compat_syscall_count);
	DMSG("[\"%s\"]SYSCALL_PHYS: %lx", PTA_NAME, syscall_phys);
		
	return res;
}

static TEE_Result sys_call_sender(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	TEE_Result res = TEE_SUCCESS;

	if (param_types != exp_param_types){
		DMSG("[\"%s\"]ERROR PARAM", PTA_NAME);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if(!(syscall_phys || compat_syscall_count)){
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	params[0].value.a = syscall_phys;
	params[0].value.b = compat_syscall_count;

	paddr_t	pa = (paddr_t)(syscall_phys);
	uint32_t size_syscall_table = compat_syscall_count;

	core_mmu_add_mapping(MEM_AREA_RAM_NSEC, pa, size_syscall_table * sizeof(unsigned long));
	unsigned long * compat_syscal_ptr = phys_to_virt(pa, MEM_AREA_RAM_NSEC, sizeof(unsigned long) * size_syscall_table);

	IMSG("SYSCALL_ADDR_VA: %lx", compat_syscal_ptr[0]);

	return res;
}

static TEE_Result invoke_command(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */
	FMSG("command entry point for pseudo-TA \"%s\"", PTA_NAME);

	switch (cmd_id) {
	case PTA_SYS_CALL_SAVER:
		return sys_call_receiver(param_types, params);
	case PTA_SYS_CALL_GETTER:
		return sys_call_sender(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

pseudo_ta_register(.uuid = MY_PTA_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);