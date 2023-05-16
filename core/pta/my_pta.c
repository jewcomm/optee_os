#include <config.h>
#include <crypto/crypto.h>
#include <kernel/linker.h>
#include <kernel/pseudo_ta.h>
#include <kernel/ts_store.h>
#include <kernel/user_mode_ctx.h>
#include <mm/file.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <tee/entry_std.h>
#include <tee/tee_fs.h>
#include <tee/tee_pobj.h>
#include <tee/uuid.h>
#include <utee_defines.h>
#include <mm/core_mmu.h>

#include <mm/core_memprot.h>

#define PTA_NAME "syscall_pta.pta"

#define ARM64_SYS_RESTART_SYSCALL 0xffff80000809c080ull

#define SYSCALL_PTA_UUID { 0x2a38dd39, 0x3414, 0x4b58, \
		{ 0xa3, 0xbd, 0x73, 0x91, 0x8a, 0xe6, 0x2e, 0x68 } }

#define PTA_SYS_CALL_SAVER 1
#define PTA_SYS_CALL_GETTER 2

uint32_t compat_syscall_count = 0;
unsigned long * syscall_va = NULL;
uint64_t syscall_shift;
bool syscall_shift_sign;

static TEE_Result sys_call_receiver(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	TEE_Result res = TEE_SUCCESS;

	paddr_t	pa; // physical address syscall

	if (param_types != exp_param_types){
		DMSG("[\"%s\"]ERROR PARAM", PTA_NAME);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// if this value already saved 
	if(compat_syscall_count || syscall_va){
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	compat_syscall_count = params[0].value.b;
	pa = (paddr_t)(params[0].value.a);
	syscall_va = core_mmu_add_mapping(MEM_AREA_RAM_NSEC, pa, 
										compat_syscall_count * sizeof(unsigned long));

	if(syscall_va[0] > ARM64_SYS_RESTART_SYSCALL) {
        syscall_shift = (uint64_t)syscall_va[0] - ARM64_SYS_RESTART_SYSCALL;
        syscall_shift_sign = true;
    } else {
        syscall_shift = ARM64_SYS_RESTART_SYSCALL - (uint64_t)syscall_va[0];
        syscall_shift_sign = false;
    }

	DMSG("[\"%s\"]SYSCALL COUNT: %ld", PTA_NAME, compat_syscall_count);
	DMSG("[\"%s\"]SYSCALL_VA(in OPTEE): %lx", PTA_NAME, syscall_va);

	DMSG("[SYSCALL 0]: %lx", syscall_va[0]);
	DMSG("[SYSCALL shift]: %lu", syscall_shift);
	DMSG("[SYSCALL shift]: %lx", syscall_shift);
	DMSG("[SYSCALL shift]: %i", syscall_shift_sign);

	if(syscall_shift_sign){
		if((syscall_va[0] - syscall_shift) != ARM64_SYS_RESTART_SYSCALL){
			DMSG("ERROR WITH SYSCALL_SHIFTING: %lx", ARM64_SYS_RESTART_SYSCALL + syscall_shift);
		}
	} else  {
		if((syscall_va[0] + syscall_shift) != ARM64_SYS_RESTART_SYSCALL){
			DMSG("ERROR WITH SYSCALL_SHIFTING: %lx", ARM64_SYS_RESTART_SYSCALL - syscall_shift);
		}
	}
	
	return res;
}

static TEE_Result sys_call_checker(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	TEE_Result res = TEE_SUCCESS;

	void *ctx = NULL; // for the crypto_hash
	uint8_t digest[TEE_SHA256_HASH_SIZE] = { }; 

	if (param_types != exp_param_types){
		DMSG("[\"%s\"]ERROR PARAM", PTA_NAME);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// if this value dont saved
	if(!(syscall_va || compat_syscall_count)){
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	unsigned long syscall_copy[compat_syscall_count];
	memset(syscall_copy, 0, (compat_syscall_count * sizeof(unsigned long)));
	// memcpy(syscall_copy, syscall_va, (compat_syscall_count * sizeof(unsigned long)));

	for(uint32_t i = 0; i < compat_syscall_count; i++){
		syscall_copy[i] = syscall_va[i] + (syscall_shift_sign? -syscall_shift: syscall_shift);
		DMSG("[SYSCALL #%i]: %lx \t(without KASLR): %lx", i, syscall_va[i], syscall_copy[i]);
	}

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if(res) return res;

	DMSG("CRYPTO_HASH_ALLCOT_CTX ok");
	res = crypto_hash_init(ctx);
	if(res) goto out;

	// hash get data in LE format
	DMSG("crypto_hash_init ok");
	res = crypto_hash_update(ctx, (const uint8_t *)syscall_copy, (compat_syscall_count * sizeof(unsigned long)));
	if(res) goto out;

	DMSG("crypto_hash_update ok");

	res = crypto_hash_final(ctx, digest, 32);
	memcpy(params[0].memref.buffer, digest, 32);
	DMSG("crypto_hash_final ok");

out:
	crypto_hash_free_ctx(ctx);
	DMSG("crypto_hash_free_ctx ok");

	DMSG("[SYSCALL HASH]: %s", digest);
	DMSG("");
	DMSG("");
	for(int i = 0; i < 32; i++){
		DMSG("[SYSCALL HASH]: %c (%x)", digest[i], digest[i]);
	}

	return res;
}

static TEE_Result invoke_command(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */
	DMSG("command entry point for pseudo-TA \"%s\"", PTA_NAME);

	switch (cmd_id) {
	case PTA_SYS_CALL_SAVER:
		return sys_call_receiver(param_types, params);
	case PTA_SYS_CALL_GETTER:
		return sys_call_checker(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

pseudo_ta_register(.uuid = SYSCALL_PTA_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);