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

// #include <mbedtls/sha256.h>

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
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
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

	paddr_t	pa = (paddr_t)(syscall_phys);

	core_mmu_add_mapping(MEM_AREA_RAM_NSEC, pa, compat_syscall_count * sizeof(unsigned long));
	unsigned long * syscall_va = phys_to_virt(pa, MEM_AREA_RAM_NSEC, sizeof(unsigned long) * compat_syscall_count);

	// params[0].value.a = syscall_va;
	// params[0].value.b = compat_syscall_count;

	for(int i = 0; i < compat_syscall_count; i++){
		IMSG("[SYSCALL #%i]: %lx", i, syscall_va[i]);
	}

	void *ctx = NULL;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if(res) return res;

	IMSG("CRYPTO_HASH_ALLCOT_CTX ok");
	res = crypto_hash_init(ctx);
	if(res) goto out;

	// hash get data in LE format
	IMSG("crypto_hash_init ok");
	res = crypto_hash_update(ctx, syscall_va, (compat_syscall_count * sizeof(unsigned long)));
	if(res) goto out;

	IMSG("crypto_hash_update ok");

	// res = crypto_hash_update(ctx, syscall_va, (compat_syscall_count * sizeof(unsigned long *)));
	if(res) goto out;
	// IMSG("crypto_hash_update ok");

	uint8_t digest[TEE_SHA256_HASH_SIZE] = { };
	res = crypto_hash_final(ctx, digest, 32);
	memcpy(params[0].memref.buffer, digest, 32);
	IMSG("crypto_hash_final ok");


out:
	crypto_hash_free_ctx(ctx);
	IMSG("crypto_hash_free_ctx ok");

	IMSG("[SYSCALL HASH]: %s", digest);
	IMSG("");
	IMSG("");
	for(int i = 0; i < 32; i++){
		IMSG("[SYSCALL HASH]: %c (%x)", digest[i], digest[i]);
	}

	core_mmu_remove_mapping(MEM_AREA_RAM_NSEC, pa, compat_syscall_count * sizeof(unsigned long));

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