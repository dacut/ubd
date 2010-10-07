#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xb796cb09, "struct_module" },
	{ 0x57383fcf, "no_llseek" },
	{ 0xb65be0f9, "kmem_cache_alloc" },
	{ 0x4902d07, "kmalloc_caches" },
	{ 0x37a0cba, "kfree" },
	{ 0x5938f506, "misc_deregister" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "A7D6DD1BAC2EA4A9D5B534F");
