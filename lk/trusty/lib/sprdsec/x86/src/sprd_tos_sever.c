#include "sprd_verify.h"
#include "sprd_stub_sec.h"
#include "sprd_mv_hypercalls.h"
//#include "sec_string.h"
//#include "sec_common.h"
#include "sprd_firewall.h"

#define PUBKEY_PADDR_LEN 0x1000
#define SEC_VERIFY_CMD 0x01
#define SEC_FIREWALL_CMD 0x02
#define SEC_GETHBK_CMD 0x08
/*add fastboot cmd for iwhale2*/
#define FUNCTYPE_GET_SOCID 0x03
#define FUNCTYPE_GET_LCS 0x0A
#define FUNCTYPE_SET_RMA 0x0B


void sprd_tos_service(uint32_t vmm_data)
{
	uint32_t *data_vaddr = NULL;
	 struct vmm_shared_data *vptr = NULL;
	if(vmm_data <=0) {
		//printf("vmm share data is null\n");
		while(1);
	}

	if(gPubKeyAddr <= 0) {
		//printf("have not reserved 4k physical addr\n");
		while(1);
	}
#if 0/*do not need map here, wd tos has been mapped it ,so we del it here*/
	if (sprd_mmu_map(vmm_data,sizeof(struct vmm_shared_data),&data_vaddr)) {
		printf("can not map vmm_data phy addr\n");
		while(1);
	}
        vptr = (struct vmm_shared_data *)data_vaddr;
#endif
        vptr = (struct vmm_shared_data *)vmm_data;
        volatile uint32_t *ptr = vptr->pal_shared_mem_data;
	uint32_t cmd = ptr[3];

	switch (cmd){
		case SEC_VERIFY_CMD:
			{
				sprd_verify_image(ptr,data_vaddr);
				break;
			}
		case SEC_FIREWALL_CMD:
			{
				sprd_fw_config(ptr,data_vaddr);
				break;
			}
		case SEC_GETHBK_CMD:
			{
				sprd_save_hbk(ptr,data_vaddr);
				break;
			}
		/*add fastboot cmd for iwhale2*/
		case FUNCTYPE_GET_LCS:
			{
				sprd_get_lifecycle(ptr,data_vaddr);
				break;
			}
		case FUNCTYPE_GET_SOCID:
			{
				sprd_get_socid(ptr,data_vaddr);
				break;
			}
		case FUNCTYPE_SET_RMA:
			{
				sprd_set_rma_mode();
				break;
			}
	}
}

