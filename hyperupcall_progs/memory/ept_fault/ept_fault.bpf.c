// #include <linux/bpf.h>
#include "../../vmlinux.h"
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */

#define PAGE_SIZE 4096
#define MAX_GUEST_PAGES 1572864ULL
#define MAX_GUEST_MEM PAGE_SIZE*MAX_GUEST_PAGES
#define PTES_PER_TABLE 512
#define PFN_CACHE_SIZE 8192
#define MAX_MEMSLOTS 16
#define DEF_FLAGS 0x600000000000B77ULL
#define N_BLANKS 0
#define REMAP_HISTORY_LEN 4
#define MAPPING_TABLE_SIZE MAX_GUEST_PAGES
#define MAPPING_HISTORY_TABLE_SIZE (MAPPING_TABLE_SIZE*REMAP_HISTORY_LEN)

#define GET_PAGE_ADDR(x) (x & 0xFFFFFFFFFFFF000ULL)
#define PTE_PRESENT_BIT (1ULL << 0)

enum counter_type {
    BYPASS_ALLOCS_INDEX = 0,
    BYPASS_ALLOC_ATTEMPS,
    BYPASS_ALLOC_SUCCESS,
    BYPASS_REMAP_SUCCESS,
    REMAP_UPDATE_SUCCESS0,
    REMAP_UPDATE_SUCCESS1,
    REMAP_UPDATE_SUCCESS2,
    REMAP_UPDATE_SUCCESS3,
    REMAP_UPDATE_SUCCESS4,
    BYPASS_ALLOC_ENABLE,
    N_COUNTERS
};

enum remap_retval {
    REMAP_SUCCESS = 0,
    REMAP_FAIL,
    REMAP_EXIT
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PFN_CACHE_SIZE);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} pfn_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_GUEST_MEM / (PAGE_SIZE*PTES_PER_TABLE));
    __type(key, __u32);
    __type(value, __u64);
	__uint(map_flags, 1024); // BPF_F_MMAPABLE
} sp_headers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, N_COUNTERS);
    __type(key, __u32);
    __type(value, __u64);
	__uint(map_flags, 1024); // BPF_F_MMAPABLE
} counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_MEMSLOTS);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} l1_memslots_base_gfns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_MEMSLOTS);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} l1_memslots_npages SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_MEMSLOTS);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} l1_memslots_userspace_addr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_MEMSLOTS);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} l0_memslots_base_gfns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_MEMSLOTS);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} l0_memslots_npages SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_MEMSLOTS);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, 1024); // BPF_F_MMAPABLE
} l0_memslots_userspace_addr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAPPING_HISTORY_TABLE_SIZE);
    __type(key, __u32); // gpa
    __type(value, __u64); // pfn
    // __uint(map_flags, 1024); // BPF_F_MMAPABLE
} history_mapping_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAPPING_TABLE_SIZE);
    __type(key, __u32); // gpa
    __type(value, __u64); // pfn
    // __uint(map_flags, 1024); // BPF_F_MMAPABLE
} mapping_table SEC(".maps");


static __always_inline bool does_have_slot_in_l1(__u64 gfn) {
    __u64 pfn = 0;
    for (int i = 0; i < MAX_MEMSLOTS; i++) {
        int current_i = i;
        __u64 *base_gfn = bpf_map_lookup_elem(&l1_memslots_base_gfns, &current_i);
        __u64 *npages = bpf_map_lookup_elem(&l1_memslots_npages, &current_i);
        __u64 *userspace = bpf_map_lookup_elem(&l1_memslots_userspace_addr, &current_i);
        if (base_gfn == NULL || npages == NULL || userspace == NULL) {
            continue;
        }
        if (gfn >= *base_gfn && gfn < *base_gfn + *npages) {
            return (*npages > 1024*8);
        }
    }
    return false;
}


static __always_inline __u64 create_pte(__u64 pfn) {
    return (pfn << 12) | DEF_FLAGS;
}

static __always_inline int do_remap(struct pt_regs *ctx, __u64 gfn) {
    int key;
    int *counter_value;
    __u64 *spte;    
    spte = bpf_map_lookup_elem(&mapping_table, &gfn);
    if (spte == NULL || *spte == 0ULL) {
        return REMAP_FAIL;
    }
    bpf_printk("spte: %llx gfn: %llx\n", *spte, gfn);
    // if ((*spte & 0xFFFULL) != (DEF_FLAGS & 0xFFFULL)) {
        return REMAP_EXIT;
    // }
    bpf_override_return(ctx, *spte);
    key = BYPASS_REMAP_SUCCESS;
    counter_value = bpf_map_lookup_elem(&counter, &key);
    if (counter_value != NULL) {
        (*counter_value)++;
        bpf_map_update_elem(&counter, &key, counter_value, BPF_ANY);
    }
    return REMAP_SUCCESS;
}


static __always_inline __u64 l1_gpa_to_l0_hva(__u64 gpa) {
    __u64 gfn = gpa >> 12;
    __u64 *spte;
    int current_i;
    for (int i = 0; i < MAX_MEMSLOTS; i++) {
        current_i = i;
        __u64 *base_gfn = bpf_map_lookup_elem(&l0_memslots_base_gfns, &current_i);
        __u64 *npages = bpf_map_lookup_elem(&l0_memslots_npages, &current_i);
        __u64 *userspace = bpf_map_lookup_elem(&l0_memslots_userspace_addr, &current_i);
        if (base_gfn == NULL || npages == NULL || userspace == NULL) {
            continue;
        }
        if (gfn >= *base_gfn && gfn < *base_gfn + *npages) {
            return *userspace + (gpa - (*base_gfn << 12));
        }
    }
    return 0;
}

/*
* Page walk in L1. Returns the pte if it exists, 0 otherwise.
* 0 Would mean that the page is not mapped, and we can allocate a frame there.
*/
static __always_inline __u64 page_walk_in_l1(__u64 cr3_l1_pa, __u64 gpa) {
    int r;
    __u64 cr3_l0_va = l1_gpa_to_l0_hva(cr3_l1_pa); 
    __u64 l3_table, l2_table, l1_table, pte;
    r = bpf_probe_read_user(&l3_table, sizeof(l3_table), (void *)(cr3_l0_va + ((gpa >> 39) & 0x1FF) * 8));
    if (r != 0 || (l3_table & PTE_PRESENT_BIT) == 0) {
        return 0;
    }
    l3_table = GET_PAGE_ADDR(l3_table);
    l3_table = l1_gpa_to_l0_hva(l3_table);
    if (l3_table == 0) {
        return 0;
    }

    r = bpf_probe_read_user(&l2_table, sizeof(l2_table), (void *)(l3_table + ((gpa >> 30) & 0x1FF) * 8));
    if (r != 0 || (l2_table & PTE_PRESENT_BIT) == 0) {
        return 0;
    }
    l2_table = GET_PAGE_ADDR(l2_table);
    l2_table = l1_gpa_to_l0_hva(l2_table);
    if (l2_table == 0) {
        return 0;
    }

    r = bpf_probe_read_user(&l1_table, sizeof(l1_table), (void *)(l2_table + ((gpa >> 21) & 0x1FF) * 8));
    if (r != 0 || (l1_table & PTE_PRESENT_BIT) == 0) {
        return 0;
    }
    l1_table = GET_PAGE_ADDR(l1_table);
    l1_table = l1_gpa_to_l0_hva(l1_table);
    if (l1_table == 0) {
        return 0;
    }

    r = bpf_probe_read_user(&pte, sizeof(pte), (void *)(l1_table + ((gpa >> 12) & 0x1FF) * 8));
    if (r != 0 || (pte & PTE_PRESENT_BIT) == 0) {
        return 0;
    }

    return pte;
}


/* Fill gfn to sp struct, create pte and return it.
 * Current version returns both values
 */
SEC("kprobe")
int bypass_alloc_bpf(struct pt_regs *ctx) {
    bpf_override_return(ctx, 0);
    // return 0;
    int current_i, r;
    int key = 0;
    __u64 *pt;
    __u64 *pfn = 0, *pfn_complement = 0;
    __u64 *attemps_counter_value;
    __u64 *counter_value;
    __u64 *sptep;
    __u64 next_counter_value = 0, orig_counter_value = 0, complement_counter_value = 0, gpa = ctx->di & ~0xFFFULL, spte, cr3 = ctx->si;

    key = BYPASS_ALLOC_ATTEMPS;
    attemps_counter_value = bpf_map_lookup_elem(&counter, &key);
    if (attemps_counter_value == NULL) {
        return 0;
    }
    (*attemps_counter_value)++;
    bpf_map_update_elem(&counter, &key, attemps_counter_value, BPF_ANY);

    if (!does_have_slot_in_l1(gpa >> 12)) {
        // bpf_printk("gfn: %llx does not have slot\n", gpa >> 12);
        return 0;
    }

    if (*attemps_counter_value < N_BLANKS) {
        return 0;
    }

    key = BYPASS_ALLOC_ENABLE;
    counter_value = bpf_map_lookup_elem(&counter, &key);
    if (counter_value == NULL || *counter_value == 0) {
        return 0;
    }

    r = do_remap(ctx, gpa >> 12);
    if (r == REMAP_SUCCESS || r == REMAP_EXIT) {
        bpf_printk("remap r = %d, gpa = %llx\n", r, gpa);
        return 0;
    }

    r = page_walk_in_l1(cr3, gpa);
    if (r != 0) {
        bpf_printk("page_walk_in_l1: %llx\n", r);
        return 0;
    }

    key = BYPASS_ALLOCS_INDEX ;
    counter_value = bpf_map_lookup_elem(&counter, &key);
    bpf_printk("gpa: %llx\n", gpa);
    if (counter_value == NULL) {
        bpf_printk("failed to get counter value\n");
        return 0;
    }
    orig_counter_value = *counter_value;
    next_counter_value = (*counter_value + 1) % (PFN_CACHE_SIZE / 2);
    complement_counter_value = *counter_value + (PFN_CACHE_SIZE / 2);
    pfn = bpf_map_lookup_elem(&pfn_cache, counter_value);
    pfn_complement = bpf_map_lookup_elem(&pfn_cache, &complement_counter_value);
    bpf_printk("counter value: %llu pt: %p\n", orig_counter_value, pt);
    if (pfn == NULL || *pfn == 0 || pfn_complement == NULL || *pfn_complement == 0 || *pfn != *pfn_complement) {
        return 0;
    }
    bpf_printk("counter: %llu, pfn: %llx\n", next_counter_value, *pfn);
    // gpa = 0xfffffff992929292;
    key = BYPASS_ALLOC_SUCCESS;
    counter_value = bpf_map_lookup_elem(&counter, &key);
    if (counter_value != NULL) {
        (*counter_value)++;
        bpf_map_update_elem(&counter, &key, counter_value, BPF_ANY);
    }
    
    spte = create_pte(*pfn);
    bpf_override_return(ctx, spte);
    bpf_map_update_elem(&pfn_cache, &orig_counter_value, &gpa, BPF_ANY);
    bpf_map_update_elem(&mapping_table, &gpa, &spte, BPF_ANY);
    key = BYPASS_ALLOCS_INDEX;
    bpf_map_update_elem(&counter, &key, &next_counter_value, BPF_ANY);
    return 0;
}

SEC("kprobe")
int update_mapping(struct pt_regs *ctx) {
    __u64 gfn = ctx->di >> 12, epte = ctx->si, prev_epte = 0;
    unsigned int i = 0, gpa_key = 0, key = 0;
    bool updated_mapping = false;
    if (!does_have_slot_in_l1(gfn)) {
        return 0;
    }

    // Check if GPA exists in each mapping table
    for (i = 0; i < REMAP_HISTORY_LEN; i++) {
        gpa_key = (i * MAPPING_TABLE_SIZE) + gfn;
        __u64 *existing_epte = bpf_map_lookup_elem(&history_mapping_table, &gpa_key);
        if (existing_epte == NULL) bpf_printk("i: %d gpa: %llx, existing_epte: %llx, epte: %llx, prev_epte: %llx\n", i, gpa_key, existing_epte, epte, prev_epte);
        if (existing_epte != NULL) bpf_printk("i: %d gpa: %llx, *existing_epte: %llx, epte: %llx, prev_epte: %llx\n", i, gpa_key, *existing_epte, epte, prev_epte);
        if ((existing_epte == NULL || *existing_epte == 0ULL) && (prev_epte == 0 || prev_epte != epte)) {
            bpf_map_update_elem(&history_mapping_table, &gpa_key, &epte, BPF_ANY);
            updated_mapping = true;
            break;
        }
        else if ((existing_epte == NULL || *existing_epte == 0ULL) && (prev_epte == epte)) {
            break;
        }
        if (existing_epte != NULL) prev_epte = *existing_epte;
    }
    bpf_map_update_elem(&mapping_table, &gpa_key, &epte, BPF_ANY);

    key = REMAP_UPDATE_SUCCESS0 + i;
    __u64 *counter_value = bpf_map_lookup_elem(&counter, &key);
    if (updated_mapping && counter_value != NULL) {
        bpf_printk("updating counter %d, updated_mapping: %d gpa: %llx\n",key, updated_mapping, gpa_key);
        (*counter_value)++;
        bpf_map_update_elem(&counter, &key, counter_value, BPF_ANY);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
