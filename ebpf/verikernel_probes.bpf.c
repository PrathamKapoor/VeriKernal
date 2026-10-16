#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct inode_cache_key {__u32 syscall_nr,pad;__u64 dev_id,inode_nr,mtime_ns;};
struct inode___vk_old {struct timespec64 i_mtime;} __attribute__((preserve_access_index));
struct inode___vk_middle {struct timespec64 __i_mtime;} __attribute__((preserve_access_index));
struct inode___vk_current {__s64 i_mtime_sec;__u32 i_mtime_nsec;} __attribute__((preserve_access_index));
struct event {__u64 seq_no,timestamp_ns;__u32 pid,tid,syscall_nr;__s32 fault_injected;__u64 dev_id,inode_nr,mtime_ns,call_stack_hash;__u8 target_digest[32],ratchet_tag[32];};
struct {__uint(type,BPF_MAP_TYPE_RINGBUF);__uint(max_entries,16777216);} events_ringbuf SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_LRU_HASH);__uint(max_entries,16384);__type(key,struct inode_cache_key);__type(value,__u8);} inode_dedup_map SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,16384);__type(key,__u64);__type(value,__u8);} contract_allow_map SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,__u8[32]);} ratchet_state_map SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,__u64);} sequence_map SEC(".maps");
struct crypto_work {__u64 h[8],v[16],m[16];__u8 input[256];};
struct {__uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct crypto_work);} crypto_work_map SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,__u64);} loss_count_map SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,__u32);} ratchet_ready_map SEC(".maps");
const volatile __u32 enforce=0;
const volatile __u32 target_tgid=0;
const volatile __s32 kernel_fault_errno=0;

static const __u64 iv[8]={0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};
static const __u8 sigma[12][16]={
 {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
 {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
 {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
 {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
 {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
 {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
 {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
 {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
 {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
 {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
 {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
 {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3}};
static __always_inline __u64 rotate(__u64 x,int n){return (x>>n)|(x<<(64-n));}
#define G(a,b,c,d,x,y) do {w->v[a]+=w->v[b]+(x);w->v[d]=rotate(w->v[d]^w->v[a],32);w->v[c]+=w->v[d];w->v[b]=rotate(w->v[b]^w->v[c],24);w->v[a]+=w->v[b]+(y);w->v[d]=rotate(w->v[d]^w->v[a],16);w->v[c]+=w->v[d];w->v[b]=rotate(w->v[b]^w->v[c],63);} while(0)
static __always_inline void compress(struct crypto_work *w,int offset,__u64 count,int final){
    for(int i=0;i<16;i++){__u64 x=0;for(int j=0;j<8;j++)x|=(__u64)w->input[offset+i*8+j]<<(j*8);w->m[i]=x;w->v[i]=i<8?w->h[i]:iv[i-8];}
    w->v[12]^=count;if(final)w->v[14]=~w->v[14];
    for(int round=0;round<12;round++){
        const __u8 *s=sigma[round];
        G(0,4,8,12,w->m[s[0]],w->m[s[1]]);G(1,5,9,13,w->m[s[2]],w->m[s[3]]);G(2,6,10,14,w->m[s[4]],w->m[s[5]]);G(3,7,11,15,w->m[s[6]],w->m[s[7]]);
        G(0,5,10,15,w->m[s[8]],w->m[s[9]]);G(1,6,11,12,w->m[s[10]],w->m[s[11]]);G(2,7,8,13,w->m[s[12]],w->m[s[13]]);G(3,4,9,14,w->m[s[14]],w->m[s[15]]);
    }
    for(int i=0;i<8;i++)w->h[i]^=w->v[i]^w->v[i+8];
}
static __always_inline void hash_input(struct crypto_work *w,int length,__u8 *out){
    for(int i=0;i<8;i++)w->h[i]=iv[i];w->h[0]^=0x01010020;
    if(length>128){compress(w,0,128,0);compress(w,128,length,1);}else{compress(w,0,length,1);}
    for(int i=0;i<32;i++)out[i]=(w->h[i/8]>>((i%8)*8))&255;
}
static __always_inline void clear_input(struct crypto_work *w){for(int i=0;i<256;i++)w->input[i]=0;}
static __always_inline int producer_tag(struct event *e){
    __u32 zero=0;__u32 *ready=bpf_map_lookup_elem(&ratchet_ready_map,&zero);
    __u8 *state=bpf_map_lookup_elem(&ratchet_state_map,&zero);
    struct crypto_work *w=bpf_map_lookup_elem(&crypto_work_map,&zero);
    if(!ready||!*ready||!state||!w)return -95;
    clear_input(w);
    for(int i=0;i<24;i++)w->input[i]=((__u8 *)&e->dev_id)[i];
    hash_input(w,24,e->target_digest);
    clear_input(w);
    const char tag_domain[]="VK-RATCHET-TAG-V1";
    for(int i=0;i<sizeof(tag_domain)-1;i++)w->input[i]=tag_domain[i];
    for(int i=0;i<32;i++)w->input[sizeof(tag_domain)-1+i]=state[i];
    for(int i=0;i<96;i++)w->input[sizeof(tag_domain)-1+32+i]=((__u8 *)e)[i];
    hash_input(w,sizeof(tag_domain)-1+32+96,e->ratchet_tag);
    clear_input(w);
    const char step_domain[]="VK-RATCHET-STEP-V1";
    for(int i=0;i<sizeof(step_domain)-1;i++)w->input[i]=step_domain[i];
    for(int i=0;i<32;i++){w->input[sizeof(step_domain)-1+i]=state[i];w->input[sizeof(step_domain)-1+32+i]=e->ratchet_tag[i];state[i]=0;}
    hash_input(w,sizeof(step_domain)-1+64,state);
    clear_input(w);for(int i=0;i<8;i++)w->h[i]=0;for(int i=0;i<16;i++){w->m[i]=0;w->v[i]=0;}
    return 0;
}

static __always_inline int emit(__u32 op,struct inode *inode) {
    if((bpf_get_current_pid_tgid()>>32)!=target_tgid)return 0;
    struct inode_cache_key key={.syscall_nr=op};
    if(inode){
        key.inode_nr=BPF_CORE_READ(inode,i_ino);key.dev_id=BPF_CORE_READ(inode,i_sb,s_dev);
        struct inode___vk_current *current=(void *)inode;
        struct inode___vk_middle *middle=(void *)inode;
        struct inode___vk_old *old=(void *)inode;
        if(bpf_core_field_exists(current->i_mtime_sec))key.mtime_ns=BPF_CORE_READ(current,i_mtime_sec)*1000000000ULL+BPF_CORE_READ(current,i_mtime_nsec);
        else if(bpf_core_field_exists(middle->__i_mtime))key.mtime_ns=BPF_CORE_READ(middle,__i_mtime.tv_sec)*1000000000ULL+BPF_CORE_READ(middle,__i_mtime.tv_nsec);
        else key.mtime_ns=BPF_CORE_READ(old,i_mtime.tv_sec)*1000000000ULL+BPF_CORE_READ(old,i_mtime.tv_nsec);
    }
    __u64 identity=key.inode_nr^(key.dev_id<<32);
    if(enforce && !bpf_map_lookup_elem(&contract_allow_map,&identity))return -13;
    if(inode && bpf_map_lookup_elem(&inode_dedup_map,&key))return 0;
    struct event *e=bpf_ringbuf_reserve(&events_ringbuf,sizeof(*e),0);
    if(!e){__u32 zero=0;__u64 *loss=bpf_map_lookup_elem(&loss_count_map,&zero);if(loss)(*loss)++;return enforce?-28:0;}
    __builtin_memset(e,0,sizeof(*e));
    __u32 zero=0;__u64 *seq=bpf_map_lookup_elem(&sequence_map,&zero);
    if(seq)e->seq_no=__sync_fetch_and_add(seq,1);
    __u64 ids=bpf_get_current_pid_tgid();e->pid=ids>>32;e->tid=ids;e->timestamp_ns=bpf_ktime_get_ns();e->syscall_nr=op;e->dev_id=key.dev_id;e->inode_nr=key.inode_nr;e->mtime_ns=key.mtime_ns;
    if(producer_tag(e)){bpf_ringbuf_discard(e,0);return enforce?-95:0;}
    __u8 present=1;if(inode)bpf_map_update_elem(&inode_dedup_map,&key,&present,BPF_ANY);
    bpf_ringbuf_submit(e,0);return 0;
}
SEC("lsm/file_open") int BPF_PROG(vk_file,struct file *file,int ret){if(ret)return ret;return emit(2,BPF_CORE_READ(file,f_inode));}
SEC("lsm/bprm_check_security") int BPF_PROG(vk_exec,struct linux_binprm *bprm,int ret){if(ret)return ret;struct file *f=BPF_CORE_READ(bprm,file);return emit(1,BPF_CORE_READ(f,f_inode));}
SEC("lsm/socket_connect") int BPF_PROG(vk_connect,struct socket *sock,struct sockaddr *addr,int addrlen,int ret){if(ret)return ret;return emit(3,0);}
SEC("kprobe/ksys_read") int BPF_KPROBE(vk_read){
#ifdef VK_ENABLE_OVERRIDE
    if((bpf_get_current_pid_tgid()>>32)==target_tgid && kernel_fault_errno>0)return bpf_override_return(ctx,-kernel_fault_errno);
#endif
    return emit(9,0);
}
char LICENSE[] SEC("license")="GPL";
