#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <libiptc/libiptc.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/x_tables.h>

#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>


#define dbgBreak() __asm__("int3")

#define IP_PARTS_NATIVE(n)			\
(unsigned int)((n)>>24)&0xFF,			\
(unsigned int)((n)>>16)&0xFF,			\
(unsigned int)((n)>>8)&0xFF,			\
(unsigned int)((n)&0xFF)

#define IP_PARTS(n) IP_PARTS_NATIVE(ntohl(n))

struct Handle {
    int socketfd;
    struct ipt_getinfo info;
    struct ipt_get_entries* entries;
    _Bool changed;
};

#define TABLE_MAXNAMELEN 32

static inline int
print_match(const struct xt_entry_match* m)
{
    printf("Match name: `%s'\n", m->u.user.name);
    return 0;
}

#define DEBUG


/* Architecture of firewall rules is as follows:
 *
 * Chains go INPUT, FORWARD, OUTPUT then user chains.
 * Each user chain starts with an ERROR node.
 * Every chain ends with an unconditional jump: a RETURN for user chains,
 * and a POLICY for built-ins.
 */

static void dumpIptEntries(struct ipt_entry* entries, uint32_t num_entries, uint32_t* hook_entry) {

    // struct ipt_get_entries* entries = h->entries;
    // uint32_t num_entries = h->info.num_entries;
    struct ipt_entry* entry;
    struct ipt_entry_target* target;
    struct ipt_entry_match* match;
    entry = &entries[0];
    uint32_t idx = 0;
    _Bool user_chain = 0;
    const char* prevName = NULL;
    const char* userChainName = NULL;

    while (idx < num_entries) {

        size_t offset = (size_t)((void*)entry - (void*)entries);

        if (offset == hook_entry[NF_INET_LOCAL_OUT]) {
            printf("OUTPUT(%u) chains:\n", offset);
        }

        else if (offset == hook_entry[NF_INET_FORWARD]) {
            printf("FORWARD(%u) chains:\n", offset);
        }

        else if (offset == hook_entry[NF_INET_LOCAL_IN]) {
            printf("INPUT(%u) chains:\n", offset);
        }


        printf("Entry[%u, %lu]:\n", idx, offset);
        size_t i;
        printf("SRC IP: %u.%u.%u.%u/%u.%u.%u.%u\n",
            IP_PARTS(entry->ip.src.s_addr), IP_PARTS(entry->ip.smsk.s_addr));
        printf("DST IP: %u.%u.%u.%u/%u.%u.%u.%u\n",
            IP_PARTS(entry->ip.dst.s_addr), IP_PARTS(entry->ip.dmsk.s_addr));

        size_t namelen = strlen(entry->ip.iniface);
        printf("Interface: <%s>/", namelen ? entry->ip.iniface : "anywhere");
        for (i = 0; i < IFNAMSIZ; i++)
            printf("%c", entry->ip.iniface_mask[i] ? 'X' : '.');
        namelen = strlen(entry->ip.outiface);
        printf(" to <%s>/", namelen ? entry->ip.outiface : "anywhere");
        for (i = 0; i < IFNAMSIZ; i++)
            printf("%c", entry->ip.outiface_mask[i] ? 'X' : '.');
        printf("\nProtocol: %u\n", entry->ip.proto);
        printf("Flags: %02X\n", entry->ip.flags);
        printf("Invflags: %02X\n", entry->ip.invflags);
        printf("Counters: %llu packets, %llu bytes\n",
            (unsigned long long)entry->counters.pcnt, (unsigned long long)entry->counters.bcnt);
        printf("Cache: %08X\n", entry->nfcache);

        XT_MATCH_ITERATE(struct ipt_entry, entry, print_match);

        target = ipt_get_target(entry);
        namelen = strlen(target->u.user.name);

        printf("Target name: ");
        if (strcmp(target->u.user.name, XT_STANDARD_TARGET) == 0) {
            printf("%s [%u]\n", userChainName ? userChainName : "XT_STANDARD_TARGET", target->u.user.target_size);
            const unsigned char* data = target->data;
            int pos = *(const int*)data;
            if (pos < 0) {
                printf("verdict=%s\n",
                    pos == -NF_ACCEPT - 1 ? "NF_ACCEPT"
                    : pos == -NF_DROP - 1 ? "NF_DROP"
                    : pos == -NF_QUEUE - 1 ? "NF_QUEUE"
                    : pos == XT_RETURN ? "RETURN"
                    : "UNKNOWN");
            }

            else if (pos == offset + entry->next_offset) {
                puts("verdict=fallthrough");
            }

            else {
                printf("jump, target=%u\n", (u_int32_t)pos);
            }
        }

        // Start new user chain
        else if (strcmp(target->u.user.name, XT_ERROR_TARGET) == 0) {
            printf("%s [%u]\n", target->data, target->u.user.target_size);
            userChainName = target->data;
        }
#ifdef DEBUG
        fprintf(stderr, "next_offset = %u\n", entry->next_offset);
#endif

        entry = (struct ipt_entry*)((char*)entry + entry->next_offset);
        putchar('\n');
        idx++;
    }
}

struct Handle* checkTable(const char* tablename) {

    struct Handle* h;

    if (strlen(tablename) >= TABLE_MAXNAMELEN) {
        goto err;
    }

    int socketfd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
    if (socketfd < 0) {
        goto err;
    }

    struct ipt_getinfo info;
    strcpy(info.name, tablename);
    socklen_t len = sizeof(info);

    //Get info
    if (getsockopt(socketfd, IPPROTO_IP, IPT_SO_GET_INFO, &info, &len) < 0) {
        close(socketfd);
        goto err;
    }

    fprintf(stderr, "vaild_hooks=0x%x, num_entries=%u, size=%u\n",
        info.valid_hooks, info.num_entries, info.size);

    h = calloc(1, sizeof(*h));
    if (h == NULL) {
        goto err;
    }

    strcpy(h->info.name, info.name);

    h->entries = calloc(1, sizeof(struct ipt_get_entries) + info.size);
    strcpy(h->entries->name, info.name);
    h->entries->size = info.size;

    h->socketfd = socketfd;
    h->info = info;

    socklen_t len2 = sizeof(struct ipt_get_entries) + h->info.size;
    if (getsockopt(h->socketfd, IPPROTO_IP, IPT_SO_GET_ENTRIES, h->entries, &len2))
    {
        perror("IPT_SO_GET_ENTRIES");
        goto err;
    }

    dumpIptEntries(h->entries->entrytable, h->info.num_entries, h->info.hook_entry);

    return h;

err:
    return NULL;
}

int commitEntry(struct Handle* h) {


    /*Setup new entry*/

    struct ipt_entry* new_entry = calloc(1, (sizeof(struct ipt_entry)) + 0x200);
    inet_pton(AF_INET, "1.1.1.1", &new_entry->ip.src);
    inet_pton(AF_INET, "0.0.0.0", &new_entry->ip.dst);

    inet_pton(AF_INET, "255.255.255.255", &new_entry->ip.smsk);

    memset(&new_entry->ip.iniface_mask, 0, sizeof new_entry->ip.iniface_mask);
    memset(&new_entry->ip.outiface_mask, 0, sizeof new_entry->ip.outiface_mask);
    new_entry->ip.proto = IPPROTO_TCP;
    new_entry->target_offset = sizeof(struct ipt_entry);

    /* Setup the target to drop packets */
    struct xt_standard_target* std_target = (struct xt_standard_target*)((char*)new_entry + new_entry->target_offset);
    std_target->target.u.target_size = sizeof(struct xt_standard_target);
    strcpy(std_target->target.u.user.name, XT_STANDARD_TARGET);
    std_target->verdict = -NF_DROP - 1;


    new_entry->next_offset = sizeof(struct ipt_entry) + std_target->target.u.target_size;

    /*Alloc ipt_replace*/

    struct ipt_replace* rpl;

    uint32_t sizeAllocEntries = new_entry->next_offset;

    uint64_t count = 0;
    struct ipt_entry* entry = &h->entries->entrytable[0];
    while (count < h->info.num_entries) {
        sizeAllocEntries += entry->next_offset;
        entry = (struct ipt_entry*)((char*)entry + entry->next_offset);
        ++count;
    }

    uint32_t new_num = h->info.num_entries + 1;
    rpl = calloc(1, sizeof(*rpl) + sizeAllocEntries);

    uint32_t counterlen = sizeof(struct  xt_counters_info)
        + sizeof(struct xt_counters) * new_num;

    struct xt_counters_info* newcounters = calloc(1, counterlen);

    /*Setup entries for replacing*/

    entry = &rpl->entries[0];
    memcpy(entry, new_entry, new_entry->next_offset);

    count = 0;
    entry = (struct ipt_entry*)((char*)entry + entry->next_offset);
    struct ipt_entry* src_entry = &h->entries->entrytable[0];

    rpl->counters = calloc(h->info.num_entries,
        sizeof(struct xt_counters));

    while (count < h->info.num_entries) {
        memcpy(entry, src_entry, src_entry->next_offset);
        rpl->counters[count] = entry->counters;

        src_entry = (struct ipt_entry*)((char*)src_entry + src_entry->next_offset);
        entry = (struct ipt_entry*)((char*)entry + entry->next_offset);
        ++count;
    }

    strcpy(rpl->name, h->info.name);
    rpl->num_entries = new_num;
    rpl->size = sizeAllocEntries;

    rpl->num_counters = h->info.num_entries;
    rpl->valid_hooks = h->info.valid_hooks;

    //Let the kernel setup pre/post routing

    rpl->hook_entry[NF_INET_LOCAL_IN] = h->info.hook_entry[NF_INET_LOCAL_IN];
    rpl->hook_entry[NF_INET_FORWARD] = h->info.hook_entry[NF_INET_FORWARD] + new_entry->next_offset;
    rpl->hook_entry[NF_INET_LOCAL_OUT] = h->info.hook_entry[NF_INET_LOCAL_OUT] + new_entry->next_offset;

    memcpy(rpl->underflow, rpl->hook_entry, sizeof rpl->hook_entry);
    rpl->underflow[NF_INET_LOCAL_IN] += new_entry->next_offset; // if fail, just jmp to bulit-in chain


    fprintf(stderr, "vaild_hooks=0x%x, num_entries=%u, size=%u, num_counters=%u\n",
        rpl->valid_hooks, rpl->num_entries, rpl->size, rpl->num_counters);

    dumpIptEntries(rpl->entries, rpl->num_entries, rpl->hook_entry);

    int ret = setsockopt(h->socketfd, IPPROTO_IP, IPT_SO_SET_REPLACE, rpl,
        sizeof(*rpl) + rpl->size);

    free(rpl);

    if (ret < 0) {
        perror("setockopt");
    }

    free(new_entry);
}

int main() {
    const char* table = "filter"; // check /proc/net/ip_tables_names
    struct Handle* h = checkTable(table);
    commitEntry(h);
    return 0;
}
