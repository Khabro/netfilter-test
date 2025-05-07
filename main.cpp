#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <errno.h>

int isBlocked = 0;
int host_len;
char *host;

#pragma pack(push, 1)
struct IpHdr {
    uint8_t  ihl_ver;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct TcpHdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  doff_res; // data offset (4 bits) + reserved (4 bits)
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};
#pragma pack(pop)

static u_int32_t print_pkt(struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *data;
    int ret;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("[*] Packet id=%u\n", id);
    }

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        printf("[*] Payload length: %d bytes\n", ret);

        struct IpHdr *iphdr = (struct IpHdr *)data;
        int ip_hdr_len = (iphdr->ihl_ver & 0x0F) * 4;

        if (iphdr->protocol != IPPROTO_TCP) {
            printf("[*] Not a TCP packet. Skipping...\n\n");
            return id;
        }

        struct TcpHdr *tcphdr = (struct TcpHdr *)(data + ip_hdr_len);
        int tcp_hdr_len = ((tcphdr->doff_res & 0xF0) >> 4) * 4;

        int http_offset = ip_hdr_len + tcp_hdr_len;
        int http_len = ret - http_offset;

        if (http_len > 0) {
            unsigned char *http = data + http_offset;

            const char* http_methods[] = {
                "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "CONNECT", "PATCH"
            };
            const int num_methods = sizeof(http_methods) / sizeof(http_methods[0]);

            int matched = 0;
            for (int i = 0; i < num_methods; ++i) {
                int len = strlen(http_methods[i]);
                if (strncmp((char*)http, http_methods[i], len) == 0) {
                    matched = 1;
                    break;
                }
            }

            if (matched) {
                char *tmp_host_ptr = strstr((char *)http, "Host: ");
                if (tmp_host_ptr) {
                    if (strncmp(tmp_host_ptr + 6, host, host_len) == 0) {
                        printf("[+] Blocked Host Matched: %.*s\n", host_len, host);
                        isBlocked = 1;
                    }
                }
            }
        }
    }

    printf("[*] Block Status: %s\n\n", isBlocked ? "BLOCKED" : "ACCEPTED");
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("[*] Entering callback...\n");
    if (isBlocked) {
        isBlocked = 0;  // reset for next packet
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <host_to_block>\n", argv[0]);
        exit(1);
    }

    host_len = strlen(argv[1]);
    host = (char*)malloc(host_len + 1);
    memcpy(host, argv[1], host_len);
    host[host_len] = '\0';

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd, rv;
    char buf[4096] __attribute__ ((aligned));

    printf("[*] Opening nfqueue handle\n");
    h = nfq_open();
    if (!h) {
        perror("nfq_open");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        perror("nfq_unbind_pf");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("nfq_bind_pf");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        perror("nfq_create_queue");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode");
        exit(1);
    }

    fd = nfq_fd(h);

    printf("[*] Waiting for packets...\n");
    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    perror("recv failed");

    nfq_destroy_queue(qh);
    nfq_close(h);
    free(host);

    return 0;
}

