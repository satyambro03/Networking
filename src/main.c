#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pcap.h>

struct Stats {
    unsigned long total;
    unsigned long ipv4;
    unsigned long tcp;
    unsigned long udp;
    unsigned long icmp;
    unsigned long other;
};

struct Stats stats = {0};

void packet_handler(
    unsigned char *args,
    const struct pcap_pkthdr *header,
    const unsigned char *packet
) {
    (void)args;

    stats.total++;

    if (header->caplen < 14) {
        stats.other++;
        return;
    }

    unsigned int ethertype =
        ((unsigned int)packet[12] << 8) | packet[13];

    if (ethertype != 0x0800) {
        stats.other++;
        return;
    }

    if (header->caplen < 34) {
        stats.other++;
        return;
    }

    const unsigned char *ip = packet + 14;

    unsigned int ihl = (ip[0] & 0x0F) * 4;

    if (ihl < 20 || header->caplen < 14 + ihl) {
        stats.other++;
        return;
    }

    stats.ipv4++;

    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, ip + 12, src, sizeof(src));
    inet_ntop(AF_INET, ip + 16, dst, sizeof(dst));

    unsigned int protocol = ip[9];

    printf("\nPacket: %lu\n", stats.total);
    printf("Source IP      : %s\n", src);
    printf("Destination IP : %s\n", dst);
    printf("Packet Size    : %u bytes\n", header->len);

    const unsigned char *transport = ip + ihl;
    unsigned int remaining = header->caplen - 14 - ihl;

    if (protocol == 6) {
        stats.tcp++;
        printf("Protocol       : TCP\n");

        if (remaining >= 20) {
            unsigned int sport =
                (transport[0] << 8) | transport[1];

            unsigned int dport =
                (transport[2] << 8) | transport[3];

            printf("Source Port    : %u\n", sport);
            printf("Destination Port: %u\n", dport);
        }
    }
    else if (protocol == 17) {
        stats.udp++;
        printf("Protocol       : UDP\n");

        if (remaining >= 8) {
            unsigned int sport =
                (transport[0] << 8) | transport[1];

            unsigned int dport =
                (transport[2] << 8) | transport[3];

            printf("Source Port    : %u\n", sport);
            printf("Destination Port: %u\n", dport);
        }
    }
    else if (protocol == 1) {
        stats.icmp++;
        printf("Protocol       : ICMP\n");
    }
    else {
        stats.other++;
        printf("Protocol       : Other (%u)\n", protocol);
    }
}

int main(int argc, char *argv[]) {

 FILE *report = fopen("reports/summary.csv", "w");

if (report != NULL) {
    fprintf(report, "Metric,Count\n");
    fprintf(report, "Total Packets,%lu\n", stats.total);
    fprintf(report, "IPv4 Packets,%lu\n", stats.ipv4);
    fprintf(report, "TCP Packets,%lu\n", stats.tcp);
    fprintf(report, "UDP Packets,%lu\n", stats.udp);
    fprintf(report, "ICMP Packets,%lu\n", stats.icmp);
    fprintf(report, "Other Packets,%lu\n", stats.other);

    fclose(report);

    printf("CSV Report: reports/summary.csv\n");
}

    if (argc != 2) {
        printf("Usage: ./netscope file.pcap\n");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_offline(argv[1], errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        printf("Unsupported link type\n");
        pcap_close(handle);
        return 1;
    }

    printf("\n===== NETSCOPE ANALYZER =====\n");

    int result = pcap_loop(handle, 0, packet_handler, NULL);

    if (result == PCAP_ERROR) {
        fprintf(stderr, "%s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    printf("\n===== FINAL STATISTICS =====\n");
    printf("Total Packets : %lu\n", stats.total);
    printf("IPv4 Packets  : %lu\n", stats.ipv4);
    printf("TCP Packets   : %lu\n", stats.tcp);
    printf("UDP Packets   : %lu\n", stats.udp);
    printf("ICMP Packets  : %lu\n", stats.icmp);
    printf("Other Packets : %lu\n", stats.other);

    pcap_close(handle);

    return 0;
}

