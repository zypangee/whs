#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Ethernet 헤더를 분석하기 위한 구조체 선언 및 초기화
    struct ether_header *eth_header = (struct ether_header *) packet;
    
    // IP 헤더를 분석하기 위한 구조체 선언 및 초기화
    struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    
    // Ethernet 프레임의 유형이 IP이고, IP 패킷 중에서도 TCP 프로토콜만을 처리
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP && ip_header->ip_p == IPPROTO_TCP) {
        // TCP 헤더를 분석하기 위한 구조체 선언 및 초기화
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
        
        // IP 헤더의 길이 계산
        int ip_header_len = ip_header->ip_hl << 2; // IP 헤더 길이는 32비트 워드로 표현되므로 4로 곱해줍니다.
        
        // TCP 헤더의 길이 계산
        int tcp_header_len = tcp_header->th_off << 2; // TCP 헤더 길이는 32비트 워드로 표현되므로 4로 곱해줍니다.
        
        // Ethernet 헤더 정보 출력
        printf("Ethernet Header\n");
        printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_header->ether_shost[0], eth_header->ether_shost[1],
               eth_header->ether_shost[2], eth_header->ether_shost[3],
               eth_header->ether_shost[4], eth_header->ether_shost[5]);
        printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_header->ether_dhost[0], eth_header->ether_dhost[1],
               eth_header->ether_dhost[2], eth_header->ether_dhost[3],
               eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
        
        // IP 헤더 정보 출력 (길이 정보 포함)
        printf("IP Header\n");
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
        printf("IP Header Length: %d bytes\n", ip_header_len);
        
        // TCP 헤더 정보 출력 (길이 정보 포함)
        printf("TCP Header\n");
        printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
        printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
        printf("TCP Header Length: %d bytes\n", tcp_header_len);
        
        // Message 출력 (예: 처음 20바이트만 출력)
        printf("Message: ");
        for (int i = 0; i < 20; i++) {
            printf("%02x ", packet[ETHER_HDR_LEN + ip_header_len + tcp_header_len + i]);
        }
        printf("\n");
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    const char *dev = "ens33"; // vmware ubuntu 네트워크 인터페이스
    
    // 지정된 네트워크 인터페이스로부터 패킷을 캡처하기 위한 핸들 생성
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        return 1;
    }
    
    // 패킷 수집 및 처리 루프
    pcap_loop(handle, 0, packet_handler, NULL);
    
    // 핸들 닫기
    pcap_close(handle);
    return 0;
}
