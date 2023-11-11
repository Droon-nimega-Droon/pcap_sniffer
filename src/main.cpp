#include <iostream>
#include <pcap/pcap.h>


void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    std::cout << "Packet captured: " << pkt_data << std::endl;
}


int main(int argc, char* argv[]) {
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("wlx0013eff8082e", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cout << "Error opening device: " << errbuf << std::endl;
        return 1;
    }
    if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
        std::cout << "Device is not a WLAN interface" << std::endl;
        return 1;
    }
    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        std::cout << "Error capturing packets: " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    pcap_close(handle);
    
    std::cout << "dsadfgdgfsd" << std::endl;
    return 0;
}