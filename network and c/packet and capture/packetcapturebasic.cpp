#include"stdafx.h"

class capture{
    public:

    static capture& GetInstance() noexcept{
        static capture instance;
        return instance;
    }

    inline bool CheckDevice(const char* deviceName){
        
        for(int i=0; i<deviceList.size(); ++i){
            if(strncmp(deviceList[i].c_str(),deviceName,strlen(deviceList[i].c_str())) == 0){
                return true;
            }
        }

        return false;
    }

    unsigned char* CapturePacket(){

        while(true)
        {
            pcap_pkthdr* header;
            const unsigned char* packet;
            int res = pcap_next_ex(device,&header,&packet);
            if(res == 0) break;
            ether_header& ether = reinterpret_cast<ether_header&>(packet);
            PrintEthernet(ether);
            const ip_header& ip = *reinterpret_cast<const ip_header*>(packet + sizeof(ether_header));
            PrintIP(ip);
            const tcp_header& tcp = *reinterpret_cast<const tcp_header*>((packet+(sizeof(ip) + sizeof(ether))));
            PrintTcp(tcp);
        }

        return nullptr;
    }

    inline void PrintAllDevice() noexcept {
        if(deviceList.size() == 0) return;
        for(std::vector<std::string>::iterator iter = deviceList.begin(); iter!=deviceList.end();iter++){
            fprintf(stdout,"DeviceName: %s\n",iter->data());
        }
    }

    void SetAllDevice(){
        
        pcap_if_t* alldev;

        if(pcap_findalldevs(&alldev,errbuffer) < 0){
            return;
        }

        if(alldev == nullptr){
            printf("%s\n",errbuffer);
        }

        for(auto cur= alldev; cur; cur= cur->next){    
            deviceList.push_back(cur->name);
        }

        pcap_freealldevs(alldev);
        return;
    }

    bool setDevice(const char* deviceName){
        if(!CheckDevice(deviceName)){
            return false;
        }
        if(device != nullptr){
            pcap_close(device);
        }
        
        device = pcap_open_live(deviceName,BUFSIZ,1,1000,errbuffer);
        if(device != nullptr){
            return true;
        }

        return false;
    }

    void PrintEthernet(const ether_header& header) const{
        printf("==================================MAC===============================\n");
        printf("DestinationAddress: ");
        for(int i=0; i<6; ++i){
            printf("%02x",htons(header.ether_dhost[i]));
            if(i != 5){
                printf(":");
            }
        }
        printf("\n");
        printf("SourceAddresss: ");
        for(int i=0; i<6; ++i){
            printf("%02x:",htons(header.ether_shost[i]));
            if(i != 5){
                printf(":");
            }
        }
        printf("\n");
        printf("type:%04x\n",htons(header.ether_type));
        return;
    }

    void PrintIP(const ip_header& header) const{
        unsigned char dstip[INET_ADDRSTRLEN];
        unsigned char srcip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET,&header.ip_dst,reinterpret_cast<char*>(srcip),INET_ADDRSTRLEN);
        inet_ntop(AF_INET,&header.ip_src,reinterpret_cast<char*>(dstip),INET_ADDRSTRLEN);
        printf("=============================================IP===================================\n");
        printf("src ip: %s\n",srcip);
        printf("dst ip: %s\n",dstip);
        return;
    }

    void PrintTcp(const tcp_header& header) const {
        
        printf("===============================================TCP=====================================\n");
        printf("sourceport:%d\n",htons(header.source_port));
        printf("destinationport:%d\n",htons(header.dest_port));
        
        
        
        return;
    };
    private:

    capture() = default;
    ~capture() = default;
    capture(const capture& ref) = delete;
    capture(capture&& ref) = delete;
    capture& operator=(capture& ref) = delete;
    capture& operator=(capture&& ref) = delete;
    

    pcap_t* device;
    std::vector<std::string> deviceList;
    char errbuffer[PCAP_ERRBUF_SIZE];
    
};



int main(int argc, char* argv[]){
   // printf("%d\n",argc);
    if(argc < 2){
        PrintUsage();
        return 0;
    }
    
    if(strncmp(argv[1],"help",strlen("help")) == 0){
        PrintCommends();
        return 0;
    }
    capture& instance = capture::GetInstance();
    instance.SetAllDevice();
    if(argc == 2){
        if(strncmp(argv[1],"showdevice",strlen("showdevice")) == 0){
            instance.PrintAllDevice();
            return 0;     
        }else{
            PrintUsage();
            return 0;
        }
    }

    if(argc == 3 && strncmp(argv[1],"attach",strlen("attach")) == 0){
        //printf("gettin");
        if(!instance.setDevice(argv[2])){
            fprintf(stdout,"\nUnknown devicename was inserted\n");
            return 0;
        }
        instance.CapturePacket();
        return 0;
    }
}