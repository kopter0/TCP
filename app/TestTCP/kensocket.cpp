#include<bits/stdc++.h>
#include<arpa/inet.h>
namespace kensocket{


    class kref{
    public:
        int k_fd;
        in_addr_t k_addr;
        in_port_t k_port;

        kref():
            k_fd(-1), k_addr(-1), k_port(-1){}
        kref(int fd, in_addr_t addr, in_port_t port):
            k_fd(fd), k_addr(addr), k_port(port)
        {}

        // bool operator< (const kref& rhs){
        //     if (this -> k_fd < rhs.k_fd)
        //         return true;
        //     return false;
        // }

        // bool operator() (kref const& lhs, kref const& rhs) const{
        //     return (lhs.k_fd < rhs.k_fd);
        // }
    };

    class kensock{
    public:
        kensock(){}
    };


    struct krefComparator{
        bool operator() (const kref & lhs, const kref & rhs){
            return (lhs.k_fd < rhs.k_fd);
        }
    };
    static std::map<kref, kensock, krefComparator> kref_kensock_map;

    // static void init_map(){
    //     std::map<int, kref> kref_kensock_map = new std::map<int , kref>();
    // }

}