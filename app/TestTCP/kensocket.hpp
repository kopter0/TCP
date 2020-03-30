#include<bits/stdc++.h>
#include<arpa/inet.h>

#ifndef KENSOCKET_HPP
#define KENSOCKET_HPP

class kensocket{
public:
    #define t_first std::get<0>
    #define t_second std::get<1>
    #define t_third std::get<2>

    #define mt std::make_tuple
    enum k_set_type{
        allocated,
        unallocated
    };

    typedef std::tuple<int, in_addr_t, in_port_t> kensockaddr;
    typedef std::set<kensockaddr>::iterator k_set_itr;


private:
    std::set<kensockaddr> allocated_addrs;
    std::set<kensockaddr> unallocated_addrs;
    std::map<k_set_type, std::set<kensockaddr>> k_sets_map;



public:
    kensocket();
    k_set_itr find_by_fd(int fd, k_set_type set_type);
    k_set_itr find(kensockaddr k_addr, k_set_type set_type);
    void insert(kensockaddr k_addr, k_set_type set_type);
    void erase(k_set_itr itr, k_set_type set_type);
    k_set_itr end(k_set_type set_type);
};

#endif
