#include "kensocket.hpp"
kensocket::kensocket(){
    allocated_addrs.clear();
    unallocated_addrs.clear();
    k_sets_map[allocated] = allocated_addrs;
    k_sets_map[unallocated] = unallocated_addrs;
}

kensocket::k_set_itr kensocket::find_by_fd(int fd, k_set_type set_type){
    k_set_itr ret = k_sets_map[set_type].begin();
    for (;ret != k_sets_map[set_type].end(); ret++){
        if (t_first(*ret) == fd){
            break;
        }
    }
    return ret;
}

kensocket::k_set_itr kensocket::find(kensockaddr k_addr, k_set_type set_type){
    k_set_itr ret = k_sets_map[set_type].begin();
    for (;ret != k_sets_map[set_type].end(); ret++){
        if (t_first(*ret) == t_first(k_addr)){
            break;
        }

        if (t_second(*ret) == t_second(k_addr) || t_second(*ret) == 0){
            if (t_third(*ret) == t_third(k_addr) || t_third(*ret) == 0){
                break;
            }
        }
    }
    return ret;
}  

void kensocket::insert(kensockaddr k_addr, k_set_type set_type){
    k_sets_map[set_type].insert(k_addr);
}

void kensocket::erase(k_set_itr itr, k_set_type set_type){
    k_sets_map[set_type].erase(itr);
}

kensocket::k_set_itr kensocket::end(k_set_type set_type){
    return k_sets_map[set_type].end();
}
