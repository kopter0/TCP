/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include "kensocket.cpp"

namespace E
{

std::map<std::tuple<int, in_addr_t, in_port_t>, int> mymap;

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{
	kensocket::kref_kensock_map.clear();
}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	int fd;
	struct sockaddr_in *sa;
	kensocket::kref temp_kref;
	std::map<kensocket::kref, kensocket::kensock>::iterator it;
	switch(param.syscallNumber)
	{
	case SOCKET:
		//this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		fd = createFileDescriptor(pid);
		returnSystemCall(syscallUUID, fd);
		break;
	case CLOSE:
		//this->syscall_close(syscallUUID, pid, param.param1_int);
		removeFileDescriptor(pid, param.param1_int);
		
		// it = kensocket::kref_kensock_map.begin();
		// for (; it != kensocket::kref_kensock_map.end(); it++){

		// 	// std::cout<< "it: " << it->first.k_fd << " " << it->first.k_addr << " " << it->first.k_port << std::endl;
		// 	if (it->first.k_fd == param.param1_int){
		// 		kensocket::kref_kensock_map.erase(it->first);
				
		// 		returnSystemCall(syscallUUID, 0);
		// 	}

		// }
		returnSystemCall(syscallUUID, 0);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		//this->syscall_bind(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		(socklen_t) param.param3_int);
		sa = static_cast<struct sockaddr_in *> (param.param2_ptr);	
		temp_kref = kensocket::kref(param.param1_int, sa->sin_addr.s_addr, sa->sin_port);
		// std::cout << "temp_kerf:" <<param.param1_int << " " << sa->sin_addr.s_addr << " " <<sa->sin_port << std::endl;
		it = kensocket::kref_kensock_map.begin();
		for (; it != kensocket::kref_kensock_map.end(); it++){

			// std::cout<< "it: " << it->first.k_fd << " " << it->first.k_addr << " " << it->first.k_port << std::endl;
			if (it->first.k_fd == temp_kref.k_fd){
				returnSystemCall(syscallUUID, -1);
			}
			if (it->first.k_addr == temp_kref.k_addr || it->first.k_addr == 0){
				if (it->first.k_port == temp_kref.k_port || it->first.k_port == 0){
					returnSystemCall(syscallUUID, -1);
				}
			}
		}

		kensocket::kref_kensock_map[temp_kref] = kensocket::kensock();
		returnSystemCall(syscallUUID, 0);
		break;
	case GETSOCKNAME:
		//this->syscall_getsockname(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}


}
