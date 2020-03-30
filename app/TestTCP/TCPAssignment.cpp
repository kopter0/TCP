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
#include "kensocket.hpp"

namespace E
{

kensocket kensock;

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
	kensock = kensocket();
}

void TCPAssignment::finalize()
{
	
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	int fd;
	struct sockaddr_in *sa;
	kensocket::kensockaddr t_kensockaddr;
	kensocket::k_set_itr itr;
	switch(param.syscallNumber)
	{
	case SOCKET:
		//this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		fd = createFileDescriptor(pid);
		kensock.insert(mt(fd, 0, 0), kensocket::unallocated);
		returnSystemCall(syscallUUID, fd);
		break;
	case CLOSE:
		//this->syscall_close(syscallUUID, pid, param.param1_int);
		fd = param.param1_int;
		itr = kensock.find_by_fd(fd, kensocket::allocated);

		if ( itr != kensock.end(kensocket::allocated)){
			kensock.erase(itr, kensocket::allocated);
			removeFileDescriptor(pid, fd);
			returnSystemCall(syscallUUID, 0);
			break;
		}
		itr = kensock.find_by_fd(fd, kensocket::unallocated);
		if(itr != kensock.end(kensocket::unallocated)){
			kensock.erase(itr, kensocket::unallocated);
			removeFileDescriptor(pid, fd);
			returnSystemCall(syscallUUID, 0);
			break;
		}
		returnSystemCall(syscallUUID, -1);
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
		fd = param.param1_int;
		sa = static_cast<struct sockaddr_in *> (param.param2_ptr);	
		t_kensockaddr = mt(fd, sa->sin_addr.s_addr, sa->sin_port);
		if (kensock.find(t_kensockaddr, kensocket::allocated) != kensock.end(kensocket::allocated)){
			returnSystemCall(syscallUUID, -1);
			break;
		}
		itr = kensock.find_by_fd(fd, kensocket::unallocated);
		if (itr == kensock.end(kensocket::unallocated)){
			returnSystemCall(syscallUUID, -1);
			break;			
		}
		kensock.erase(itr, kensocket::unallocated);
		kensock.insert(t_kensockaddr, kensocket::allocated);
		returnSystemCall(syscallUUID, 0);
		break;
	case GETSOCKNAME:
		//this->syscall_getsockname(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		fd = param.param1_int;
		sa = static_cast<struct sockaddr_in *> (param.param2_ptr);

		itr = kensock.find_by_fd(fd, kensocket::allocated);
		if (itr == kensock.end(kensocket::allocated)){
			returnSystemCall(syscallUUID, -1);
			break;
		}
		sa->sin_addr.s_addr = t_second(*itr);
		sa->sin_family = AF_INET;
		sa->sin_port = t_third(*itr);
		memset(sa->sin_zero, 0, 8); 
		returnSystemCall(syscallUUID, 0);
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
