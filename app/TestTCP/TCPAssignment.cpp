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
#include <unistd.h>

namespace E
{

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
	all_flags = {SYN, ACK, FIN, RST};
	flag_map.clear();
	// connection_vector.clear();
}

void TCPAssignment::finalize()
{
	all_flags.clear();
	flag_map.clear();
	// connection_vector.clear();
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	uint fd;
	struct sockaddr_in *sa;
	Connection *t_connection;
	//Conn_itr itr;
	// Conn_itr itr;
	std::vector<Connection*>::iterator itr;
	std::vector <FLAGS> fl;

	int inter_index;
	uint8_t my_ip_1byte[4] = {0};
	uint32_t dest_ip, my_ip;
	const uint8_t *dest_ptr;
	bool c;
	Packet *first_syn;
	// const uint8_t *dest_ptr;
	// std::cout<<param.syscallNumber << " " << pid << std::endl;
	switch(param.syscallNumber)
	{
	case SOCKET:
		//this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		fd = createFileDescriptor(pid);
		t_connection = new Connection();
		t_connection -> fd = fd;
		t_connection -> state = CLOSED_SOCKET;
		t_connection -> pid = pid;
		connection_vector.pb(t_connection);
		returnSystemCall(syscallUUID, fd);
		
		break;

	case CLOSE:
		//this->syscall_close(syscallUUID, pid, param.param1_int);
		fd = param.param1_int;
		itr = find_by_fd(fd, pid);
		if (itr == connection_vector.end()){		
			returnSystemCall(syscallUUID, -1);
		}

		if ((*itr)->state == ESTAB_SOCKET){
			sendTCPSegment((*itr), std::vector<FLAGS>{FIN, ACK});
			(*itr) -> send_isn++;
			(*itr) -> state = FIN_WAIT_1_SOCKET;
			(*itr) -> uuid = syscallUUID;
			break;
		}
		else if ((*itr)-> state == CLOSE_WAIT_SOCKET)
		{
			// (*itr) -> send_isn++;
			sendTCPSegment((*itr), std::vector<FLAGS>{FIN, ACK});
			(*itr) -> state = LAST_ACK_SOCKET;
			(*itr) -> uuid = syscallUUID;
			break;
		}
		else if ((*itr) -> state == CLOSED_SOCKET){
			removeFileDescriptor(pid, fd);
			connection_vector.erase(itr);
			returnSystemCall(syscallUUID, 0);
		}
		

	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		

		fd = param.param1_int;
		sa = static_cast<struct sockaddr_in*> (param.param2_ptr);
		dest_ip = ( sa->sin_addr.s_addr);
		dest_ptr = (const uint8_t *)&dest_ip;
		inter_index = this->getHost()->getRoutingTable(dest_ptr);
		c = this->getHost()->getIPAddr ( my_ip_1byte, inter_index); 
		my_ip = (*(uint32_t *) my_ip_1byte);
		
		
		//filling info to the 
		itr = find_by_fd(fd, pid);
		if (itr == connection_vector.end()){
			// connecting to not existifind_by_fdng socket
			returnSystemCall(syscallUUID, -1);
			break;
		}
		

		(*itr)-> local_ip = ntohl(my_ip); 
		(*itr)-> remote_ip = ntohl( sa->sin_addr.s_addr);
		if ((*itr)-> local_port == 0){
			t_connection = new Connection;
			for (unsigned short i = 46759; i < 65536; i++){
			
				t_connection->local_ip = ntohl(sa->sin_addr.s_addr);
				t_connection->local_port = i;
				if(find_by_port_ip(t_connection ) == connection_vector.end()){
					
					(*itr)-> local_port = i;
					break;
				}

			}
		}
		
		
		// print_kensock_conns(connection_vector);
		(*itr)-> remote_port = ntohs(sa->sin_port);
		(*itr)-> state = SYN_SENT_SOCKET;
		(*itr)-> send_isn = rand();
		(*itr)-> bound = true;
		(*itr)->uuid = syscallUUID;
		(*itr)-> pid = pid;

		sendTCPSegment((*itr), std::vector<FLAGS>{SYN});
		(*itr) -> send_isn++;
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		fd = param.param1_int;
		itr = find_by_fd(fd, pid, CLOSED_SOCKET);
		// print_kensock_conns(connection_vector);
		if (itr != connection_vector.end()){
			if ((*itr) -> bound){
				(*itr) -> state = LISTEN_SOCKET;
				(*itr) -> backlog = param.param2_int;
				(*itr) -> pid = pid;    
				(*itr) -> accept_queue = new std::deque<std::tuple<uint64_t, int, void*>>();
				(*itr) -> estab_queue = new std::deque<Connection*>();
				returnSystemCall(syscallUUID, 0);
			}
		}
		
		// print_kensock_conns(connection_vector);
		returnSystemCall(syscallUUID, -1);

		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		// std::cout<<"in accept_sys_call"<<std::endl;
		fd = param.param1_int; 
		itr = find_by_fd(fd, pid, LISTEN_SOCKET);
		if (itr == connection_vector.end()){
			returnSystemCall(syscallUUID, -1);
			break;
		}

		if ((*itr)->estab_queue -> size() > 0){
			(*itr) -> backlog_used--;
			auto new_conn = (*itr) -> estab_queue -> front();
			(*itr) -> estab_queue -> pop_front();

			new_conn -> fd = createFileDescriptor(pid); 

			sa = static_cast<struct sockaddr_in*>(param.param2_ptr);
			sa ->sin_addr.s_addr = htonl(new_conn -> remote_port);
			sa -> sin_family = AF_INET;
			sa -> sin_port = htons(new_conn -> remote_port);
			memset(sa -> sin_zero, 0, 8);
			returnSystemCall(syscallUUID, new_conn -> fd);
		}
		else {
			(*itr) -> accept_queue -> push_back(std::make_tuple(syscallUUID, pid, param.param2_ptr));
		}
		break;
	case BIND:
		// this->syscall_bind(syscallUUID, pid, param.param1_int,
		// 		static_cast<struct sockaddr *>(param.param2_ptr),
		// 		(socklen_t) param.param3_int);
		
		fd = param.param1_int;
		sa = static_cast<struct sockaddr_in *> (param.param2_ptr);	
		t_connection = new Connection();
		t_connection -> fd = fd;
		t_connection -> local_ip = ntohl(sa -> sin_addr.s_addr);
		t_connection -> local_port = ntohs(sa -> sin_port);
		t_connection -> bound = true;
		t_connection -> pid = pid;
		itr = find(t_connection);
		if (itr != connection_vector.end()){
			if ((*itr) -> bound){
				returnSystemCall(syscallUUID, -1);
				break;
			}else{
				connection_vector.erase(itr);
			}
		}
		
		connection_vector.pb(t_connection);
		returnSystemCall(syscallUUID, 0);
		break;
		
	case GETSOCKNAME:
		//this->syscall_getsockname(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		fd = param.param1_int;
		sa = static_cast<struct sockaddr_in *> (param.param2_ptr);

		itr = find_by_fd(fd, pid);
		if (itr == connection_vector.end()){
			returnSystemCall(syscallUUID, -1);
			break;
		}
		sa -> sin_addr.s_addr = htonl((*itr) -> local_ip);
		sa -> sin_family = AF_INET;
		sa -> sin_port = htons((*itr) -> local_port);
		memset(sa -> sin_zero, 0, 8);
		returnSystemCall(syscallUUID, 0);
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		fd = param.param1_int;
		sa = static_cast<struct sockaddr_in*> (param.param2_ptr);
		itr = find_by_fd(fd, pid, ESTAB_SOCKET);
		if (itr != connection_vector.end()){
						
			sa -> sin_addr.s_addr = htonl((*itr) -> remote_ip); // maybe network
			sa -> sin_port = htons((*itr) -> remote_port);
			sa -> sin_family = AF_INET;
			memset(sa -> sin_zero, 0, 8);
			returnSystemCall(syscallUUID, 0);
			break;
		}
		returnSystemCall(syscallUUID, -1);
		break;
	default:
		assert(0);
	}
}
void TCPAssignment::printPack(Packet* pck, std::vector<TCPAssignment::FLAGS> fl){
	uint lg;
	ushort sh;
	in_addr ad;
	char buf[54];
	memset(buf, 0, 54);
	int s = 0;
	pck -> readData(OFFSET_SRC_IP, &lg, 4);
	pck -> readData(OFFSET_SRC_PORT, &sh, 2);
	ad.s_addr = lg;
	s += sprintf(buf + s, "From %s:%d ", inet_ntoa(ad), ntohs(sh));
	
	pck -> readData(OFFSET_DST_IP, &lg, 4);
	pck -> readData(OFFSET_DST_PORT, &sh, 2);
	ad.s_addr = lg;
	s += sprintf(buf + s, "To %s:%d\n", inet_ntoa(ad), ntohs(sh));
	
	
	// printf("%s", buf);


	for (uint i = 0; i < fl.size(); i++){
		switch (fl[i])
		{
		case TCPAssignment::SYN:
			std::cout << "SYN ";
			break;
		case TCPAssignment::ACK:
			std::cout << "ACK ";
			break;
		case TCPAssignment::RST:
			std::cout << "RST ";
			break;
		
		default:
			break;
		}
	}
	
}



void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{	
	if (fromModule.compare("IPv4") == 0){
		Conn_itr itr, itr1;
		short flags;

		Connection* in_con = new Connection();
		packet -> readData(OFFSET_FLAGS, &flags, 2);
		packet -> readData(OFFSET_DST_IP, &(in_con -> local_ip), 4);
		packet -> readData(OFFSET_SRC_IP, &(in_con -> remote_ip), 4);
		packet -> readData(OFFSET_DST_PORT, &(in_con->local_port), 2);
		packet -> readData(OFFSET_SRC_PORT, &(in_con->remote_port), 2);
		packet -> readData(OFFSET_SEQ_NUM, &(in_con -> recv_isn), 4);
		packet -> readData(OFFSET_ACK_NUM, &(in_con -> send_isn), 4);
		// add length detector

		in_con -> local_ip = ntohl(in_con -> local_ip);
		in_con -> local_port = ntohs(in_con -> local_port);
		in_con -> remote_ip = ntohl(in_con -> remote_ip);
		in_con -> remote_port = ntohs(in_con -> remote_port);
		in_con -> recv_isn = ntohl(in_con -> recv_isn);
		in_con -> send_isn = ntohl(in_con -> send_isn);

			
		flags = ntohs(flags);
		std::vector<FLAGS> flag_vector = get_flags(flags);
		flag_map.clear();
		for (FLAGS fl: all_flags){
			flag_map[fl] = false;
		}
		for (FLAGS fl: flag_vector){
			flag_map[fl] = true;
		}
		
		// SYN ACK signal
		if (flag_map[SYN] && flag_map[ACK]){
			this-> freePacket(packet);
			


			itr = find_by_port_ip(in_con, SYN_RCVD_SOCKET);
			if (itr != connection_vector.end()){
				(*itr)->state = ESTAB_SOCKET;
				(*itr)->recv_isn = in_con->recv_isn + 1;
				// (*itr)->send_isn = in_con->send_isn;
				(*itr) -> send_isn++;	
				sendTCPSegment((*itr), std::vector<FLAGS>{ACK});
				free(in_con);
				return;
			}


			itr = find_by_port_ip(in_con, SYN_SENT_SOCKET);
			
			if (itr == connection_vector.end()){
				sendRST(in_con);			
				return;
			}
			

			(*itr)->state = ESTAB_SOCKET;
			(*itr)-> recv_isn = in_con -> recv_isn + 1; 
			
			sendTCPSegment((*itr), std::vector<FLAGS>{ACK});	
			
			returnSystemCall((*itr)->uuid, 0);
			free(in_con);
			return;
		}

		else if (flag_map[FIN] && flag_map[ACK]){
			this -> freePacket(packet);
			
			itr = find_by_lr_port_ip(in_con);

			if (itr != connection_vector.end()){
				if ((*itr) -> state == FIN_WAIT_1_SOCKET){
					(*itr) -> state = CLOSING_SOCKET;
				}

				else if ((*itr) -> state == FIN_WAIT_2_SOCKET) {
					(*itr) -> state = TIMED_WAIT_SOCKET;
					(*itr) -> timer_uuid = addTimer((*itr), 60);
				}

				else if ((*itr) -> state == TIMED_WAIT_SOCKET){
					cancelTimer((*itr) -> timer_uuid);
					(*itr) -> timer_uuid = addTimer((*itr), 60);
				}

				else if ((*itr) -> state == ESTAB_SOCKET){
					(*itr) -> state = CLOSE_WAIT_SOCKET;
				}
				(*itr) -> recv_isn++;
				sendTCPSegment((*itr), std::vector<FLAGS>{ACK});
				// (*itr) -> send_isn++;
				free(in_con);
				return;
			}
		}

		// SYN only
		else if (flag_map[SYN]){

			this -> freePacket (packet);

			itr = find_by_port_ip(in_con, SYN_SENT_SOCKET);
			
			if (itr != connection_vector.end()){

				(*itr) -> state = SYN_RCVD_SOCKET;
				(*itr) -> recv_isn = in_con -> recv_isn + 1;
				(*itr) -> send_isn--;			
				sendTCPSegment((*itr), std::vector<FLAGS>{SYN, ACK});
				return;	

			}

			itr = find_by_port_ip(in_con, LISTEN_SOCKET);

			if (itr == connection_vector.end()){
				sendRST(in_con);
				return;
			}
			
			if (!(((*itr) -> backlog_used) < ((*itr) -> backlog))){
				sendRST(in_con);
				return;
			}
			(*itr) -> backlog_used++;
			in_con -> fd = (*itr) -> fd;
			in_con -> state = SYN_RCVD_SOCKET;
			in_con -> pid = (*itr) -> pid;
			in_con -> send_isn = rand();
			in_con -> recv_isn++;
			connection_vector.push_back(in_con);
			sendTCPSegment(in_con, std::vector<FLAGS>{SYN, ACK});
			in_con -> send_isn++;
			return;
		}
		// ACK
		else if (flag_map[ACK])
		{
			this -> freePacket(packet);
			// sim connect
			itr = find_by_lr_port_ip(in_con, ESTAB_SOCKET);
			if (itr != connection_vector.end() ){
				// (*itr)->recv_isn++;
				// (*itr)->send_isn = in_con->send_isn;
				returnSystemCall((*itr)->uuid, 0 );
				free(in_con);
				return;
			}
			
			itr = find_by_lr_port_ip(in_con, LAST_ACK_SOCKET);
			if (itr != connection_vector.end() ){
				uint64_t uuid_temp = (*itr)->uuid;
				connection_vector.erase(itr);
				returnSystemCall((*itr)->uuid, 0 );
				return;
			}
			
			itr = find_by_lr_port_ip(in_con, SYN_RCVD_SOCKET);
			if (itr != connection_vector.end()){
				Connection *t_connection = (*itr);
				t_connection -> state = ESTAB_SOCKET;
				itr = find_by_fd(t_connection -> fd, t_connection -> pid, LISTEN_SOCKET);

				if ( (*itr) -> accept_queue -> size() > 0){
					std::tuple<uint64_t, int, void*> tup = (*itr) -> accept_queue -> front();
					(*itr) -> accept_queue -> pop_front();

					int new_fd = createFileDescriptor(std::get<1>(tup));
					t_connection -> fd = new_fd;
					(*itr) -> backlog_used--;

					struct sockaddr_in* sockad = static_cast<struct sockaddr_in*>(std::get<2>(tup));
					sockad -> sin_addr.s_addr = htonl(t_connection -> remote_ip);
					sockad -> sin_family = AF_INET;
					sockad -> sin_port = htonl(t_connection -> remote_port);
					memset(sockad -> sin_zero, 0, 8);

					returnSystemCall((UUID)std::get<0>(tup), new_fd);
				}
				else{
					(*itr) -> estab_queue -> push_back(t_connection);
					(*itr) -> backlog_used --;
				}		
				return;		
			}
			
			itr = find_by_lr_port_ip(in_con);
			if (itr != connection_vector.end()){
				if ((*itr) -> state == FIN_WAIT_1_SOCKET){
					(*itr) -> state = FIN_WAIT_2_SOCKET;
				}
				if ((*itr) -> state == CLOSING_SOCKET){
					(*itr) -> state = TIMED_WAIT_SOCKET;
					(*itr) -> timer_uuid = addTimer((*itr), 60);
				}
			}
			free(in_con);
			return;
		}
	}
}

void TCPAssignment::timerCallback(void* payload)
{
	Connection *con = (Connection *) payload;
	if (con -> state == TIMED_WAIT_SOCKET){
		UUID syscall_UUID = con -> uuid;
		removeFileDescriptor(con -> pid, con -> fd);
		connection_vector.erase(find_by_fd(con -> fd, con -> pid));
		returnSystemCall(syscall_UUID, 0);
		return;
	}
}



uint16_t TCPAssignment::set_flags(std::vector <FLAGS> fl, int length)
{
	uint16_t ret_flag = 0;

	for (uint i = 0; i < fl.size(); i++){
		switch (fl[i])
		{
		case ACK:
			ret_flag |= 0x0010;
			break;
		case RST:
			ret_flag |= 0x0004;
			break;
		case FIN:
			ret_flag |= 0x0001;
			break;
		case SYN:
			ret_flag |= 0x0002;
			break;
		
		default:
			break;
		}
	}

	uint16_t len = length / 4;
	len = len << 12;

	ret_flag |= len;

	return ret_flag;
} 

std::vector<TCPAssignment::FLAGS> TCPAssignment::get_flags(short flags){
	std::vector<FLAGS> vect;
	if (flags & 0x01){
		vect.push_back(FIN);
	}
	if (flags & 0x02){
		vect.push_back(SYN);
	}
	if (flags & 0x04){
		vect.push_back(RST);
	}
	if (flags & 0x10){
		vect.push_back(ACK);
	}
	return vect;
}

void TCPAssignment::construct_tcpheader(Packet * pkt, Connection *con, std::vector<FLAGS> flags){
		
		// pkt->clearContext();
		uint32_t li = htonl(con -> remote_ip);
		pkt -> writeData(OFFSET_DST_IP, &(li), 4);
		li = htonl(con -> local_ip);
		pkt -> writeData(OFFSET_SRC_IP, &(li), 4);
		
		uint16_t sh = htons(con -> local_port);
		pkt -> writeData(OFFSET_SRC_PORT, &(sh), 2);
		sh = htons(con -> remote_port);
		pkt -> writeData(OFFSET_DST_PORT, &(sh), 2);

		li = htonl(con -> send_isn);
		pkt -> writeData(OFFSET_SEQ_NUM, &li, 4);
		li = htonl(con -> recv_isn);
		pkt -> writeData(OFFSET_ACK_NUM, &li, 4);

		
		ushort fl = htons(set_flags(flags , 20));
		pkt -> writeData(OFFSET_FLAGS, &fl, 2);
		fl = htons(0xc800);
		pkt -> writeData(48, &fl, 2);
		
		u_char tcpeheader[20];
		pkt -> readData(34, tcpeheader, 20);
		
		uint16_t chec = NetworkUtil::tcp_sum(htonl(con -> local_ip), htonl(con -> remote_ip) ,tcpeheader, 20);
		chec = ~chec;
		chec = htons(chec);
		pkt -> writeData(50, &chec, 2);
}

inline void TCPAssignment::sendTCPSegment(Connection *con, std::vector<FLAGS> flags){
	// Sends only header now
	Packet *pck = this -> allocatePacket(54);
	construct_tcpheader(pck, con, flags);
	this -> sendPacket("IPv4", pck);
}

inline void TCPAssignment::sendRST(Connection *con){
	sendTCPSegment(con, std::vector<FLAGS>{RST});
}

#pragma region Vector Interactions
char *states_socket[] =
{
    "CLOSED",
        "LISTEN",
        "SYN_SENT",
        "SYN_RCVD",
        "ESTAB",
        //exit state send FIN
        "FIN_WAIT_1",
        "FIN_WAIT_2",
        "CLOSING",
        "TIME_WAIT",
        //exit state FIN rcvd
        "CLOSE_WAIT",
        "LAST_ACK"
};    

Conn_itr TCPAssignment::find_by_fd(uint fd, int pid){		
    Conn_itr itr = connection_vector.begin();
    for (; itr != connection_vector.end(); itr++){
		if ((*itr) -> pid != pid){
			continue;
		}
        if ((*itr)->fd == fd){
            break;
        } 
    }
    return itr;
}
         
     

Conn_itr TCPAssignment::find_by_fd(uint fd, int pid, socket_state sock_state){
    Conn_itr itr = connection_vector.begin();
    for (; itr != connection_vector.end(); itr++){
		if ((*itr) -> pid != pid){
			continue;
		}
        if (((*itr)->fd == fd) && ((*itr) -> state == sock_state)){
            break;
        } 
    }
    return itr;
}

Conn_itr TCPAssignment::find(Connection* k_con){
    Conn_itr itr = connection_vector.begin();
    for (; itr != connection_vector.end(); itr++){
        if ((*itr) -> fd == k_con -> fd){
            break;
        }
        if ((*itr)->local_ip == k_con -> local_ip || (*itr)->local_ip == 0){
            if ((*itr) -> local_port == k_con -> local_port || (*itr) -> local_port == 0){
                break;
            }
        }
    }
    return itr;
}

Conn_itr TCPAssignment::find(Connection* k_con, socket_state sock_state){
    Conn_itr itr = connection_vector.begin();
    for (; itr != connection_vector.end(); itr++){
        if ((*itr) -> state != sock_state){
            continue;
        }
        if (((*itr) -> fd == k_con -> fd)){
            break;
        }
        if ((*itr)->local_ip == k_con -> local_ip || (*itr)->local_ip == 0){
            if ((*itr) -> local_port == k_con -> local_port || (*itr) -> local_port == 0){
                break;
            }
        }
    }
    return itr;
}

Conn_itr TCPAssignment::find_by_port_ip(Connection* k_con){
    Conn_itr itr = connection_vector.begin();
    for (; itr != connection_vector.end(); itr++){
        if ((*itr)->local_ip == k_con -> local_ip || (*itr)->local_ip == 0){
            if ((*itr) -> local_port == k_con -> local_port || (*itr) -> local_port == 0){
                break;
            }
        }
    }
    return itr;
}
Conn_itr TCPAssignment::find_by_port_ip(Connection* k_con, socket_state sock_state){
    Conn_itr itr = connection_vector.begin();
    for (; itr != connection_vector.end(); itr++){
        if ((*itr) -> state != sock_state){
            continue;
        }
        if ((*itr)->local_ip == k_con -> local_ip || (*itr)->local_ip == 0){
            if ((*itr) -> local_port == k_con -> local_port || (*itr) -> local_port == 0){
                break;
            }
        }
    }
    return itr;
}
Conn_itr TCPAssignment::find_by_lr_port_ip(Connection* k_con, socket_state sock_state){
    Conn_itr itr = connection_vector.begin();
    for (; itr != connection_vector.end(); itr++){
        if ((*itr) -> state != sock_state){
            continue;
        }

        bool li = (*itr)->local_ip == k_con -> local_ip;
        bool ri = (*itr)->remote_ip == k_con -> remote_ip;
        bool lp = (*itr) -> local_port == k_con -> local_port;
        bool rp = (*itr) -> remote_port == k_con -> remote_port;
        
        if (li && ri && lp && rp){
            break;
        }
    }
    return itr;
}
Conn_itr TCPAssignment::find_by_lr_port_ip(Connection* k_con){
    Conn_itr itr = connection_vector.begin();
    for (; itr != connection_vector.end(); itr++){

        bool li = (*itr)->local_ip == k_con -> local_ip;
        bool ri = (*itr)->remote_ip == k_con -> remote_ip;
        bool lp = (*itr) -> local_port == k_con -> local_port;
        bool rp = (*itr) -> remote_port == k_con -> remote_port;
        
        if (li && ri && lp && rp){
            break;
        }
    }
    return itr;
}

void TCPAssignment::print_kensock_conns( std::vector<Connection*> con_v ){
    std::cout<<"#############    start   ################\n";
    Conn_itr itr = con_v.begin();
    int i = 1;
    in_addr inadr;
    for ( ; itr != con_v.end(); itr++){
        std::cout<<"*****"<<i<<" connection  ********\n";
        std::cout<<"fd: "<<(*itr)->fd<<"\n";

        inadr.s_addr =htonl((*itr)->local_ip);
        std::cout<<"local_ip: "<<inet_ntoa((inadr))<<"\n";
        inadr.s_addr = htonl( (*itr)->remote_ip);
        std::cout<<"remote_ip: "<<inet_ntoa(inadr)<<"\n";
        std::cout<<"send_isn: "<<"0x"<<std::hex<<(*itr)->send_isn<<"\n";
        std::cout<<"recv_isn(aka ack_num): "<<"0x"<<std::hex<<(*itr)->recv_isn<<"\n";
        std::cout<<"backlog: "<<(*itr)->backlog<<"\n";
        std::cout<<"backlog used: "<<"0x"<<(*itr)->backlog_used<<"\n";
        
        std::cout<<"state: "<<socket_FSM[(*itr)->state]<<"\n";
        std::cout<<"local port: "<<"  in dec: "<<std::dec<<(*itr)->local_port <<"   in hex 0x"<<std::hex<<(*itr)->local_port<<"\n";
        std::cout<<"remote port: "<<"  in dec: "<<std::dec<<(*itr)->remote_port <<"   in hex 0x"<<std::hex<<(*itr)->remote_port<<"\n";
        std::cout<<"bound: "<<(*itr)->bound<<"\n";
		std::cout<<"pid: "<<std::dec<<(*itr)->pid<<" syscalluuid: "<<(*itr)->uuid<<"\n";
    }

    std::cout<<"###########       end    ################\n";
}



#pragma endregion Vector Interactions


}



