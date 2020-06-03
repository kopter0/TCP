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

// #define PART2_DEBUG
// #define DEBUG

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

	std::vector<Connection*>::iterator itr = connection_vector.begin();
	for (; itr != connection_vector.end(); itr++){
		cancelTimers((*itr),0xFFFFFFFFFFFFFFFF); 	
	}
	connection_vector.clear();
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
	
	
	uint total_bytes_left, in_bytes; 
	char *buffer_ptr;

	int inter_index, temp_int;
	uint8_t my_ip_1byte[4] = {0};
	uint32_t dest_ip, my_ip;
	const uint8_t *dest_ptr;
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

		#ifdef PART2_DEBUG
		std::cout << "Syscall: Close..." << std::flush;
		#endif // PART2_DEBUG

		fd = param.param1_int;
		itr = find_by_fd(fd, pid);
		if (itr == connection_vector.end()){		
			returnSystemCall(syscallUUID, -1);
		}
		

		if ((*itr)->state == ESTAB_SOCKET){
			#ifdef PART2_DEBUG
			std::cout << "Estab Socket...";
			#endif // PART2_DEBUG
			if ((*itr) -> write_in_process){

				#ifdef PART2_DEBUG
				std::cout << "Still writing" << std::endl;
				#endif // PART2_DEBUG

				(*itr) -> close_requested = true;
				(*itr) -> uuid = syscallUUID;
				break;
			}

			#ifdef PART2_DEBUG
			std::cout << "Alter to Fin Wait 1" << std::endl;
			#endif // PART2_DEBUG
			sendTCPSegment((*itr),NULL,0, std::vector<FLAGS>{FIN, ACK});
			(*itr) -> send_isn++;
			(*itr) -> state = FIN_WAIT_1_SOCKET;
			(*itr) -> uuid = syscallUUID;
			break;
		}
		else if ((*itr)-> state == CLOSE_WAIT_SOCKET)
		{
			#ifdef PART2_DEBUG
			std::cout << "Close Wait" << std::endl;
			#endif // PART2_DEBUG
			sendTCPSegment((*itr), NULL, 0, std::vector<FLAGS>{FIN, ACK});
			(*itr) -> state = LAST_ACK_SOCKET;
			(*itr) -> uuid = syscallUUID;
			break;
		}
		else if ((*itr) -> state == CLOSED_SOCKET){
			removeFileDescriptor(pid, fd);
			connection_vector.erase(itr);
			returnSystemCall(syscallUUID, 0);
		}
		
		else if ((*itr) -> state == SYN_RCVD_SOCKET){
			#ifdef PART2_DEBUG
			std::cout << "SYN_RCVD" << std::endl;
			#endif // PART2_DEBUG
			sendTCPSegment((*itr), NULL, 0, std::vector<FLAGS>{FIN, ACK});
			(*itr) -> state = FIN_WAIT_1_SOCKET;
			(*itr) -> uuid = syscallUUID;
			break;
		}

		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		fd = param.param1_int;
		itr = find_by_fd(fd, pid);

		


		if (itr == connection_vector.end()){
			returnSystemCall(syscallUUID, -1);
			break;
		}

		//std::cout << "read" <<param.param3_int << std::endl;
		// EOF on -1??? FIN??

		total_bytes_left =  param.param3_int;
		buffer_ptr = (char*) param.param2_ptr;
		in_bytes = (*itr) -> read_buffer -> inorder_bytes;
		if (in_bytes > 0){
			uint32_t actual_get = (*itr) -> read_buffer -> get(buffer_ptr, total_bytes_left);
			returnSystemCall(syscallUUID, actual_get);
			break;
		}
		else{
			(*itr)->read_requested = true;
			(*itr)->read_request = std::make_tuple(syscallUUID, param.param2_ptr, param.param3_int);
			break;
		}
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		// std::cout << "write" << std::endl;
		itr = find_by_fd(param.param1_int, pid);

		if ((*itr) -> write_buffer -> available() > 0){
			temp_int = (*itr) -> write_buffer -> put((char*)param.param2_ptr, param.param3_int);
			returnSystemCall(syscallUUID, temp_int);
		}
		else {
			(*itr) -> write_requested = true;
			(*itr) -> write_request = std::make_tuple(syscallUUID, param.param2_ptr, param.param3_int);
		}

		if (!((*itr) -> write_in_process)){

			#ifdef DEBUG
			std::cout << "IDLE write" << std::endl;
			#endif // DEBUG
			
			do_write(*itr);
		}
		
		break;
	case CONNECT:
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		

		fd = param.param1_int;
		sa = static_cast<struct sockaddr_in*> (param.param2_ptr);
		dest_ip = ( sa->sin_addr.s_addr);
		dest_ptr = (const uint8_t *)&dest_ip;
		inter_index = this->getHost()->getRoutingTable(dest_ptr);
		this->getHost()->getIPAddr ( my_ip_1byte, inter_index); 
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
		sendTCPSegment((*itr), NULL, 0, std::vector<FLAGS>{SYN});

		(*itr) -> send_isn++;

		#ifdef DEBUG
		(*itr) -> isn = (*itr) -> send_isn - 1;
		#endif // DEBUG
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

		#ifdef PART2_DEBUG
		std::cout << "Syscall: Accept..." << std::flush;
		#endif // PART2_DEBUG

		fd = param.param1_int; 
		itr = find_by_fd(fd, pid, LISTEN_SOCKET);

		if (itr == connection_vector.end()){
			returnSystemCall(syscallUUID, -1);
			break;
		}

		while (1){
			if ((*itr)->estab_queue -> size() > 0){
				

				(*itr) -> backlog_used--;
				auto new_conn = (*itr) -> estab_queue -> front();
				(*itr) -> estab_queue -> pop_front();

				// if (new_conn -> state != ESTAB_SOCKET || new_conn -> state != CLOSE_WAIT_SOCKET){
				// 	std::cout << "skipping" << std::endl;
				// 	continue;
				// }

				#ifdef PART2_DEBUG
				std::cout << "Available" << std::endl;
				#endif // PART2_DEBUG

				new_conn -> fd = createFileDescriptor(pid); 

				sa = static_cast<struct sockaddr_in*>(param.param2_ptr);
				sa ->sin_addr.s_addr = htonl(new_conn -> remote_port);
				sa -> sin_family = AF_INET;
				sa -> sin_port = htons(new_conn -> remote_port);
				memset(sa -> sin_zero, 0, 8);
				returnSystemCall(syscallUUID, new_conn -> fd);
				break;
			}
			else {
				(*itr) -> accept_queue -> push_back(std::make_tuple(syscallUUID, pid, param.param2_ptr));
				
				#ifdef PART2_DEBUG
				std::cout << "Queued" << std::endl;
				#endif // PART2_DEBUG
				
				break;
			}
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
		itr = find_by_fd(fd, pid);
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
	// ushort sh;
	// in_addr ad;
	char buf[128];
	memset(buf, 0, 128);
	int s = 0;
	// pck -> readData(OFFSET_SRC_IP, &lg, 4);
	// pck -> readData(OFFSET_SRC_PORT, &sh, 2);
	// ad.s_addr = lg;
	// s += sprintf(buf + s, "From %s:%d ", inet_ntoa(ad), ntohs(sh));
	// pck -> readData(OFFSET_DST_IP, &lg, 4);
	// pck -> readData(OFFSET_DST_PORT, &sh, 2);
	// ad.s_addr = lg;
	// s += sprintf(buf + s, "To %s:%d\n", inet_ntoa(ad), ntohs(sh));
	


	// for (int i = 0; i < 5; i++){
	// 	pck -> readData(34 + i * 4, &lg, 4);
	// 	s += sprintf(buf + s, "%x\n", ntohl(lg));
	// }
	
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
		case FIN:
			std::cout << "FIN ";
			break;
		default:
			break;
		}
	}

	pck ->readData(OFFSET_ACK_NUM, &lg, 4);
	s+= sprintf(buf + s, " Acked: %x", ntohl(lg));
	pck -> readData(OFFSET_SEQ_NUM, &lg, 4);
	s += sprintf(buf + s, " Seq: %x", ntohl(lg));
	printf("%s", buf);
	std::cout << std::endl;
	
}



void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{	
	if (fromModule.compare("IPv4") == 0){
		Conn_itr itr, itr1;
		uint rec_window;
		uint16_t checksum;
		ssize_t payload_size;
		unsigned short flags, recw;

		Connection* in_con = new Connection();
		packet -> readData(OFFSET_FLAGS, &flags, 2);
		packet -> readData(OFFSET_DST_IP, &(in_con -> local_ip), 4);
		packet -> readData(OFFSET_SRC_IP, &(in_con -> remote_ip), 4);
		packet -> readData(OFFSET_DST_PORT, &(in_con->local_port), 2);
		packet -> readData(OFFSET_SRC_PORT, &(in_con->remote_port), 2);
		packet -> readData(OFFSET_SEQ_NUM, &(in_con -> recv_isn), 4);
		packet -> readData(OFFSET_ACK_NUM, &(in_con -> send_isn), 4);
		packet -> readData(OFFSET_REC_WNDW, &rec_window, 2);
		packet -> readData(48, &recw, 2);
		payload_size = packet -> getSize();
		payload_size -= 54; // - header size
		flags = ntohs(flags);
		std::vector<FLAGS> flag_vector = get_flags(flags);

		#ifdef PART2_DEBUG
		std::cout << "Arriving...";
		printPack(packet, flag_vector);
		#endif // PART2_DEBUG


		//tcp checksum checking; discard if not correct
		char tcp_segment_temp[payload_size + 20];
		packet -> readData(OFFSET_SRC_PORT, tcp_segment_temp, payload_size + 20);
		checksum = NetworkUtil::tcp_sum((in_con -> remote_ip),(in_con -> local_ip),(const uint8_t* )tcp_segment_temp, payload_size + 20);
		checksum = ~checksum;
		if (checksum != 0){
			#ifdef PART2_DEBUG
			std::cout << "Discarding..."<< checksum << std::endl;
			#endif // PART2_DEBUG
			this->freePacket(packet);
			return;
		}
		char payload[payload_size];
		memcpy(payload, tcp_segment_temp + 20, payload_size);
		// free(tcp_segment_temp);
		// add length detector
		

		itr = find(in_con);
		recw = ntohs(recw);

		in_con -> local_ip = ntohl(in_con -> local_ip);
		in_con -> local_port = ntohs(in_con -> local_port);
		in_con -> remote_ip = ntohl(in_con -> remote_ip);
		in_con -> remote_port = ntohs(in_con -> remote_port);
		in_con -> recv_isn = ntohl(in_con -> recv_isn);
		in_con -> send_isn = ntohl(in_con -> send_isn);
		in_con -> recw = recw;

		
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
			
			itr = find_by_lr_port_ip(in_con);

			if (itr != connection_vector.end()){
				
				
				if ((*itr) -> state == SYN_RCVD_SOCKET){
					cancelTimers((*itr), in_con -> send_isn);
					(*itr)->state = ESTAB_SOCKET;
					(*itr)->recv_isn = in_con->recv_isn + 1;
					(*itr) -> send_isn++;
					(*itr) -> recw = recw;
					sendTCPSegment((*itr), std::vector<FLAGS>{ACK});
					returnSystemCall((*itr) -> uuid, 0);
				}

				else if ((*itr) -> state == SYN_SENT_SOCKET){
					cancelTimers(*itr, (*itr) -> send_isn);
					(*itr)->state = ESTAB_SOCKET;
					(*itr)-> recv_isn = in_con -> recv_isn + 1; 
					(*itr) -> recw = recw;
					
					sendTCPSegment((*itr), std::vector<FLAGS>{ACK});	
					
					(*itr)->read_buffer->set_expected_seq_num((*itr)->recv_isn);
					returnSystemCall((*itr)->uuid, 0);
				}

				else {
					in_con -> recv_isn++;
					sendTCPSegment(in_con, std::vector<FLAGS>{ACK});
				}

			}
			
			free(in_con);
			return;
		}

		else if (flag_map[FIN] && flag_map[ACK]){
			this -> freePacket(packet);
			#ifdef PART2_DEBUG

			#endif // PART2_DEBUG
			

			itr = find_by_lr_port_ip(in_con);

			if (itr != connection_vector.end()){
				if ((*itr) -> state == FIN_WAIT_1_SOCKET){
					(*itr) -> state = CLOSING_SOCKET;
					sendTCPSegment((*itr), std::vector<FLAGS>{ACK});
					return;
				}

				else if ((*itr) -> state == FIN_WAIT_2_SOCKET || (*itr) -> state == TIMED_WAIT_SOCKET) {
					(*itr) -> state = TIMED_WAIT_SOCKET;
					cancelTimers((*itr), in_con->send_isn);
					uint64_t tmp = getHost() -> getSystem() -> getCurrentTime();
					this -> addTimer((void*)new TimerCallbackFrame(TimerCallbackFrame::TimedWait, (*itr), NULL, 0, tmp), 2 * (*itr) -> rto);
				}

				else if ((*itr) -> state == CLOSE_WAIT_SOCKET){
					sendTCPSegment((*itr), std::vector<FLAGS>{ACK});
					return;
				}

				else if ((*itr) -> state == CLOSING_SOCKET){
					sendTCPSegment((*itr), std::vector<FLAGS>{ACK});
					return;
				}

				else if ((*itr) -> state == ESTAB_SOCKET){

					#ifdef PART2_DEBUG
					std::cout << "FINACK to Estab" << std::endl;
					#endif // PART2_DEBUG

					(*itr) -> upper_data_bound = in_con ->recv_isn; // maybe insert to if cond above					
					cancelTimers((*itr), in_con -> send_isn);
					(*itr) -> state = CLOSE_WAIT_SOCKET;
					if ((*itr) -> read_requested){
						if ((*itr)->read_requested && (*itr) -> read_buffer -> inorder_bytes > 0){
							uint to_read = std::get<2>((*itr)->read_request);
							char* to_buffer = (char *) std::get<1>((*itr)->read_request);
							uint32_t actual_get = (*itr) -> read_buffer -> get(to_buffer, to_read);
							(*itr) -> read_requested = false;
							returnSystemCall(std::get<0>((*itr)->read_request), actual_get);
						}
						else{
							returnSystemCall(std::get<0>((*itr) -> read_request), -1);
							(*itr) -> read_requested = false;	
						}
					}
				}

				else if ((*itr) -> state == SYN_RCVD_SOCKET){
					
					performAccept((*itr), in_con);

					if ((*itr)->sim_connect){
						cancelTimers((*itr),in_con -> send_isn+1);
						(*itr)->state = CLOSE_WAIT_SOCKET;
						(*itr)-> recv_isn = in_con -> recv_isn + 1; 
						(*itr) -> recw = recw;
						(*itr) -> send_isn = in_con -> send_isn;
						sendTCPSegment((*itr), std::vector<FLAGS>{ACK});	
						returnSystemCall((*itr)->uuid, 0);
						return;
						
					}
				
					#ifdef PART2_DEBUG
					std::cout << "FINACK TO SYNRCVD ARRIVED" << std::endl;
					#endif // PART2_DEBUG
				}
				(*itr) -> recv_isn++;
				sendTCPSegment((*itr), std::vector<FLAGS>{ACK});
				free(in_con);
			}
		}

		// SYN only
		else if (flag_map[SYN]){

			this -> freePacket (packet);

			itr = find_by_lr_port_ip(in_con);

			if(itr != connection_vector.end()){
				if ((*itr) -> state == SYN_SENT_SOCKET){

					#ifdef PART2_DEBUG
					std::cout << "SimConnect Initiated" << std::endl;
					#endif // PART2_DEBUG

					cancelTimers((*itr), (*itr) -> send_isn);
					(*itr) -> state = SYN_RCVD_SOCKET;
					(*itr) -> recv_isn = in_con -> recv_isn + 1;
					(*itr) -> send_isn--;
					(*itr) -> sim_connect = true; 			
					sendTCPSegment((*itr), NULL, 0, std::vector<FLAGS>{SYN, ACK});
					return;	
				}
			}

			else {
				itr = find_by_port_ip(in_con, LISTEN_SOCKET);
				if (itr != connection_vector.end()){
					if (!(((*itr) -> backlog_used) < ((*itr) -> backlog))){
						// sendRST(in_con);
						return;
					}
					(*itr) -> backlog_used++;
					in_con -> fd = (*itr) -> fd;
					in_con -> state = SYN_RCVD_SOCKET;
					in_con -> pid = (*itr) -> pid;
					in_con -> send_isn = rand();
					in_con -> recv_isn++;
					in_con -> recw = recw;
					connection_vector.push_back(in_con);
					// sendTCPSegment(in_con, std::vector<FLAGS>{SYN, ACK});
					sendTCPSegment(in_con, NULL, 0, std::vector<FLAGS>{SYN, ACK});
					in_con -> send_isn++;

					#ifdef DEBUG
					(*itr) -> isn = (*itr) -> send_isn - 1;
					#endif // DEBUG
				}
			}		
		}
		// ACK
		else if (flag_map[ACK])
		{		
			itr = find_by_lr_port_ip(in_con);
			if (itr != connection_vector.end()){
				if ((*itr) -> state == ESTAB_SOCKET){
					if (payload_size > 0){
						(*itr) -> recv_isn = (*itr) -> read_buffer -> put(payload, in_con -> recv_isn, in_con -> send_isn, payload_size);
						if ((*itr)->read_requested && (*itr) -> read_buffer -> inorder_bytes > 0){
							uint to_read = std::get<2>((*itr)->read_request);
							char* to_buffer = (char *) std::get<1>((*itr)->read_request);
							uint32_t actual_get = (*itr) -> read_buffer -> get(to_buffer, to_read);
							(*itr) -> read_requested = false;
							returnSystemCall(std::get<0>((*itr)->read_request), actual_get);
						}
						sendTCPSegment((*itr), std::vector<FLAGS>{ACK});
					}
					auto to_ack = &((*itr) -> not_acked_pckts);
					if (to_ack -> size() > 0){
						uint acked = in_con -> send_isn;

						#ifdef DEBUG
						printf("Acked: %d...%d\n", acked - (*itr) -> isn, (*itr) -> congstate);
						#endif // DEBUG

						if ((*itr) -> last_ack == acked){
							(*itr) -> dup_ack_counter++;
							if ((*itr) -> dup_ack_counter == 3){
								(*itr) -> sshtresh = (*itr) -> cwnd / 2;
								(*itr) -> cwnd = (*itr) -> sshtresh + 3 * 512; 
								
								#ifdef DEBUG
								std::cout << std::endl << "Fast Retransmission" << std::endl;
								#endif // PART2_DEBUG
								
								fastRetransmit(*itr);
								(*itr) -> congstate = CongestionAvoidance;								
							}
						}
						else{
							(*itr) -> congstate = ((*itr) -> congstate == FastRecovery) ? CongestionAvoidance : (*itr) -> congstate;
							(*itr) -> last_ack = acked;
							(*itr) -> dup_ack_counter = 0;
						}
						int canceled = cancelTimers((*itr), acked);

						if ((*itr) -> congstate == SlowStart){
							(*itr) -> cwnd += MSS * canceled;
							#ifdef DEBUG
							std::cout << "SlowStart new ACK: +" << canceled << " MSS" << std::endl;
							#endif // 
						}

						if ((*itr) -> byte_in_flight < (*itr) -> cwnd / 2){
							(*itr) -> cwnd +=  MSS / 2;
							do_write((*itr));
						}

						if (to_ack -> size() == 0){
							if ((*itr) -> congstate == CongestionAvoidance){
								(*itr) -> cwnd += MSS;
								
								#ifdef DEBUG
								std::cout << "CongAvoid + 1" << std::endl;
								#endif // 
							}
							else if ((*itr) -> cwnd >= (*itr) -> sshtresh){
								#ifdef DEBUG
								std::cout << "Threshold reached" << std::endl;
								#endif // DEBUG

								(*itr) -> congstate = CongestionAvoidance;
							}

							#ifdef DEBUG
							std::cout << "completed" << std::endl;
							#endif // DEBUG
							
							(*itr) -> timers_map.clear();
							// (*itr) -> byte_in_flight = 0;
							do_write((*itr));
						}
					}
					else {
						#ifdef PART2_DEBUG
						std::cout << "Simconnect" << std::endl;
						#endif // PART2_DEBUG
						cancelTimers((*itr), in_con -> send_isn);
					}
				}

				if ((*itr) -> state == CLOSE_WAIT_SOCKET){
					if (payload_size > 0){
						
						#ifdef PART2_DEBUG
						std::cout<<"(close Wait) with payload"<<std::endl;
						#endif // PART2_DEBUG

						(*itr) -> read_buffer -> put(payload, in_con -> recv_isn, in_con -> send_isn, payload_size, (*itr)->upper_data_bound);
						if ((*itr)->read_requested && (*itr) -> read_buffer -> inorder_bytes > 0){
							uint to_read = std::get<2>((*itr)->read_request);
							char* to_buffer = (char *) std::get<1>((*itr)->read_request);
							uint32_t actual_get = (*itr) -> read_buffer -> get(to_buffer, to_read);
							(*itr) -> read_requested = false;
							returnSystemCall(std::get<0>((*itr)->read_request), actual_get);
						}	
					}
					sendTCPSegment((*itr), std::vector<FLAGS>{ACK});
				}

				if ((*itr) -> state == LAST_ACK_SOCKET){
					cancelTimers((*itr), (in_con)->send_isn);
					if (payload_size > 0){
						
						#ifdef PART2_DEBUG
						std::cout<<"(last ack Wait) with payload"<<std::endl;
						#endif // PART2_DEBUG

						(*itr) -> read_buffer -> put(payload, in_con -> recv_isn, in_con -> send_isn, payload_size, (*itr)->upper_data_bound);
						if ((*itr)->read_requested && (*itr) -> read_buffer -> inorder_bytes > 0){
							uint to_read = std::get<2>((*itr)->read_request);
							char* to_buffer = (char *) std::get<1>((*itr)->read_request);
							uint32_t actual_get = (*itr) -> read_buffer -> get(to_buffer, to_read);
							(*itr) -> read_requested = false;
							returnSystemCall(std::get<0>((*itr)->read_request), actual_get);
						}
						sendTCPSegment((*itr), std::vector<FLAGS>{ACK});			
					}
					else{
						// removeFileDescriptor((*itr)->pid, (*itr)->fd);
						returnSystemCall((*itr)->uuid, 0);
						// connection_vector.erase(itr);
					}
				}

				if ((*itr) -> state == SYN_RCVD_SOCKET){
					performAccept((*itr), in_con);
				}

				if ((*itr) -> state == FIN_WAIT_1_SOCKET){
					(*itr) -> state = FIN_WAIT_2_SOCKET;
					cancelTimers((*itr), in_con -> send_isn);

				}
				if ((*itr) -> state == CLOSING_SOCKET){
					(*itr) -> state = TIMED_WAIT_SOCKET;
					cancelTimers((*itr), in_con -> send_isn + 1	);

					this -> addTimer((void*)new TimerCallbackFrame(TimerCallbackFrame::TimedWait, (*itr), NULL, 0, 0), 2 * (*itr) -> rto);
					// Add retransmission
				}
				
				if ((*itr) -> state == FIN_WAIT_2_SOCKET){
					cancelTimers((*itr), in_con -> send_isn);

				}

				free(in_con);
			}
			
			this -> freePacket(packet);			
		}
		// std::cout << "Sent" << std::endl;
	}
}


void TCPAssignment::timerCallback(void *payload){
	TimerCallbackFrame *info = (TimerCallbackFrame*)payload;
	if (info -> timer_type == TimerCallbackFrame::ACKTimeout){

		if (info -> self_destruct){
			free(info -> payload);
			free(info);
			return;
		}
		info -> TTL--;
		if (info -> TTL == 0){
			info -> self_destruct = true;
		}

		Connection *con = (Connection*) info -> con;
		if (con -> state == ESTAB_SOCKET && con -> congstate != FastRecovery){
			con -> congstate = SlowStart;
			con -> sshtresh = con -> cwnd / 2;
			con -> cwnd = MSS;
			con -> dup_ack_counter = 0;
			con -> congstate = FastRecovery;

			#ifdef DEBUG
			std::cout << "Timeouted...transition to fastrecovery" << std::endl;
			#endif // DEBUG
		}


		char *buffer = (char*) info -> payload;

		Packet* packet = this -> allocatePacket(info -> payload_size);
		packet -> writeData(0, buffer, info -> payload_size);



		this -> addTimer(payload, con -> rto);

		#ifdef PART2_DEBUG
		ushort flags;
		packet -> readData(OFFSET_FLAGS, &flags, 2);
	 	std::cout << "Timeout Sending...";
		printPack(packet, get_flags(ntohs(flags)));
		#endif // PART2_DEBUG

		this -> sendPacket("IPv4", packet);
	}

	if (info -> timer_type == TimerCallbackFrame::TimedWait){
		Connection* con = (Connection*) info -> con;
		cancelTimers(con, con-> send_isn +1 );
		con -> state = CLOSED_SOCKET;
		returnSystemCall(con -> uuid, 0);
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

void TCPAssignment::construct_tcpheader(Packet * pkt, Connection *con, std::vector<FLAGS> flags, int payload_size){
		
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
		
		ushort recv_wind = htons(con->read_buffer->space_available);
		pkt -> writeData(OFFSET_REC_WNDW, &recv_wind, 2);
		
		u_char tcpsegment[20 + payload_size];
		pkt -> readData(34, tcpsegment, 20 + payload_size);
		
		uint16_t chec = NetworkUtil::tcp_sum(htonl(con -> local_ip), htonl(con -> remote_ip) ,tcpsegment, 20 + payload_size);
		chec = ~chec;
		chec = htons(chec);
		pkt -> writeData(50, &chec, 2);
}

inline void TCPAssignment::sendTCPSegment(Connection *con, std::vector<FLAGS> flags){
	// Sends only header now
	Packet *pck = this -> allocatePacket(54);
	construct_tcpheader(pck, con, flags, 0);
	
	#ifdef PART2_DEBUG
	std::cout << "Sending...";
	printPack(pck, flags);
	#endif // PART2_DEBUG

	this -> sendPacket("IPv4", pck);

}

inline void TCPAssignment::sendTCPSegment(Connection *con, char* payload, int payload_size, std::vector<FLAGS> flags){
	Packet *pck = this -> allocatePacket(54 + payload_size);
	
	pck -> writeData(54, payload, payload_size);
	construct_tcpheader(pck, con, flags, payload_size);
	uint old_seq = con -> send_isn;
	con -> send_isn += payload_size;
	con -> not_acked_pckts.push_back(old_seq + 1);
	
	char *buffer = (char*) malloc(54 + payload_size);
	pck -> readData(0, buffer, 54 + payload_size);
	TimerCallbackFrame *tmp = new TimerCallbackFrame(TimerCallbackFrame::ACKTimeout, con, buffer, 54 + payload_size, getHost() -> getSystem() -> getCurrentTime());
	this -> addTimer((void*) tmp, con -> rto);
	con -> timers_map.insert({old_seq + 1, (void*) tmp});
	
	
	#ifdef PART2_DEBUG
	std::cout << "Sending...";
	printPack(pck, flags);
	#endif // PART2_DEBUG
	
	this -> sendPacket("IPv4", pck);

}

inline void TCPAssignment::sendRST(Connection *con){
	sendTCPSegment(con, std::vector<FLAGS>{RST});
}

int TCPAssignment::cancelTimers(Connection *con, uint64_t last){
	int res = 0;
	auto to_ack = &(con -> not_acked_pckts);
	auto ack_itr = std::upper_bound(to_ack -> begin(), to_ack -> end(), last);
	std::vector<uint> to_erase;
	for (auto titr = to_ack -> begin(); titr != ack_itr; titr++){
		TimerCallbackFrame* tmp = (TimerCallbackFrame*) con -> timers_map[*titr];
		tmp -> self_destruct = true;

		con -> byte_in_flight -= (tmp -> payload_size - 54);

		to_erase.push_back(*titr);

		uint64_t rtt = getHost() -> getSystem() -> getCurrentTime() - tmp -> creation_time;
		con -> updateRTO(rtt); 		

		res++;
	}
	for (uint i = 0; i < to_erase.size(); i++)
		con -> timers_map.erase(to_erase[i]);
	to_ack -> erase(to_ack -> begin(), ack_itr);
	return res;
}


void TCPAssignment::do_write(Connection* con){
	con -> write_in_process = true;
	#ifdef DEBUG
	int total = 0;
	printf("Before Write: state - %d, bif - %d, recw - %d, cwnd: %d\n", con -> congstate, con->byte_in_flight, con -> recw, con -> cwnd);
	fflush(stdout);
	#endif
	while (con -> write_buffer -> get_size() > 0){
		int to_fetch = std::min(con -> recw - con -> byte_in_flight, con -> cwnd - con -> byte_in_flight);
		to_fetch = std::min(to_fetch, MSS);
		if (!to_fetch)
			break;
		char *payload = (char*)malloc(to_fetch);
		int actual_size = con -> write_buffer -> get(payload, to_fetch);
		sendTCPSegment(con, payload, actual_size, std::vector<FLAGS>{ACK});
		free(payload);
		con -> byte_in_flight += actual_size;

		#ifdef DEBUG
		total++;
		#endif // DEBUG
	}
	#ifdef DEBUG
	std::cout << "Sent: " << total << std::endl;

	for (uint i = 0; i < con -> not_acked_pckts.size(); i++){
		printf("%d ", con -> not_acked_pckts[i] - con -> isn);
	}
	std::cout << std::endl;

	#endif // DEBUG
	if (con -> write_requested){
		int sysuuid = std::get<0>(con -> write_request);
		char *ptr = (char*)std::get<1>(con -> write_request);
		int size = std::get<2>(con -> write_request);

		int actual = con -> write_buffer -> put(ptr, size);
		con -> write_requested = false;				
		returnSystemCall(sysuuid, actual);
		return;
	}	
	if (con -> write_buffer -> get_size() == 0 && con -> close_requested){
		sendTCPSegment(con, NULL, 0, std::vector<FLAGS>{FIN, ACK});
		con -> send_isn++;
		con -> state = FIN_WAIT_1_SOCKET;
		return;
	}

	if (con -> write_buffer -> get_size() == 0){
		con -> write_in_process = false;
	}
}



void TCPAssignment::performAccept(Connection* con, Connection *in_con){
	// cancelTimers((*con), in_con->send_isn);
	Connection *t_connection = con;
	t_connection -> state = ESTAB_SOCKET;
	cancelTimers(t_connection, in_con -> send_isn );
	std::vector<Connection*>::iterator itr = find_by_fd(t_connection -> fd, t_connection -> pid, LISTEN_SOCKET);
	t_connection -> recw = 512;
	t_connection -> recv_isn = in_con -> recv_isn;
	t_connection -> read_buffer -> set_expected_seq_num(in_con -> recv_isn);

	if (itr == connection_vector.end()){
		returnSystemCall(t_connection -> uuid, 0);
		return;
	}

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
		// (*itr)->read_buffer->set_expected_seq_num((*itr)->recv_isn);
		returnSystemCall((UUID)std::get<0>(tup), new_fd);

		#ifdef PART2_DEBUG
		std::cout << "Request handled" << std::endl;
		#endif // PART2_DEBUG

	}
	else{
		#ifdef PART2_DEBUG
		std::cout << "Pushed to queue" << std::endl;
		#endif // PART2_DEBUG
		(*itr) -> estab_queue -> push_back(t_connection);
		(*itr) -> backlog_used --;
	}		
}


void TCPAssignment::fastRetransmit(Connection* con){

	#ifdef DEBUG
	uint first = con ->not_acked_pckts[0] - con -> isn;
	uint last = con -> not_acked_pckts[con -> not_acked_pckts.size() - 1] - con -> isn;
	std::cout << "First: " << first << "Last: " << last << std::endl;
	#endif // DEBUG

	std::vector<uint> tmp_vec(con -> not_acked_pckts);
	con -> send_isn = tmp_vec[0] - 1;
	con -> not_acked_pckts.clear();
	for (uint a: tmp_vec){
		auto tmp = (TimerCallbackFrame*)con -> timers_map[a];
		con -> timers_map.erase(a);
		tmp -> self_destruct = true;
		char* start = (char*) tmp -> payload;
		start += 54;
		sendTCPSegment(con, start, (tmp -> payload_size - 54), std::vector<FLAGS>{ACK});
	}
}






/*---------------------------------------------------------------------------------------------------*/

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



}



