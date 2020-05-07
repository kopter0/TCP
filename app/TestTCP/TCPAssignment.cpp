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
	char *buffer;
	struct sockaddr_in *sa;
	Connection *t_connection;
	//Conn_itr itr;
	// Conn_itr itr;
	std::vector<Connection*>::iterator itr;
	std::vector <FLAGS> fl;
	
	uint total_bytes_left, in_bytes, in_bytes_ret; 
	char *buffer_ptr;
	TCPAssignment::ReadBuffer::packet_info_rcvd *temp;

	int inter_index, temp_int;
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
			break;
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
		in_bytes = (*itr)->read_buffer->inorder_bytes;
		in_bytes_ret = in_bytes;
		if (in_bytes > 0){
			while(total_bytes_left > 0 && in_bytes > 0){
				temp = (*itr)->read_buffer->pop_packet_inorder();
				if (total_bytes_left >= temp->data_length){
					for(uint i = 0; i < temp->data_length ; i++){
						*buffer_ptr = temp->buffer[i];
						buffer_ptr++;
					}
					total_bytes_left -= temp->data_length;

				}
				else{
					for(uint i = 0; i < total_bytes_left ; i++){
						*buffer_ptr = temp->buffer[i];
						buffer_ptr++;
					}
					(*itr)->read_buffer->insert_inorder(temp->seq_num + total_bytes_left, temp->ack_num, temp->data_length - total_bytes_left, buffer_ptr, true);
					total_bytes_left = 0;

				}

			in_bytes = (*itr)->read_buffer->inorder_bytes;
			}

			returnSystemCall(syscallUUID, std::min(in_bytes_ret, (uint) param.param3_int));
			break;
		}
		else{
			(*itr)->read_requested = true;
			(*itr)->read_request = std::make_tuple(syscallUUID, param.param2_ptr,param.param3_int);
			break;
		}
		// if ((*itr)->read_buffer->inorder_bytes >= param.param3_int){
		// 	while(total_bytes_left > 0){
		// 		TCPAssignment::ReadBuffer::packet_info_rcvd *temp = (*itr)->read_buffer->pop_packet_inorder();
		// 		for(uint i = 0; i<temp->data_length;i++){
		// 				*buffer_ptr = temp->buffer[i];
		// 				buffer_ptr++;
		// 		}
		// 		total_bytes_left -= temp->data_length;

		// 	}
		// 	returnSystemCall(syscallUUID, param.param3_int);
		// 	break;
		// }

		// in_bytes = (*itr)->read_buffer->inorder_bytes;
		//std::cout<<in_bytes<<"\n";
		// while(total_bytes_left > 0 && (*itr)->read_buffer->inorder_bytes != 0 ){
		// 	TCPAssignment::ReadBuffer::packet_info_rcvd *temp = (*itr)->read_buffer->pop_packet_inorder();
		// 	if (total_bytes_left >= temp->data_length){
		// 		for(uint i = 0; i < temp->data_length ; i++){
		// 		*buffer_ptr = temp->buffer[i];
		// 		buffer_ptr++;
		// 		}
		// 		total_bytes_left -= temp->data_length;

		// 	}
		// 	else{
		// 		for(uint i = 0; i < total_bytes_left ; i++){
		// 			*buffer_ptr = temp->buffer[i];
		// 			buffer_ptr++;
		// 		}
		// 		(*itr)->read_buffer->insert_inorder(temp->seq_num + total_bytes_left, temp->ack_num, temp->data_length - total_bytes_left, buffer_ptr, true);
		// 		total_bytes_left = 0;
		// 	}



		// }

		
			
	
		
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

		if (!(*itr) -> write_in_process){
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
			//
			(*itr)->read_buffer->set_expected_seq_num((*itr)->recv_isn);
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
	std::cout<<"payload_size"<<pck->getSize()-54<<std::endl;
	pck -> readData(OFFSET_DST_IP, &lg, 4);
	pck -> readData(OFFSET_DST_PORT, &sh, 2);
	ad.s_addr = lg;
	s += sprintf(buf + s, "To %s:%d\n", inet_ntoa(ad), ntohs(sh));
	
	
	printf("%s", buf);

	// s = 0;
	// for(int i = 0; i < 5; i++){
	// 	int t;
	// 	pck -> readData(34 + 4 * i, &t, 4);
	// 	s += sprintf(buf + s, "%x\n", t);
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
		payload_size = packet -> getSize();
		payload_size -= 54; // - header size
		
		//tcp checksum checking; discard if not correct
		char tcp_segment_temp[payload_size + 20];
		packet -> readData(OFFSET_SRC_PORT, tcp_segment_temp, payload_size + 20);
		checksum = NetworkUtil::tcp_sum((in_con -> remote_ip),(in_con -> local_ip),(const uint8_t* )tcp_segment_temp, payload_size + 20);
		checksum = ~checksum;
		if (checksum != 0){
			this->freePacket(packet);
			return;
		packet -> readData(48, &recw, 2);
		// add length detector

		}
		char payload[payload_size];
		memcpy((void*)payload, (const void *)(tcp_segment_temp + 20), payload_size );
		// add length detector
		
		in_con -> local_ip = ntohl(in_con -> local_ip);
		in_con -> local_port = ntohs(in_con -> local_port);
		in_con -> remote_ip = ntohl(in_con -> remote_ip);
		in_con -> remote_port = ntohs(in_con -> remote_port);
		in_con -> recv_isn = ntohl(in_con -> recv_isn);
		in_con -> send_isn = ntohl(in_con -> send_isn);

		recw = ntohs(recw);
		flags = ntohs(flags);
		std::vector<FLAGS> flag_vector = get_flags(flags);
		flag_map.clear();
		for (FLAGS fl: all_flags){
			flag_map[fl] = false;
		}
		for (FLAGS fl: flag_vector){
			flag_map[fl] = true;
		}
		// printPack(packet, flag_vector);
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
			
			(*itr)->read_buffer->set_expected_seq_num((*itr)->recv_isn);
			returnSystemCall((*itr)->uuid, 0);
			free(in_con);
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
					returnSystemCall((*itr) -> uuid, 0);
					// (*itr) -> timer_uuid = addTimer((*itr), 60);
				}

				else if ((*itr) -> state == TIMED_WAIT_SOCKET){
					// cancelTimer((*itr) -> timer_uuid);
					// (*itr) -> timer_uuid = addTimer((*itr), 60);
				}

				else if ((*itr) -> state == ESTAB_SOCKET){
					(*itr) -> state = CLOSE_WAIT_SOCKET;
				}
				(*itr) -> recv_isn++;
				sendTCPSegment((*itr), std::vector<FLAGS>{ACK});
				// (*itr) -> send_isn++;
				free(in_con);
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
				//(*itr) -> sim_connect = true; 			
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
			in_con -> recw = recw;
			connection_vector.push_back(in_con);
			sendTCPSegment(in_con, std::vector<FLAGS>{SYN, ACK});
			in_con -> send_isn++;
		}
		// ACK
		else if (flag_map[ACK])
		{
			
			// sim connect
			itr = find_by_lr_port_ip(in_con);

			if (itr != connection_vector.end()){
				// if ((*itr) -> state == ESTAB_SOCKET){
				// 	returnSystemCall((*itr)->uuid, 0 );
				// }
				if ((*itr) -> state == ESTAB_SOCKET){
					// printPack(packet, flag_vector);
					if (payload_size > 0){
						uint32_t cur_seq = (in_con->recv_isn);
						uint32_t exp_seq = (((*itr)->read_buffer)->expected_seq());
						if (cur_seq == exp_seq){
							(*itr)->read_buffer->insert_inorder(in_con->recv_isn, in_con->send_isn, payload_size, payload);
							(*itr)->read_buffer->check_ooo_packets();
							((*itr)->recv_isn) = (((*itr)->read_buffer)->expected_seq());
							sendTCPSegment((*itr), std::vector<FLAGS>{ACK}); 
							if ((*itr)->read_requested){
								uint bytes_read_left = std::get<2>((*itr)->read_request);

								char* buffer_ptr = (char *) std::get<1>((*itr)->read_request);
								
								uint in_bytes = (*itr)->read_buffer->inorder_bytes;
								uint in_bytes_ret = in_bytes;
								while(bytes_read_left > 0 && in_bytes > 0){
									TCPAssignment::ReadBuffer::packet_info_rcvd *temp = (*itr)->read_buffer->pop_packet_inorder();
									if (bytes_read_left >= temp->data_length){
										for(uint i = 0; i < temp->data_length ; i++){
											*buffer_ptr = temp->buffer[i];
											buffer_ptr++;
										}
										bytes_read_left -= temp->data_length;

									}
									else{
										for(uint i = 0; i < bytes_read_left ; i++){
											*buffer_ptr = temp->buffer[i];
											buffer_ptr++;
										}
										(*itr)->read_buffer->insert_inorder(temp->seq_num + bytes_read_left, temp->ack_num, temp->data_length - bytes_read_left, buffer_ptr, true);
										bytes_read_left = 0;

									}

								in_bytes = (*itr)->read_buffer->inorder_bytes;
								}
													
								returnSystemCall(std::get<0>((*itr)->read_request), std::min(in_bytes_ret,(uint) std::get<2>((*itr)->read_request) ));
								(*itr)->read_requested = false;
							}
							// add write if needed
							return;
						}
						else if (cur_seq > exp_seq){
							(*itr)->read_buffer->insert_ooo(in_con->recv_isn, in_con->send_isn, payload_size, payload);
							sendTCPSegment((*itr), std::vector<FLAGS>{ACK});
							return;
						}
						else{
							sendTCPSegment((*itr), std::vector<FLAGS>{ACK});
							return;
						}


					}
					auto to_ack = &((*itr) -> not_acked_pckts);
					if (to_ack -> size() > 0){
						int acked = in_con -> send_isn;
						auto ack_itr = std::lower_bound(to_ack -> begin(), to_ack -> end(), acked);
						(*itr) -> max_allowed_packets += (ack_itr - to_ack -> begin());
						to_ack -> erase(to_ack -> begin(), ack_itr);
						// std::cout << "Acked: " << acked << " left: " << (*itr) -> not_acked_pckts.size() << std::endl;
						if (to_ack -> size() == 0){
							(*itr) -> byte_in_flight = 0;
							do_write((*itr));
							// std::cout << "sdfds" << std::endl;
						}
					}
					else {
						(*itr)->read_buffer->set_expected_seq_num((*itr)->recv_isn);

						returnSystemCall((*itr)->uuid, 0 );
					}
				}
				
				

				if ((*itr) -> state == LAST_ACK_SOCKET){
					uint64_t uuid_temp = (*itr)->uuid;
					connection_vector.erase(itr);
					
					returnSystemCall((*itr)->uuid, 0 );
				}

				if ((*itr) -> state == SYN_RCVD_SOCKET){
					Connection *t_connection = (*itr);
					t_connection -> state = ESTAB_SOCKET;
					itr = find_by_fd(t_connection -> fd, t_connection -> pid, LISTEN_SOCKET);
					t_connection -> recw = recw;

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
						(*itr)->read_buffer->set_expected_seq_num((*itr)->recv_isn);
						returnSystemCall((UUID)std::get<0>(tup), new_fd);

					}
					else{
						(*itr) -> estab_queue -> push_back(t_connection);
						(*itr) -> backlog_used --;
					}		
				}

				if ((*itr) -> state == FIN_WAIT_1_SOCKET)
					(*itr) -> state = FIN_WAIT_2_SOCKET;
				if ((*itr) -> state == CLOSING_SOCKET){
					(*itr) -> state = TIMED_WAIT_SOCKET;
					// Add retransmission
				}

				free(in_con);
			}
			
			this -> freePacket(packet);
		}
		// std::cout << "Sent" << std::endl;
	}
}

void TCPAssignment::timerCallback(void* payload)
{
	Packet* packet = (Packet*) payload;
	short flags;
	int seq_num;
	Connection* in_con = new Connection();
	packet -> readData(OFFSET_FLAGS, &flags, 2);
	packet -> readData(OFFSET_DST_IP, &(in_con -> remote_port), 4);
	packet -> readData(OFFSET_SRC_IP, &(in_con -> local_ip), 4);
	packet -> readData(OFFSET_DST_PORT, &(in_con-> remote_port), 2);
	packet -> readData(OFFSET_SRC_PORT, &(in_con-> local_port), 2);
	packet -> readData(OFFSET_SEQ_NUM, &seq_num, 4);
	// add length detector

	in_con -> local_ip = ntohl(in_con -> local_ip);
	in_con -> local_port = ntohs(in_con -> local_port);
	in_con -> remote_ip = ntohl(in_con -> remote_ip);
	in_con -> remote_port = ntohs(in_con -> remote_port);
	seq_num = ntohl(seq_num);

	Conn_itr itr = find_by_lr_port_ip(in_con);

	Packet* pck_copy = this -> clonePacket(packet);
	this -> sendPacket("IPv4", packet);
	// add timer to discard OoO

	UUID new_timer_uuid = this -> addTimer(pck_copy, 60);
	(*itr) -> timers_map[seq_num] = {new_timer_uuid, pck_copy};
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
	this -> sendPacket("IPv4", pck);
}

inline void TCPAssignment::sendTCPSegment(Connection *con, char* payload, int payload_size, std::vector<FLAGS> flags){
	Packet *pck = this -> allocatePacket(54 + payload_size);
	
	pck -> writeData(54, payload, payload_size);
	construct_tcpheader(pck, con, flags, payload_size);
	con -> not_acked_pckts.push_back(con -> send_isn);
	con -> send_isn += payload_size;
	// Packet* pck_copy = this -> clonePacket(pck);
	// con -> timers_map.insert({con-> send_isn, {this -> addTimer(pck_copy, 60), pck_copy}});
	this -> sendPacket("IPv4", pck);
}

// void TCPAssignment::next_seq_ack(Connection *itr,Connection *in_con, uint16_t payload_size, uint16_t &next_seq,uint16_t &next_ack){

// 	// make the out of order packets work






// }


inline void TCPAssignment::sendRST(Connection *con){
	sendTCPSegment(con, std::vector<FLAGS>{RST});
}

void TCPAssignment::disable_timers_until(Connection *con, uint64_t last){
	auto itr = con -> timers_map.begin();
	for (; itr != con -> timers_map.end(); itr++){
		int sn = itr -> first;
		if (sn <= last){
			auto p = itr -> second;
			this -> cancelTimer(p.first);
			this -> freePacket(p.second);
		}
		else
			break;
	}
}


void TCPAssignment::do_write(Connection* con){
	con -> write_in_process = true;
	int total_sent = 0, total_size = 0;
	while (con -> write_buffer -> get_size() > 0){
		if ((con -> not_acked_pckts.size() < con -> max_allowed_packets) && (con -> byte_in_flight < con -> recw)){
			int to_fetch = std::min(512, 512);
			char *payload = (char*)malloc(to_fetch);
			int actual_size = con -> write_buffer -> get(payload, to_fetch);
			sendTCPSegment(con, payload, actual_size, std::vector<FLAGS>{ACK});
			free(payload);
			con -> byte_in_flight += actual_size;
			total_sent++;
			total_size += actual_size;
		}
		else 
			break;
	}
	if (con -> write_requested){
		int sysuuid = std::get<0>(con -> write_request);
		char *ptr = (char*)std::get<1>(con -> write_request);
		int size = std::get<2>(con -> write_request);

		int actual = con -> write_buffer -> put(ptr, size);
		con -> write_requested = false;				
		returnSystemCall(sysuuid, actual);
		// std::cout << "From else. pcks: " << total_sent << " bytes: " << total_size << std::endl;
		return;
	}	
	// std::cout << "pcks: " << total_sent << " bytes: " << total_size << std::endl;

	con -> write_in_process = false;
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

#pragma region ReadBuffer



	
	
#pragma endregion ReadBuffer



}



