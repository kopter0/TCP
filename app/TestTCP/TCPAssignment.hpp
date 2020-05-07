/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;

public:
	#define OFFSET_DST_IP 30
	#define OFFSET_SRC_IP 26
	#define OFFSET_SRC_PORT 34
	#define OFFSET_DST_PORT 36
	#define OFFSET_SEQ_NUM 38
	#define OFFSET_ACK_NUM 42
	#define OFFSET_FLAGS 46
	
	enum FLAGS {SYN, ACK, FIN, RST};
    
	enum socket_state{
        CLOSED_SOCKET,
        LISTEN_SOCKET,
        SYN_SENT_SOCKET,
        SYN_RCVD_SOCKET,
        ESTAB_SOCKET,
        //exit state send FIN
        FIN_WAIT_1_SOCKET,
        FIN_WAIT_2_SOCKET,
        CLOSING_SOCKET,
        TIMED_WAIT_SOCKET,
        //exit state FIN rcvd
        CLOSE_WAIT_SOCKET,
        LAST_ACK_SOCKET
    };
    std::map<socket_state, std::string> socket_FSM ={
        {CLOSED_SOCKET, "CLOSEDs"},
        {LISTEN_SOCKET, "LISTENs"},
        {SYN_SENT_SOCKET, "SYN_SENTs"},
        {SYN_RCVD_SOCKET, "SYN_RCVDs"},
        {ESTAB_SOCKET, "ESTABs"},
        {FIN_WAIT_1_SOCKET, "FIN_WAIT_1s"},
        {FIN_WAIT_2_SOCKET, "FIN_WAIT_2s"},
        {CLOSING_SOCKET, "CLOSINGs"},
        {TIMED_WAIT_SOCKET, "TIME_WAITs"},
        {CLOSE_WAIT_SOCKET, "CLOSE_WAITs"},
        {LAST_ACK_SOCKET, "LAST_ACKs"}
        
    };
    
        #define MAXBUFFERSIZE 51200 
    class MyBuffer{
        char buffer[MAXBUFFERSIZE];
        int start, end, size;

    public:
        MyBuffer(){
            start = end = size = 0;
        }

        inline int get_size(){
            return size;
        }

        inline int available(){
            return MAXBUFFERSIZE - size;
        }

        int get(char *tobuffer, int to_get){
            int actual_get= std::min(to_get, size);
            if (start + actual_get < MAXBUFFERSIZE){
                memcpy(tobuffer, buffer + start, actual_get);
                start += actual_get;
            }
            else {
                memcpy(tobuffer, buffer + start, MAXBUFFERSIZE - start);
                int second_phase = actual_get + start - MAXBUFFERSIZE;
                memcpy(tobuffer + MAXBUFFERSIZE - start, buffer, second_phase);
                start = second_phase;

            }
            size -= actual_get;
            // std::cout << "After get: " << size << std::endl;
            // std::cout << "start: " << start << " end: " << end << " to_get: " << to_get << std::endl;
            return actual_get;
        }
        int put(char *frombuffer, int to_put){
            // FILE *fd = fopen("output.txt", "a+");
            int free = available();
            int actual_put = std::min(to_put, free);
            if (end + actual_put < MAXBUFFERSIZE){
                memcpy(buffer + end, frombuffer, actual_put);
                end += actual_put; 
            }

            else {
                memcpy(buffer + end, frombuffer, MAXBUFFERSIZE - end);
                int second_phase = actual_put + end - MAXBUFFERSIZE;
                memcpy(buffer, frombuffer + MAXBUFFERSIZE - end, second_phase);
                end = second_phase;
            }
            // char buf[32];
            // sprintf(buf, "Write: Start: %d, End: %d\n", start, end);
            // fputs(buf, fd);
            // fclose(fd);
            size += actual_put;
            // std::cout << "start: " << start << " end: " << end << " to_put: " << to_put << std::endl;
            // std::cout << "after put: " << size << std::endl;
            return actual_put;
        }
    };

	struct Connection{
        uint fd;
        in_addr_t local_ip, remote_ip;
        uint send_isn, recv_isn, backlog, backlog_used;
        std::deque<std::tuple<uint64_t, int, void*>> *accept_queue;
        std::deque<Connection *> *estab_queue;
        socket_state state;
        uint64_t uuid, timer_uuid, read_uuid;
        std::map<int, std::pair<uint64_t, Packet*>> timers_map;
        std::vector<int> not_acked_pckts;
        int pid, max_allowed_packets;
        ushort recw, conw, byte_in_flight;
        in_port_t local_port, remote_port;
        bool bound, write_requested, read_request, write_in_process;
        std::tuple<uint64_t, void*, int> write_request;
        MyBuffer *read_buffer, *write_buffer; 
        Connection(){
            fd = local_ip = remote_ip = send_isn = recv_isn = local_port = remote_port = backlog = backlog_used = 0;
            recw = conw = 1;
            byte_in_flight = 0;
            uuid = timer_uuid = read_uuid = 0;
            max_allowed_packets = 1;
			pid = -1;
            state = CLOSED_SOCKET;  
            bound = write_requested = read_request = write_in_process = false;
            read_buffer = new MyBuffer();
            write_buffer = new MyBuffer();
            not_acked_pckts = std::vector<int>();
            timers_map = std::map<int, std::pair<uint64_t, Packet*>>();
        }
        ~Connection(){
        }

        friend bool operator<(const Connection & lhs, const Connection & rhs){
            return (lhs.fd < rhs.fd);
        }

        void operator=(const Connection & other){
            fd = other.fd;
            local_ip = other.local_ip;
            remote_ip = other.remote_ip;
            send_isn = other.send_isn;
            recv_isn = other.recv_isn;
            local_port = other.local_port;
            remote_port = other.remote_port;
            state = other.state;
            bound = other.bound;
            backlog = other.backlog;
            backlog_used = other.backlog_used;
            pid = other.pid;
            uuid = other.uuid;
            recw = other.recw;
        }
    };



	#define Conn_itr std::vector<TCPAssignment::Connection*>::iterator
    std::vector<Connection*> connection_vector;
    #define pb std::vector<TCPAssignment::Connection*>::push_back

	std::vector<FLAGS> all_flags;
	std::map<FLAGS, bool> flag_map;

	TCPAssignment(Host* host);
	virtual void initialize();
	void construct_tcpheader(Packet * pkt, Connection *con, std::vector<FLAGS> flags, int payload_size);
	uint16_t set_flags(std::vector <FLAGS> fl, int length);
	std::vector<FLAGS> get_flags(short flags);
	void print_packet(Packet *pkt);
	void printPack(Packet* pck, std::vector<TCPAssignment::FLAGS> fl);
	virtual void finalize();
	virtual ~TCPAssignment();


    // Quick Packets
    inline void sendTCPSegment(Connection *con, std::vector<FLAGS> flags);
    inline void sendTCPSegment(Connection *con, char *payload, int payload_size, std::vector<FLAGS> flags);
    inline void sendRST(Connection* con);
    void disable_timers_until(Connection* con, uint64_t last);

    // Connection vector managment
	void print_kensock_conns(std::vector<Connection*> con_v);
    Conn_itr find_by_fd(uint fd, int pid);
    Conn_itr find_by_fd(uint fd, int pid, socket_state sock_state);
    Conn_itr find(Connection* k_con);
    Conn_itr find(Connection* k_con, socket_state sock_state);
    Conn_itr find_by_port_ip(Connection* k_con);
    Conn_itr find_by_port_ip(Connection* k_con, socket_state sock_state);
    Conn_itr find_by_lr_port_ip(Connection* k_con, socket_state sock_state);
    Conn_itr find_by_lr_port_ip(Connection* k_con);
    void do_write(Connection* itr);

protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}

#endif /* E_TCPASSIGNMENT_HPP_ */
