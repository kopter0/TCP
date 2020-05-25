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
    #define OFFSET_REC_WNDW 48
    #define OFFSET_CHECKSUM 50
    #define OFFSET_PAYLOAD 54
    #define STANDARD_TIMEOUT 1e8
	
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
    #define MAXSEQNUM 4294967296
    #define pv_itr std::vector<ReadBuffer::packet_info_rcvd>::iterator
    #define pb_pp std::vector<ReadBuffer::packet_info_rcvd>::push_back

    class ReadBuffer{
        public:
        int space_available;
        uint32_t expected_seq_num;
        uint32_t inorder_bytes;
        struct packet_info_rcvd{
            uint32_t seq_num;
            uint32_t ack_num;
            uint32_t data_length;
            char* buffer;
        
            packet_info_rcvd(uint32_t seq,uint32_t ack, uint32_t length, char *payload ){
                seq_num = seq;
                ack_num = ack;
                data_length = length;
                buffer = (char*) malloc(length);
                memcpy(buffer, payload, length);
            }
            packet_info_rcvd(){};
            
            bool operator< (const packet_info_rcvd& rhs)
            {
                return this->seq_num < rhs.seq_num;
            }


        };

        struct compare_priority{
            bool operator()(packet_info_rcvd& lhs, packet_info_rcvd& rhs)
            {
                return lhs.seq_num > rhs.seq_num;
            }
        };

        // std::priority_queue <packet_info_rcvd, std::vector <packet_info_rcvd>,compare_priority > received_packets;
        std::vector <packet_info_rcvd> inorder_packet_vector;
        std::vector <packet_info_rcvd> ooo_packet_vector;
        
        

        ReadBuffer()
        {
            space_available = MAXBUFFERSIZE;
            expected_seq_num = inorder_bytes = 0;
            inorder_packet_vector.clear();
            ooo_packet_vector.clear();
           
        }
        ~ReadBuffer(){
            inorder_packet_vector.clear();
            ooo_packet_vector.clear();
        }
        
        uint32_t set_expected_seq_num(uint32_t seq){
            this->expected_seq_num = seq;
            return  seq;
        }

        void insert_inorder(uint32_t seq,uint32_t ack, uint32_t length, char *payload){
            inorder_packet_vector.pb_pp(packet_info_rcvd(seq, ack,length, payload));
            space_available -= length;
            expected_seq_num = (expected_seq_num + length)%MAXSEQNUM;
            inorder_bytes += length;
            
        }

        void insert_inorder(uint32_t seq,uint32_t ack, uint32_t length, char *payload, bool sort){
            inorder_packet_vector.pb_pp(packet_info_rcvd(seq, ack,length, payload));
            if (sort)
                std::sort(inorder_packet_vector.begin(), inorder_packet_vector.end());
            space_available -= length;
            // expected_seq_num = (expected_seq_num + length)%MAXSEQNUM;
            inorder_bytes += length;
            
        }
        int available_space(){return space_available;}
        uint32_t expected_seq(){return expected_seq_num;}

        void insert_ooo(uint32_t seq,uint32_t ack, uint32_t length, char *payload){
            ooo_packet_vector.pb_pp(packet_info_rcvd(seq, ack,length, payload));
            std::sort(ooo_packet_vector.begin(), ooo_packet_vector.end());
            space_available -= length;

        }
        
        void check_ooo_packets(){
            if (!ooo_packet_vector.empty()){
                packet_info_rcvd temp = ooo_packet_vector.front();
                while (expected_seq_num == temp.seq_num){
                    // std::cout << "Defrag" << std::endl;
                    inorder_packet_vector.pb_pp(temp);
                    ooo_packet_vector.erase(ooo_packet_vector.begin());
                    inorder_bytes += temp.data_length;
                    expected_seq_num = (expected_seq_num + temp.data_length)%MAXSEQNUM;
                    temp = ooo_packet_vector.front();
                }
            }
        }
        

        packet_info_rcvd* pop_packet_inorder(){
            if (inorder_packet_vector.empty()){
                return NULL;
            }
            else{

                packet_info_rcvd* temp = new packet_info_rcvd();
                *temp = inorder_packet_vector.front();
                inorder_packet_vector.erase(inorder_packet_vector.begin());
                space_available += temp->data_length;
                inorder_bytes -= temp->data_length;
                return temp;
            }

        }

        packet_info_rcvd* top_packet_inorder(){
            if (inorder_packet_vector.empty()){
                return NULL;
            }
            else{

                packet_info_rcvd* temp = new packet_info_rcvd();
                *temp = inorder_packet_vector.front();
                //inorder_packet_vector.erase(inorder_packet_vector.begin());
                return temp;
            }
        }

        int get(char *tobuffer, uint32_t to_get){
            uint32_t actual_get = std::min(to_get, inorder_bytes);
            uint32_t left_read = actual_get;
            while(left_read > 0 && actual_get > 0){
                auto temp = pop_packet_inorder();
                if (left_read >= temp -> data_length){
                    memcpy(tobuffer, temp -> buffer, temp -> data_length);
                    left_read -= temp -> data_length;
                    tobuffer += temp -> data_length;
                    // free(temp);
                }
                else{
                    // std::cout << "Not enough " << temp -> data_length << " " << left_read;
                    memcpy(tobuffer, temp -> buffer, left_read);
                    insert_inorder(temp -> seq_num, temp -> ack_num,(uint32_t)(temp -> data_length - left_read), temp -> buffer + left_read, true);
                    left_read = 0;
                    // free(temp);
                }
            }
            return actual_get;
        }

        uint32_t put(char *frombuffer, uint32_t cur_seq, uint32_t send_isn, uint32_t to_put){
            if (cur_seq == expected_seq_num){
                // std::cout << "As Expected" << std::endl;
                insert_inorder(cur_seq, send_isn, to_put, frombuffer);
                check_ooo_packets();
            }
            else if (cur_seq > expected_seq_num){
                // std::cout << "OOO" << std::endl;
                insert_ooo(cur_seq, send_isn, to_put, frombuffer);
            }
            else {
                // std::cout << "Prev" << std::endl;
            }                
            // std::cout << cur_seq << " " << expected_seq_num << std::endl;
            return expected_seq_num;
        }

};

    
    class MyBuffer {
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
        uint32_t send_isn, recv_isn, backlog, backlog_used;
        std::deque<std::tuple<UUID, int, void*>> *accept_queue;
        std::deque<Connection *> *estab_queue;
        socket_state state;
        uint64_t uuid, timer_uuid, read_uuid;
        std::map<uint, void*> timers_map;
        std::vector<uint> not_acked_pckts;
        int pid, max_allowed_packets;
        ushort recw, conw, byte_in_flight;
        in_port_t local_port, remote_port;
        bool bound, write_requested, read_requested, close_requested ,write_in_process;
        std::tuple<uint64_t, void*, int> write_request, read_request;
        MyBuffer *write_buffer; 
        ReadBuffer *read_buffer;
        

        Connection(){
            fd = local_ip = remote_ip = send_isn = recv_isn = local_port = remote_port = backlog = backlog_used = 0;
            recw = conw = 1;
            byte_in_flight = 0;
            uuid = timer_uuid = read_uuid = 0;
            max_allowed_packets = 1;
			pid = -1;
            state = CLOSED_SOCKET;  
            bound = write_requested = read_requested = write_in_process = false;
            read_buffer = new ReadBuffer();
            write_buffer = new MyBuffer();
            not_acked_pckts = std::vector<uint>();
            timers_map = std::map<uint, void*>();
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


    struct TimerCallbackFrame{
        enum TimerType{
            ACKTimeout,
            TimedWait,
            NONE
        };

        TimerType timer_type;
        void *con;
        void *payload;
        int payload_size;
        bool self_destruct;

        TimerCallbackFrame(){
            this -> timer_type = NONE;
            this -> self_destruct = false;
            this -> payload = NULL;
            this -> con = NULL;
        }
        TimerCallbackFrame(TimerType type, void *con, void* payload, int payload_size){
            this -> timer_type = type;
            this -> self_destruct = false;
            this -> payload = payload;
            this -> con = con;
            this -> payload_size = payload_size;
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

    //packet ReadBuffer management
    
    void insert_packet_readbuffer(uint32_t seq,uint32_t ack, uint32_t length, char *payload, ReadBuffer rb);


    // Quick Packets
    inline void sendTCPSegment(Connection *con, std::vector<FLAGS> flags);
    inline void sendTCPSegment(Connection *con, char *payload, int payload_size, std::vector<FLAGS> flags);
    inline void sendRST(Connection* con);
    void cancelTimers(Connection* con, uint64_t last);

    // JUST
    void performAccept(Connection *con, Connection* in_con);
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
