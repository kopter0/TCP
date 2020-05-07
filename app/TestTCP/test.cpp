#include <bits/stdc++.h>
using namespace std;
#define pv_itr std::vector<ReadBuffer::packet_info_rcvd>::iterator
#define pb std::vector<ReadBuffer::packet_info_rcvd>::push_back
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
                for (int i=0; i<length; i++){
                    buffer[i] = payload[i];
                }
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
            space_available = 51200;
            expected_seq_num = inorder_bytes = 0;
            inorder_packet_vector.clear();
            ooo_packet_vector.clear();
           
        }
        ~ReadBuffer(){
            inorder_packet_vector.clear();
            ooo_packet_vector.clear();
        }
        
        int set_expected_seq_num(uint32_t seq){
            this->expected_seq_num = seq;
            return (int) seq;
        }

        int insert_packet(uint32_t seq,uint32_t ack, uint32_t length, char *payload){
            //received_packets.push(packet_info_rcvd(seq, ack,length, payload));
        
            inorder_packet_vector.pb(packet_info_rcvd(seq, ack,length, payload));
            std::sort(inorder_packet_vector.begin(),inorder_packet_vector.end()); 
            return 0;
        }
        
        pv_itr begin(){
            return inorder_packet_vector.begin();
        }
        pv_itr end(){
            return inorder_packet_vector.end();
        }

        packet_info_rcvd* pop_packet(){
            if (inorder_packet_vector.empty()){
                return NULL;
            }
            else{
                packet_info_rcvd temp = inorder_packet_vector.front();
                inorder_packet_vector.erase(inorder_packet_vector.begin());
                return &temp;
            }

        }
};

int main(){
    char *pay1 = "assem";
    char *pay2 = "messa";
    char *pay3 = "asddd";
    ReadBuffer rd = ReadBuffer();

    std::cout<<rd.space_available<<std::endl;
    
    ReadBuffer::packet_info_rcvd packet1 = ReadBuffer::packet_info_rcvd(23, 13, 5, pay1);
    ReadBuffer::packet_info_rcvd packet2 = ReadBuffer::packet_info_rcvd(28, 13, 5, pay2);
    ReadBuffer::packet_info_rcvd packet3 = ReadBuffer::packet_info_rcvd(16, 13, 5, pay3);

    rd.insert_packet(23, 13, 5, pay1);
    rd.insert_packet(28, 13, 5, pay2);
    rd.insert_packet(16, 13, 5, pay3);
    
    rd.set_expected_seq_num(233);
    std::cout<<rd.expected_seq_num<<"\n";
    pv_itr itr = rd.begin();
    for (;itr !=rd.end() ;itr++){
        std::cout<<(itr->buffer)<<"\n";

    }
    //ReadBuffer::packet_info_rcvd temp = (rd.received_packets).pop();
    ReadBuffer::packet_info_rcvd temp;
    //= rd.received_packets.top()  ;
    
    return 0;
}


