#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <regex.h>

// This is used for defining users input size
#define USER_INPUT_LEN  1024
#define MAX_SIZE_ARP_MESSAGES_DB  1024
#define MAX_ARP_MESSAGE_NAME 20
#define MAX_INTERFACE_NAME  20
#define ETHER_HEADER_LEN 14
#define ARP_HEADER_LEN 28
#define ARP_HARDWARE_TYPE  1   // (Ethernet)
#define ARP_PROTOCOL_TYPE  0x0800  // (IPv4)
#define ARP_HARDWARE_LEN   6
#define ARP_PROTOCOL_LEN   4
#define ARP_OPCODE         1    // ARP Request



typedef unsigned short t_2b;
typedef unsigned char  t_1b;
typedef struct std_arp_header arp_header_t;
typedef struct arp_message arp_message_t;
typedef struct arp_messages_db arp_messages_db_t;
typedef struct ifreq interface_name_t;
typedef struct sockaddr_ll  sockaddr_ll_t;
typedef struct sockaddr_in sockadd_in_t;



struct std_arp_header {
    //standard ARP‌ header
    t_2b hardware_type;
    t_2b protocol_type;
    t_1b hardware_len;
    t_1b protocol_len;
    t_2b opcode;

    t_1b sender_mac_addr[ARP_HARDWARE_LEN];
    t_1b sender_ip_addr[ARP_PROTOCOL_LEN];
    t_1b target_mac_addr[ARP_HARDWARE_LEN];
    t_1b target_ip_addr[ARP_PROTOCOL_LEN];
};

struct arp_message {
    /*
     * This struct is a simpler arp_message structur which is
     * similar to std_arp_header structure , but some fields like smac,tmac,sip,tip
     * are not arrays of ordered byte but they are just simple strings
     * */

    char *name;
    t_2b hardware_type;
    t_2b protocol_type;
    t_1b hardware_len;
    t_1b protocol_len;
    t_2b opcode;

    char *smac;
    char *sip;
    char *tmac;
    char *tip;


    arp_header_t arp_header;

};

struct arp_messages_db {
    /*
     * This struct is a databse for karpg .
     * it contains all the message that have created till now.
     * */
    int current_messages;
    arp_message_t message_arrays[MAX_SIZE_ARP_MESSAGES_DB];
};



// Functions prototypes
//-----------------------------------------------------
void strip_space(char * str , char * dst);
void printe(char * error_message);
void print_mac_address_from_byte_order(char *interface_name , unsigned char * src_mac);
void arp_create_with_mini_parser(arp_message_t  *arp_message , char * create_command);
int is_message_exist_by_name(arp_messages_db_t *karp_message_db ,char *name);
void print_message_info(arp_messages_db_t karp_message_db,char *name);
void arp_message_initialize(arp_message_t *arp_message);
void mac_str_to_byte(const char * mac_addr,unsigned char *dst_mac_byte);
int hex2int(char ch);

//------------------------------------------------------



int main() {

    // defining some regex for program
    regex_t regex_send;
    regex_t regex_create;
    regex_t regex_show;
    regex_t regex_set_interface;
    regex_t regex_show_interface;

    // this regex matches create functio >> ()
    if (regcomp(&regex_create,
                "([a-zA-Z_][a-zA-Z_0-9]*)\\s*=\\s*\\(\\s*(opcode\\s*=\\s*[0-9]+\\s*|\\s*htype\\s*=\\s*[0-9]+\\s*|\\s*ptype\\s*=\\s*[0-9]+|hlen\\s*=\\s*[0-9]+\\s*|\\s*plen\\s*=\\s*[0-9]+\\s*|\\s*smac\\s*=\\s*[0-9a-f]{12}\\s*|\\s*tmac\\s*=\\s*[0-9a-f]{12}\\s*|\\s*(sip)\\s*=\\s*((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\\s*)|\\s*(tip)\\s*=\\s*((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|,)*\\)",
                REG_EXTENDED) != 0) {
        printe("regex_create compilation error");
        exit(2);
    }

    // this regex matches send function >> send
    if (regcomp(&regex_send,
                "send",REG_EXTENDED) != 0) {
        printe("regex_send compilation error");
        exit(2);
    }

    // this regex matches show message function
    if (regcomp(&regex_show, "show\\s*([a-zA-Z_]+([0-9]|[a-zA-Z_])*)", REG_EXTENDED) != 0) {
        printe("regex_show compilation error");
        exit(2);
    }

    // this regex matches show interface function
    if (regcomp(&regex_show_interface, "show\\s*(interface| int)\\s*", REG_EXTENDED) != 0) {
        printe("regex_show_interface compilation error");
        exit(2);
    }
    // this regex matches set interface function
    if (regcomp(&regex_set_interface, "setint\\s*[a-zA-Z0-9]+", REG_EXTENDED) != 0){
        printe("regex_set_interface compilation error");
        exit(2);
    }

    int raw_socket;
    interface_name_t intface;

    unsigned char *src_mac = (unsigned char *)malloc(ARP_HARDWARE_LEN);
    unsigned char *dst_mac = (unsigned char *)malloc(ARP_HARDWARE_LEN);


    bzero(dst_mac,ARP_HARDWARE_LEN);
    bzero(src_mac,ARP_HARDWARE_LEN); //TODO


    char *src_ip = (char *)malloc(ARP_PROTOCOL_LEN);
    char *dst_ip = (char *)malloc(ARP_PROTOCOL_LEN);
    bzero(src_ip,ARP_PROTOCOL_LEN);
    bzero(dst_ip,ARP_PROTOCOL_LEN);


    unsigned char *ether_frame = (unsigned char *)malloc(IP_MAXPACKET);
    bzero(ether_frame,IP_MAXPACKET);


    struct addrinfo hints, *res;
    sockaddr_ll_t device ;
    sockadd_in_t * ipv4;
    arp_header_t arp_header;



    char *user_command =(char *)malloc(USER_INPUT_LEN);
    char *user_command_ns= (char *)malloc(USER_INPUT_LEN);

    bzero(user_command,USER_INPUT_LEN);
    bzero(user_command_ns,USER_INPUT_LEN);





    //-----------------------‌‌ Program Start-----
    arp_messages_db_t karp_message_db;
    karp_message_db.current_messages=0; // initial to 0
    char *interface_name=NULL;


    // greeting
        printf("\tWelcome to karpg ( aka kiarash arp generator )\n\n");
    //
    //------------------------------------------



    while(1) {
        printf(">> ");
        fgets(user_command, USER_INPUT_LEN, stdin);
        strip_space(user_command, user_command_ns);


        if (strncmp(user_command_ns, "quit", 4) == 0 || strncmp(user_command_ns, "exit", 4) == 0) {
            printf("Bye!!\n");
            exit(0);
        }

        else if (regexec(&regex_set_interface, user_command_ns, 0, NULL, 0) ==0){

            if (interface_name==NULL)
                interface_name = (char *) malloc(MAX_INTERFACE_NAME);

                bzero(interface_name, MAX_INTERFACE_NAME);

                char *end_of_command_ptr = user_command_ns + strlen(user_command_ns) - 1;
                while (*end_of_command_ptr != 32 && *end_of_command_ptr != 10 && *end_of_command_ptr != 9)
                    end_of_command_ptr--;
                end_of_command_ptr++;


                int counter_helper = 0;
                while (*end_of_command_ptr) {
                    *interface_name = *end_of_command_ptr;
                    interface_name++;
                    end_of_command_ptr++;
                    counter_helper++;
                }
                interface_name -= counter_helper;



            printf("interface {%s} was set as default interface\n",interface_name); //TODO

        }

        else if (regexec(&regex_show_interface, user_command_ns, 0, NULL, 0) ==0){
            if (interface_name)
                printf("Interface = %s\n",interface_name);
            else
                printf("Interface = Not set\n");

        }

        else if (regexec(&regex_send, user_command_ns, 0, NULL, 0) == 0) {


            char *smac=( char *)malloc(13);
            char *tmac=( char *)malloc(13);

            bzero(&intface,sizeof(intface));
            bzero(&device,sizeof(device));
            bzero(smac,13);
            bzero(tmac,18);


            // check whether interface set before
            if(interface_name==NULL){
                printe("No interface has been set ");
                continue;
            }


            char * message_name=(char *)malloc(MAX_INTERFACE_NAME); // from send
            bzero(message_name,MAX_INTERFACE_NAME);
            printf("message: ");
            scanf("%s",message_name);

            int search_result=is_message_exist_by_name(&karp_message_db,message_name);
            if(search_result==-1)
            {
                printe("Message %s does not exit");
                continue;
            }


            // getting ethernet header information from user

            printf("smac :[d for default] ");
            scanf("%s",smac);


            printf("tmac :[d for default] ");
            scanf("%s",tmac);


            // getting send repetition from user
            printf("count :[d for default] ");
            char repetition[13];
            scanf("%s",repetition);



            if ((raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
                printe("Unable to create raw socket , check permission");
                continue;
            }



            // clear intface structure
            memset(&intface, 0, sizeof(intface));

            strncpy(intface.ifr_name, interface_name, MAX_INTERFACE_NAME - 1);

            if (ioctl(raw_socket, SIOCGIFHWADDR, &intface) < 0) {
                printe("Can't get mac address "); //TODO‌ add interface name
                continue;
            }
            close(raw_socket);




            // Copy source MAC address.
            // setting src_mac , if user has specified already
            // we use that , else we use mac address of specified NIC
            if(strncmp(smac,"d",1)==0)
                memcpy(src_mac, intface.ifr_hwaddr.sa_data, 6 * sizeof(t_1b));
            else
                mac_str_to_byte(smac,src_mac);



            // clear device
            memset (&device, 0, sizeof (device));

            // we use if_nametoindex to get interface index by name
            if ((device.sll_ifindex = if_nametoindex(interface_name)) == 0) {
                printe("Can't obtain interface index ");
                continue;
            }


            // setting dst_mac , if user has specified already
            // we use that , else we use 0xffffffffffff
            if(strncmp(tmac,"d",1)==0)
                memset (dst_mac, 0xff, 6 * sizeof (uint8_t));
            else
                mac_str_to_byte(tmac,dst_mac);



            // Source IPv4 address:  you need to fill this out

            strcpy(src_ip, karp_message_db.message_arrays[search_result].sip);


            // Destination IPv4 address:  you need to fill this out
            strcpy(dst_ip, karp_message_db.message_arrays[search_result].tip);


            // Fill out hints for getaddrinfo().
            memset(&hints, 0, sizeof(struct addrinfo));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = hints.ai_flags | AI_CANONNAME;

            int status;
            if ((status = inet_pton(AF_INET, src_ip, &arp_header.sender_ip_addr)) != 1) {
                fprintf(stderr, "inet_pton() failed for source IP address.\nError message: %s", strerror(status));
                continue;
            }


            // Resolve target using getaddrinfo().
            if ((status = getaddrinfo(dst_ip, NULL, &hints, &res)) != 0) {
                fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(status));
                continue;
            }


            ipv4 = (struct sockaddr_in *) res->ai_addr;
            memcpy(&arp_header.target_ip_addr, &ipv4->sin_addr, 4 * sizeof(t_1b));
            freeaddrinfo(res);

            // Fill out sockaddr_ll.
            device.sll_family = AF_PACKET;
            memcpy(device.sll_addr, src_mac, 6 * sizeof(t_1b));
            device.sll_halen = 6;




            // filling arp header fields with the message information collected before
            arp_header.hardware_type = htons(karp_message_db.message_arrays[search_result].hardware_type);
            arp_header.protocol_type = htons(karp_message_db.message_arrays[search_result].protocol_type);
            arp_header.hardware_len = (karp_message_db.message_arrays[search_result].hardware_len);
            arp_header.protocol_len = (karp_message_db.message_arrays[search_result].protocol_len);
            arp_header.opcode = htons(karp_message_db.message_arrays[search_result].opcode);


            // setting mac address fields in arp header
            memcpy (&arp_header.sender_mac_addr, src_mac, 6 * sizeof (t_1b));
            memset (&arp_header.target_mac_addr, 0, 6 * sizeof (t_1b));



            int frame_length = 6 + 6 + 2 + ARP_HEADER_LEN;


            // Destination and Source MAC addresses of Ethernet frame
            memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
            memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

            // Next is ethernet type code (ETH_P_ARP for ARP).
            // http://www.iana.org/assignments/ethernet-numbers
            ether_frame[12] = ETH_P_ARP / 256;
            ether_frame[13] = ETH_P_ARP % 256;


            // ARP header
            memcpy(ether_frame + ETHER_HEADER_LEN, &arp_header, ARP_HEADER_LEN * sizeof(t_1b));

            // Submit request for a raw socket descriptor.
            if ((raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
                perror("socket() failed ");
                continue;
            }

            int bytes;
            // Send ethernet frame to socket.

            int loop_cnt=1;
            if(strcmp(repetition,"d")!=0)
                loop_cnt=atoi(repetition);


            for (int i = 0; i < loop_cnt; i++) {

                if((bytes = sendto(raw_socket, ether_frame, frame_length, 0, (struct sockaddr *) &device,sizeof(device))) <= 0) {
                    printe("sending arp %d unsuccessful"); //TODO‌ format
                    continue;
                }

            }



            // Close socket descriptor.
            close(raw_socket);

            free(src_mac);
            free(dst_mac);
            free(ether_frame);
            free(dst_ip);
            free(src_ip);

        }

        else if(regexec(&regex_create, user_command_ns, 0, NULL, 0) == 0) {


            // create new arp_message
            arp_message_t new_arp_message;


            arp_message_initialize(&new_arp_message);


            // fill arp message with information given from cli
            arp_create_with_mini_parser(&new_arp_message, user_command_ns);

            int search_result;
            search_result = is_message_exist_by_name(&karp_message_db, new_arp_message.name);
            if (search_result != -1) {
                // this name is already in the database , so you can
                // overwrite the previous message
                karp_message_db.message_arrays[search_result] = new_arp_message;
            } else {
                // put new message as new entry in the database
                karp_message_db.message_arrays[karp_message_db.current_messages] = new_arp_message;

                // add one to total number of messages
                karp_message_db.current_messages += 1;
            }

        }

        else if(regexec(&regex_show, user_command_ns, 0, NULL, 0) == 0){

            char *message_name=user_command_ns+4;

            while(*message_name==32 || *message_name==9 || *message_name==10)
                message_name++;

            print_message_info(karp_message_db,message_name);

        }

        else if (strlen(user_command_ns)==0)
                continue;
        else{
            printe("command is ambiguous");
        }
    }


}


void arp_message_initialize(arp_message_t *arp_message){

    /*
     * This function is used when a new ARP‌ message is created.
     * It will fill some fields by some default values defined by
     * karpg program
     * */

    arp_message->opcode=ARP_OPCODE;

    arp_message->sip=(char *)malloc(17);
    arp_message->tip=(char *)malloc(17);
    bzero(arp_message->sip,17);
    bzero(arp_message->tip,17);

    strcpy(arp_message->sip,"0.0.0.0");
    strcpy(arp_message->tip,"255.255.255.255");

    arp_message->protocol_type=ARP_PROTOCOL_TYPE;
    arp_message->hardware_len=ARP_HARDWARE_LEN;
    arp_message->protocol_len=ARP_PROTOCOL_LEN;
    arp_message->hardware_type=ARP_HARDWARE_TYPE;


    // setting default mac address for source mac
    arp_message->smac=(char *)malloc(18);
    bzero(arp_message->smac,18);
    strcpy(arp_message->smac,"000000000000");

    // setting default mac address for destination mac
    arp_message->tmac=(char *)malloc(18);
    bzero(arp_message->tmac,18);
    strcpy(arp_message->tmac,"ffffffffffff");



}

void print_message_info(arp_messages_db_t karp_message_db,  char *name) {
    /*
     * This function is useful when we issue ( show MESSSAGE_NAME).
     * It will prints all its fields value on screen
     */


    for (int i = 0; i < karp_message_db.current_messages; i++) {
        if (strcmp(karp_message_db.message_arrays[i].name, name) == 0) {

            printf("(opcode: %d , heln: %d , plen: %d, htype: %d,\nptype: %d, smac: %s, tmac: %s, sip: %s, tip:%s)\n",
                   karp_message_db.message_arrays[i].opcode,
                   karp_message_db.message_arrays[i].hardware_len, karp_message_db.message_arrays[i].protocol_len,
                   karp_message_db.message_arrays[i].hardware_type,
                   karp_message_db.message_arrays[i].protocol_type, karp_message_db.message_arrays[i].smac,
                   karp_message_db.message_arrays[i].tmac, karp_message_db.message_arrays[i].sip,
                   karp_message_db.message_arrays[i].tip);
        }
    }
}

int is_message_exist_by_name(arp_messages_db_t *karp_message_db ,char *name){
    /*
     * this function checks whether any message with name (name) does exist in
     * our database or not.if yes , returns its index , else , -1
     */

    for (int i=0;i<karp_message_db->current_messages;i++){
        if(strncmp(karp_message_db->message_arrays[i].name,name,strlen(name))==0){
            return i;
        }
    }
    return -1;


}

void arp_create_with_mini_parser(arp_message_t  *arp_message , char * create_command){
    /*
     * This function is a mini parser designed to parse create function <()> which is the most
     * important function in this program.
     * it will parse the command and values alll fields of an ARP message.
     * fields are ( opcode , htype ,hlen,plen,ptype,sip,tip,smac,tmac)
     *
     * */


    arp_message->name= (char *)malloc(MAX_ARP_MESSAGE_NAME);
    bzero(arp_message->name,20);

    // this counter is helpful when we want to bring some pointers to their initial place
    // pointers line name , sip , tip . the reason is we are not sure how much bytes
    // each of these fields would be when they are entered in create function of arp message
    unsigned char counter_helper=0;


    while(*create_command && *create_command!=32 && *create_command!=(int)'='){
        *arp_message->name=*create_command;
        counter_helper++;
        create_command++;
        arp_message->name++;
    }
    while(*create_command!=(int) '(') // set string pointing to‌ >>(  ...  )
        create_command++;


    arp_message->name-=counter_helper;


    char *field=(char *)malloc(6);
    bzero(field,6);

    while(*create_command){


        if(*create_command==(int)'o')
            strcpy(field,"opcode");
        else if(*create_command == (int) 'h' && *(create_command+1) == (int)'l')
            strcpy(field,"hlen");
        else if(*create_command == (int) 'h' && *(create_command+1) == (int)'t')
            strcpy(field,"htype");

        else if(*create_command == (int) 'p' && *(create_command+1) == (int)'l')
            strcpy(field,"plen");
        else if(*create_command == (int) 'p' && *(create_command+1) == (int)'t')
            strcpy(field,"ptype");

        else if(*create_command == (int) 's' && *(create_command+1) == (int)'i')
            strcpy(field,"sip");
        else if(*create_command == (int) 's' && *(create_command+1) == (int)'m')
            strcpy(field,"smac");

        else if(*create_command == (int) 't' && *(create_command+1) == (int)'i')
            strcpy(field,"tip");

        else if(*create_command == (int) 't' && *(create_command+1) == (int)'m')
            strcpy(field,"tmac");

        else if(*create_command == (int) '=') {

            if (strcmp(field, "opcode") == 0)
                arp_message->opcode = atoi(create_command + 1);
            else if (strcmp(field, "hlen") == 0)
                arp_message->hardware_len = atoi(create_command + 1);
            else if (strcmp(field, "plen") == 0)
                arp_message->protocol_len = atoi(create_command + 1);
            else if (strcmp(field, "htype") == 0)
                arp_message->hardware_type = atoi(create_command + 1);
            else if (strcmp(field, "ptype") == 0)
                arp_message->protocol_type = atoi(create_command + 1);
            else if (strcmp(field, "smac") == 0) {
                arp_message->smac=(char *)malloc(18);
                bzero(arp_message->smac,18);
                *(arp_message->smac+2)=(int)':';
                *(arp_message->smac+5)=(int)':';
                *(arp_message->smac+8)=(int)':';
                *(arp_message->smac+11)=(int)':';
                *(arp_message->smac+14)=(int)':';
                *(arp_message->smac)=*(create_command + 1 );
                *(arp_message->smac+1)=*(create_command + 2 );
                *(arp_message->smac+3)=*(create_command + 3 );
                *(arp_message->smac+4)=*(create_command + 4 );
                *(arp_message->smac+6)=*(create_command + 5 );
                *(arp_message->smac+7)=*(create_command + 6 );
                *(arp_message->smac+9)=*(create_command + 7 );
                *(arp_message->smac+10)=*(create_command + 8 );
                *(arp_message->smac+12)=*(create_command + 9 );
                *(arp_message->smac+13)=*(create_command + 10 );
                *(arp_message->smac+15)=*(create_command + 11 );
                *(arp_message->smac+16)=*(create_command + 12 );




            }

            else if (strcmp(field, "tmac") == 0) {
                arp_message->tmac=(char *)malloc(18);
                bzero(arp_message->tmac,18);
                *(arp_message->tmac+2)=(int)':';
                *(arp_message->tmac+5)=(int)':';
                *(arp_message->tmac+8)=(int)':';
                *(arp_message->tmac+11)=(int)':';
                *(arp_message->tmac+14)=(int)':';
                *(arp_message->tmac)=*(create_command + 1 );
                *(arp_message->tmac+1)=*(create_command + 2 );
                *(arp_message->tmac+3)=*(create_command + 3 );
                *(arp_message->tmac+4)=*(create_command + 4 );
                *(arp_message->tmac+6)=*(create_command + 5 );
                *(arp_message->tmac+7)=*(create_command + 6 );
                *(arp_message->tmac+9)=*(create_command + 7 );
                *(arp_message->tmac+10)=*(create_command + 8 );
                *(arp_message->tmac+12)=*(create_command + 9 );
                *(arp_message->tmac+13)=*(create_command + 10 );
                *(arp_message->tmac+15)=*(create_command + 11 );
                *(arp_message->tmac+16)=*(create_command + 12 );

            }

            else if(strcmp(field,"sip")==0) {

                arp_message->sip=(char *)malloc(16);
                bzero(arp_message->sip,16);
                // set string next step
                create_command++;
                counter_helper=0;
                while(*create_command!=(int)',' && *create_command!=(int)')') {
                    *arp_message->sip = *create_command;
                    arp_message->sip++;
                    create_command++;
                    counter_helper++;
                }
                // bring sip pointer to its first place
                arp_message->sip-=counter_helper;

            }
            else if(strcmp(field,"tip")==0){
                arp_message->tip=(char *)malloc(16);
                bzero(arp_message->tip,16);
                // set string next step
                create_command++;
                counter_helper=0;
                while(*create_command!=(int)',' && *create_command!=(int)')')
                {
                    *arp_message->tip=*create_command;
                    arp_message->tip++;
                    create_command++;
                    counter_helper++;
                }

                // bring tip pointer to its first place
                arp_message->tip-=counter_helper;


            }

        }
        create_command++;

    }


}

int hex2int(char ch)
{
    /*
     * This function converts hexadecimal numbers to their corresponding integer value
     * */
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    return -1;
}

void mac_str_to_byte(const char * mac_addr,unsigned char *dst_mac_byte){
    /*
     * This function converts destination mac address represented in
     * ascii characters to byte order representation ready to fill Ethernet and ARP fields
     * */
    int op1 , op2;
    unsigned char sum=0;


    for(int i=0;i<6;i+=1){
        op1=hex2int(*(mac_addr+2*i));
        op2=hex2int(*(mac_addr+2*i+1));
        sum=op1*16+op2;
        memcpy(dst_mac_byte+i,&sum,1);
    }

}

void print_mac_address_from_byte_order(char *interface_name , unsigned  char * src_mac){

    /*
     * This function will print mac address represented in byte order as
     * ascii characters(human readble xx:xx:xx:xx:xx:xx)
     *
     */

    for (int i=0; i<5; i++) {
        printf ("%02x:", src_mac[i]);
    }
    printf ("%02x\n", src_mac[5]);

}

void printe(char * error_message){
    /*
     * This function will print error message with red color
     * */
    printf("\033[1;31m");
    printf("ERR‌: %s\n",error_message);
    printf("\033[0m");
}

void strip_space(char * str , char * dst){
    /*
     * This function is designed to strip spaces around any input‌(usuall user command)
     *
     * */


    char *beg_no_space=str;
     char  *end_no_spcae=str;

    while(*end_no_spcae)
        end_no_spcae++;
    end_no_spcae--;

    while(*beg_no_space==32 || *beg_no_space==10 || *beg_no_space==9 )
        beg_no_space++;

    while(*end_no_spcae==32 || *end_no_spcae==10 || *beg_no_space==9)
        end_no_spcae--;

    while(beg_no_space<=end_no_spcae){

        *dst=*beg_no_space;
        beg_no_space++;
        dst++;
    }
    *dst=0;


}




