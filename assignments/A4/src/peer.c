#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"
#include "./sha256.h"


// Global variables to be used by both the server and client side of the peer.
// Some of these are not currently used but should be considered STRONG hints
PeerAddress_t *my_address;

pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;
PeerAddress_t** network = NULL;
uint32_t peer_count = 0;

pthread_mutex_t retrieving_mutex = PTHREAD_MUTEX_INITIALIZER;
FilePath_t** retrieving_files = NULL;
uint32_t file_count = 0;



/*
 * Gets a sha256 hash of specified data, sourcedata. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_data_sha(const char* sourcedata, hashdata_t hash, uint32_t data_size, 
    int hash_size)
{
  SHA256_CTX shactx;
  unsigned char shabuffer[hash_size];
  sha256_init(&shactx);
  sha256_update(&shactx, sourcedata, data_size);
  sha256_final(&shactx, shabuffer);

  for (int i=0; i<hash_size; i++)
  {
    hash[i] = shabuffer[i];
  }
}



/*
 * Gets a sha256 hash of specified data file, sourcefile. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_file_sha(const char* sourcefile, hashdata_t hash, int size)
{
    int casc_file_size;

    FILE* fp = fopen(sourcefile, "rb");
    if (fp == 0)
    {
        printf("Failed to open source: %s\n", sourcefile);
        return;
    }

    fseek(fp, 0L, SEEK_END);
    casc_file_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    char buffer[casc_file_size];
    fread(buffer, casc_file_size, 1, fp);
    fclose(fp);

    get_data_sha(buffer, hash, casc_file_size, size);
}



/*
 * A simple min function, which apparently C doesn't have as standard
 */
uint32_t min(int a, int b)
{
    if (a < b) 
    {
        return a;
    }
    return b;
}



/*
 * Select a peer from the network at random, without picking the peer defined
 * in my_address
 */
void get_random_peer(PeerAddress_t* peer_address)
{ 
    PeerAddress_t** potential_peers = malloc(sizeof(PeerAddress_t*));
    uint32_t potential_count = 0; 
    for (uint32_t i=0; i<peer_count; i++)
    {
        if (strcmp(network[i]->ip, my_address->ip) != 0 
                || strcmp(network[i]->port, my_address->port) != 0 )
        {
            potential_peers = realloc(potential_peers, 
                (potential_count+1) * sizeof(PeerAddress_t*));
            potential_peers[potential_count] = network[i];
            potential_count++;
        }
    }

    if (potential_count == 0)
    {
        printf("No peers to connect to. You probably have not implemented "
            "registering with the network yet.\n");
    }

    uint32_t random_peer_index = rand() % potential_count;

    memcpy(peer_address->ip, potential_peers[random_peer_index]->ip, IP_LEN);
    memcpy(peer_address->port, potential_peers[random_peer_index]->port, 
        PORT_LEN);

    free(potential_peers);

    printf("Selected random peer: %s:%s\n", 
        peer_address->ip, peer_address->port);
}



/*
 * Send a request message to another peer on the network. Unless this is 
 * specifically an 'inform' message as described in the assignment handout, a 
 * reply will always be expected.
 */
void send_message(PeerAddress_t peer_address, int command, char* request_body)
{
    fprintf(stdout, "Connecting to server at %s:%s to run command %d (%s)\n", 
        peer_address.ip, peer_address.port, command, request_body);

    compsys_helper_state_t state;
    char msg_buf[MAX_MSG_LEN];
    FILE* fp;

    // Setup the eventual output file path. This is being done early so if 
    // something does go wrong at this stage we can avoid all that pesky 
    // networking
    char output_file_path[strlen(request_body)+1];
    if (command == COMMAND_RETREIVE)
    {     
        strcpy(output_file_path, request_body);

        if (access(output_file_path, F_OK ) != 0 ) 
        {
            fp = fopen(output_file_path, "a");
            fclose(fp);
        }
    }

    // Setup connection
    int peer_socket = compsys_helper_open_clientfd(peer_address.ip, peer_address.port);
    compsys_helper_readinitb(&state, peer_socket);

    // Construct a request message and send it to the peer
    struct RequestHeader request_header;
    strncpy(request_header.ip, my_address->ip, IP_LEN);
    request_header.port = htonl(atoi(my_address->port));
    request_header.command = htonl(command);
    request_header.length = htonl(strlen(request_body));

    memcpy(msg_buf, &request_header, REQUEST_HEADER_LEN);
    memcpy(msg_buf+REQUEST_HEADER_LEN, request_body, strlen(request_body));

    compsys_helper_writen(peer_socket, msg_buf, REQUEST_HEADER_LEN+strlen(request_body));

    // We don't expect replies to inform messages so we're done here
    if (command == COMMAND_INFORM)
    {
        return;
    }

    // Read a reply
    compsys_helper_readnb(&state, msg_buf, REPLY_HEADER_LEN);

    // Extract the reply header 
    char reply_header[REPLY_HEADER_LEN];
    memcpy(reply_header, msg_buf, REPLY_HEADER_LEN);

    uint32_t reply_length = ntohl(*(uint32_t*)&reply_header[0]);
    uint32_t reply_status = ntohl(*(uint32_t*)&reply_header[4]);
    uint32_t this_block = ntohl(*(uint32_t*)&reply_header[8]);
    uint32_t block_count = ntohl(*(uint32_t*)&reply_header[12]);
    hashdata_t block_hash;
    memcpy(block_hash, &reply_header[16], SHA256_HASH_SIZE);
    hashdata_t total_hash;
    memcpy(total_hash, &reply_header[48], SHA256_HASH_SIZE);

    // Determine how many blocks we are about to recieve
    hashdata_t ref_hash;
    memcpy(ref_hash, &total_hash, SHA256_HASH_SIZE);
    uint32_t ref_count = block_count;

    // Loop until all blocks have been recieved
    for (uint32_t b=0; b<ref_count; b++)
    {
        // Don't need to re-read the first block
        if (b > 0)
        {
            // Read the response
            compsys_helper_readnb(&state, msg_buf, REPLY_HEADER_LEN);

            // Read header
            memcpy(reply_header, msg_buf, REPLY_HEADER_LEN);

            // Parse the attributes
            reply_length = ntohl(*(uint32_t*)&reply_header[0]);
            reply_status = ntohl(*(uint32_t*)&reply_header[4]);
            this_block = ntohl(*(uint32_t*)&reply_header[8]);
            block_count = ntohl(*(uint32_t*)&reply_header[12]);

            memcpy(block_hash, &reply_header[16], SHA256_HASH_SIZE);
            memcpy(total_hash, &reply_header[48], SHA256_HASH_SIZE);

            // Check we're getting consistent results
            if (ref_count != block_count)
            {
                fprintf(stdout, 
                    "Got inconsistent block counts between blocks\n");
                close(peer_socket);
                return;
            }

            for (int i=0; i<SHA256_HASH_SIZE; i++)
            {
                if (ref_hash[i] != total_hash[i])
                {
                    fprintf(stdout, 
                        "Got inconsistent total hashes between blocks\n");
                    close(peer_socket);
                    return;
                }
            }
        }

        // Check response status
        if (reply_status != STATUS_OK)
        {
            if (command == COMMAND_REGISTER && reply_status == STATUS_PEER_EXISTS)
            {
                printf("Peer already exists\n");
            }
            else
            {
                printf("Got unexpected status %d\n", reply_status);
                close(peer_socket);
                return;
            }
        }

        // Read the payload
        char payload[reply_length+1];
        compsys_helper_readnb(&state, msg_buf, reply_length);
        memcpy(payload, msg_buf, reply_length);
        payload[reply_length] = '\0';
        
        // Check the hash of the data is as expected
        hashdata_t payload_hash;
        get_data_sha(payload, payload_hash, reply_length, SHA256_HASH_SIZE);

        for (int i=0; i<SHA256_HASH_SIZE; i++)
        {
            if (payload_hash[i] != block_hash[i])
            {
                fprintf(stdout, "Payload hash does not match specified\n");
                close(peer_socket);
                return;
            }
        }

        // If we're trying to get a file, actually write that file
        if (command == COMMAND_RETREIVE)
        {
            // Check we can access the output file
            fp = fopen(output_file_path, "r+b");
            if (fp == 0)
            {
                printf("Failed to open destination: %s\n", output_file_path);
                close(peer_socket);
            }

            uint32_t offset = this_block * (MAX_MSG_LEN-REPLY_HEADER_LEN);
            fprintf(stdout, "Block num: %d/%d (offset: %d)\n", this_block+1, 
                block_count, offset);
            fprintf(stdout, "Writing from %d to %d\n", offset, 
                offset+reply_length);

            // Write data to the output file, at the appropriate place
            fseek(fp, offset, SEEK_SET);
            fputs(payload, fp);
            fclose(fp);
        }
    }

    // Confirm that our file is indeed correct
    if (command == COMMAND_RETREIVE)
    {
        fprintf(stdout, "Got data and wrote to %s\n", output_file_path);

        // Finally, check that the hash of all the data is as expected
        hashdata_t file_hash;
        get_file_sha(output_file_path, file_hash, SHA256_HASH_SIZE);

        for (int i=0; i<SHA256_HASH_SIZE; i++)
        {
            if (file_hash[i] != total_hash[i])
            {
                fprintf(stdout, "File hash does not match specified for %s\n", 
                    output_file_path);
                close(peer_socket);
                return;
            }
        }
    }

    // If we are registering with the network we should note the complete 
    // network reply
    char* reply_body = malloc(reply_length + 1);
    memset(reply_body, 0, reply_length + 1);
    memcpy(reply_body, msg_buf, reply_length);

    if (reply_status == STATUS_OK)
    {
        if (command == COMMAND_REGISTER)
        {
            // Your code here. This code has been added as a guide, but feel 
            // free to add more, or work in other parts of the code
        }
    } 
    else
    {
        printf("Got response code: %d, %s\n", reply_status, reply_body);
    }
    free(reply_body);
    close(peer_socket);
}



/*
 * Function to act as thread for all required client interactions. This thread 
 * will be run concurrently with the server_thread but is finite in nature.
 * 
 * This is just to register with a network, then download two files from a 
 * random peer on that network. As in A3, you are allowed to use a more 
 * user-friendly setup with user interaction for what files to retrieve if 
 * preferred, this is merely presented as a convienient setup for meeting the 
 * assignment tasks
 */ 
void* client_thread(void* thread_args)
{
    struct PeerAddress *peer_address = thread_args;

    // Register the given user
    send_message(*peer_address, COMMAND_REGISTER, "\0");

    // Update peer_address with random peer from network
    get_random_peer(peer_address);

    // Retrieve the smaller file, that doesn't not require support for blocks
    send_message(*peer_address, COMMAND_RETREIVE, "tiny.txt");

    // Update peer_address with random peer from network
    get_random_peer(peer_address);

    // Retrieve the larger file, that requires support for blocked messages
    send_message(*peer_address, COMMAND_RETREIVE, "hamlet.txt");

    return NULL;
}



/*
 * Handle any 'register' type requests, as defined in the asignment text. This
 * should always generate a response.
 */
void handle_register(int connfd, char* client_ip, int client_port_int)
{
    // Your code here. This function has been added as a guide, but feel free 
    // to add more, or work in other parts of the code
    printf("\nNOW WE ENTER 'handler_register'!\n");

    // First we save the values from the input to save later
    char newpeer[IP_LEN + 4];
    memset(newpeer, 0, IP_LEN + 4);
    memcpy(newpeer, client_ip, IP_LEN);
    printf("hey hey\n");
    memcpy(newpeer + IP_LEN, &client_port_int, 4);
    printf("new_peer contents: %s\n", newpeer);


    // We start off by initializing
    char* client_port[PORT_LEN];
    printf("1\n");
    memset(client_port, 0, PORT_LEN * sizeof(char*));
    printf("2\n");
    snprintf(client_port, PORT_LEN, "%d", client_port_int);
    printf("converted port: %s\n", client_port);
    printf("Finish initialize 1\n");

    char rhbuffer[REPLY_HEADER_LEN];
    memset(&rhbuffer, 0, REPLY_HEADER_LEN);
    char rbuffer[IP_LEN + 4];
    memset(&rbuffer, 0, IP_LEN + 4);

    int response_body = htonl(0);
    int status = htonl(0);
    int block_number = htonl(0);
    int block_count = htonl(0);

    hashdata_t block_hash[SHA256_HASH_SIZE];
    memset(block_hash, 0, SHA256_HASH_SIZE * sizeof(hashdata_t));
    hashdata_t total_hash[SHA256_HASH_SIZE];
    memset(total_hash, 0, SHA256_HASH_SIZE * sizeof(hashdata_t));
    
    char payload[peer_count][IP_LEN + PORT_LEN];
    memset(payload, 0, peer_count * (IP_LEN + PORT_LEN));
    char totalpayload[(IP_LEN + PORT_LEN) * peer_count];
    memset(totalpayload, 0, (IP_LEN + PORT_LEN) * peer_count);
    printf("Finish initialize 2\n");


    for (int i = 0; i < peer_count; i++) {
        if (network[i]->ip == client_ip && network[i]->port == client_port) {
            char errbuffer[REPLY_HEADER_LEN + 74];
            memset(errbuffer, 0, REPLY_HEADER_LEN + 74);
            char errmessage[74] = "Could not register a peer as they are already registerd with the network.";
            response_body = htonl(74);
            status = htonl(2);
            block_count = htonl(1);
            get_data_sha(&errmessage, total_hash, 74, SHA256_HASH_SIZE);

            memcpy(rhbuffer, &response_body, 4);
            memcpy(rhbuffer + 4, &status, 4);
            memcpy(rhbuffer + 8, &block_number, 4);
            memcpy(rhbuffer + 12, &block_count, 4);
            memcpy(rhbuffer + 16, total_hash, SHA256_HASH_SIZE);
            memcpy(rhbuffer + 48, total_hash, SHA256_HASH_SIZE);

            memcpy(errbuffer, rhbuffer, REPLY_HEADER_LEN);
            memcpy(errbuffer + REPLY_HEADER_LEN, payload, 74);

            compsys_helper_writen(connfd, errbuffer, REPLY_HEADER_LEN + 74);
            return;
        }
    }


    status = htonl(STATUS_OK);
    response_body = (IP_LEN + 4) * peer_count;
    int tempint = 0;
    for (int i = 0; i < (int)peer_count; i++) {
        memcpy(payload[i], &network[i]->ip, IP_LEN);
        tempint = htonl(atoi(network[i]->port));
        memcpy(payload[i] + IP_LEN, &tempint, 4);
        printf("testing tempint: %d\n", tempint);
        printf("testing networkint: %d\n", atoi(network[i]->port));

        memcpy(totalpayload + (IP_LEN + 4) * i, &payload, IP_LEN + 4);
    }
    get_data_sha(&payload, total_hash, (IP_LEN + 4) * peer_count, SHA256_HASH_SIZE);
    // We begin constructing the response
    response_body = htonl(response_body);
    memcpy(rhbuffer, &response_body, 4);
    memcpy(rhbuffer + 4, &status, 4);
    memcpy(rhbuffer + 8, &block_number, 4);
    memcpy(rhbuffer + 12, &block_count, 4);
    memcpy(rhbuffer + 16, total_hash, SHA256_HASH_SIZE);
    memcpy(rhbuffer + 48, total_hash, SHA256_HASH_SIZE);
    printf("1\n");


    char pbuffer[REPLY_HEADER_LEN + (IP_LEN + 4) * peer_count];
    memset(pbuffer, 0, REPLY_HEADER_LEN + (IP_LEN + 4) * peer_count);
    memcpy(pbuffer, rhbuffer, REPLY_HEADER_LEN);
    memcpy(pbuffer + REPLY_HEADER_LEN, payload, (IP_LEN + 4) * peer_count);

    compsys_helper_writen(connfd, pbuffer, REPLY_HEADER_LEN + (IP_LEN + 4) * peer_count);


    handle_inform(&newpeer);
}



/*
 * Handle 'inform' type message as defined by the assignment text. These will 
 * never generate a response, even in the case of errors.
 */
void handle_inform(char* request)
{
    // Your code here. This function has been added as a guide, but feel free 
    // to add more, or work in other parts of the code
    printf("\nNOW WE ENTER 'handler_inform'!\n");

    // We start off by initializing
    char* new_ip[IP_LEN];
    memset(&new_ip, 0, IP_LEN * sizeof(char*));
    int new_port_int = 0;
    char* new_port[PORT_LEN];
    memset(&new_port, 0, PORT_LEN * sizeof(char*));

    memcpy(&new_ip, request, IP_LEN);
    memcpy(&new_port_int, request + IP_LEN, 4);
    //new_port_int = ntohl(new_port_int);
    snprintf(new_port, PORT_LEN, "%d", new_port_int);


    // We allocate the new peer
    PeerAddress_t* new_peer = (PeerAddress_t*)malloc(sizeof(PeerAddress_t));

    // Handle the error case for memory allocation
    if (new_peer == NULL) {
        perror("Error allocating memory for the new peer");
        exit(EXIT_FAILURE);
    }

    // We copy the new peer ip and port into the array
    memcpy(&new_peer->ip, new_ip, IP_LEN);
    memcpy(&new_peer->port, new_port, PORT_LEN);

    // We resize the network array, so we can fit in the new peer
    network = (PeerAddress_t**)realloc(network, (peer_count + 1) * sizeof(PeerAddress_t*));

    // Again, we make sure to handle the error case for memory allocation
    if (network == NULL) {
        perror("Error reallocating memory for new peer in network");
        free(new_peer);
        exit(EXIT_FAILURE);
    }

    // We insert the new peer into our network array
    network[peer_count] = new_peer;

    // We increment the peer_count to keep count of current amount of peers
    peer_count++;
}



/*
 * Handle 'retrieve' type messages as defined by the assignment text. This will
 * always generate a response
 */
void handle_retreive(int connfd, char* request)
{
    // Your code here. This function has been added as a guide, but feel free 
    // to add more, or work in other parts of the code
    printf("\nNOW WE ENTER 'handler_retreive'!\n");
    
}



/*
 * Handler for all server requests. This will call the relevent function based 
 * on the parsed command code
 */
void handle_server_request(int connfd)
{
    // Your code here. This function has been added as a guide, but feel free 
    // to add more, or work in other parts of the code
    printf("\nNOW WE ENTER 'handler_server_request'!\n");
    printf("%d\n", connfd);

    // We start off by initializing
    char hbuffer[REQUEST_HEADER_LEN];
    memset(hbuffer, 0, REQUEST_HEADER_LEN);
    char bbuffer[REPLY_HEADER_LEN];
    char peer_ip[IP_LEN];
    memset(peer_ip, 0, IP_LEN);
    int peer_port = 0;
    int status = 0;
    int body_length = 0;

    printf("Initialize 1 done\n");
    compsys_helper_state_t fdd;
    compsys_helper_readinitb(&fdd, connfd);

    printf("Initialize 2 done\n");
    // We read the request
    ssize_t readbuffer = compsys_helper_readnb(&fdd, hbuffer, (size_t)REQUEST_HEADER_LEN);


    // Error cases for reading header
    if (readbuffer == -1) {
        perror("Error reading header");
        return;
    } 
    
    else if (readbuffer < REQUEST_HEADER_LEN) {
        fprintf(stderr, "Incomplete header read. Expected read: %d, Actual read: %zd\n", REQUEST_HEADER_LEN, readbuffer);
        return;
    }


    printf("Read done\n");
    memcpy(&status, hbuffer + 20, 4);
    status = ntohl(status);
    printf("Status done\n");
    memcpy(&peer_ip, hbuffer, IP_LEN);
    printf("peer_ip done\n");
    memcpy(&peer_port, hbuffer + 16, 4);
    peer_port = ntohl(peer_port);
    printf("peer_port done\n");
    memcpy(&body_length, hbuffer + 24, 4);
    body_length = ntohl(body_length);
    printf("Read request done\n");

    printf("Status code: %d\n", status);
    if (status == COMMAND_REGISTER) {
        printf("\nTest register\n");
        handle_register(connfd, peer_ip, peer_port);
    }

    else if (status == COMMAND_RETREIVE) {
        printf("\nTest retreive\n");
        char filename[body_length];
        memset(filename, 0, body_length);

        compsys_helper_readnb(&fdd, bbuffer, (size_t)body_length);
        memcpy(&filename, bbuffer, body_length);

        handle_retreive(connfd, filename);
    }

    else if (status == COMMAND_INFORM) {
        printf("\nTest inform\n");
        compsys_helper_readnb(&fdd, bbuffer, (size_t)body_length);

        char infbuffer[IP_LEN + 4];
        memset(infbuffer, 0 , IP_LEN + 4);

        int tempport = 0;
        memcpy(&tempport, bbuffer + IP_LEN, 4);
        tempport = ntohl(tempport);
        memcpy(infbuffer, bbuffer, IP_LEN);
        memcpy(infbuffer + IP_LEN, &tempport, 4);

        handle_inform(infbuffer);
    }

    else {
        printf("Error reading request type.\n");
    }  
}



/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void* server_thread()
{
    // Your code here. This function has been added as a guide, but feel free 
    // to add more, or work in other parts of the code
    printf("\nNOW WE ENTER 'server_thread'!\n");


    // We start off by intializing
    char buffer[COMPSYS_BUFSIZE];
    memset(buffer, 0, COMPSYS_BUFSIZE);
    int connfd = 0;
    PeerAddress_t peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    pthread_t mul;

    char* myip = "127.0.0.1";
    char* myport = "23456";
    //memset(port, 0, PORT_LEN);
    /* *port = "23456"; */


    char* my_ip_port[IP_LEN + PORT_LEN];
    memset(my_ip_port, 0, IP_LEN + PORT_LEN);
    memcpy(my_ip_port, myip, sizeof(myip));
    memcpy(my_ip_port + IP_LEN, myport, sizeof(myport));

    printf("peer_count before start: %d\n", peer_count);
    printf("my ip: %s\n", network[0]->ip);
    printf("my port: %s\n", network[0]->port);
    /* handle_inform(my_ip_port);
    printf("peer_count at start: %d\n", peer_count);
    printf("my ip: %s\n", network[0]->ip);
    printf("my port: %s\n", network[0]->port);
    printf("my ip: %s\n", network[1]->ip);
    printf("my port: %s\n", network[1]->port); */


    int listenfd = compsys_helper_open_listenfd(myport);
    printf("Now listening on: %s:%s\n", myip, myport);
    //printf("Now listening on: %s\n", myport);

    if (listenfd < 0) {
        perror("Error opening listening socket");
        exit(EXIT_FAILURE);
    }


    while (1) {
        printf("Listening (again).\n");
        connfd = accept(listenfd, (struct sockaddr*)&peer_addr, &peer_len);
        printf("\nWe've got a connection!\n");

        printf("Connfd: %d\n", connfd);
        if (connfd < 0) {
            perror("Error accepting connection");
            continue;
        }


        if (pthread_create(&mul, NULL, (void*)handle_server_request, connfd) != 0) {
            perror("Error creating thread");
            close(connfd);
        }
        else {
            pthread_detach(mul);
            printf("pthread done\n");
        }
    }

    close(listenfd);
}



int main(int argc, char **argv)
{
    // Initialise with known junk values, so we can test if these were actually
    // present in the config or not
    struct PeerAddress peer_address;
    memset(peer_address.ip, '\0', IP_LEN);
    memset(peer_address.port, '\0', PORT_LEN);
    memcpy(peer_address.ip, "x", 1);
    memcpy(peer_address.port, "x", 1);

    // Users should call this script with a single argument describing what 
    // config to use
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    my_address = (PeerAddress_t*)malloc(sizeof(PeerAddress_t));
    memset(my_address->ip, '\0', IP_LEN);
    memset(my_address->port, '\0', PORT_LEN);

    // Read in configuration options. Should include a client_ip, client_port, 
    // server_ip, and server_port
    char buffer[128];
    fprintf(stderr, "Got config path at: %s\n", argv[1]);
    FILE* fp = fopen(argv[1], "r");
    while (fgets(buffer, 128, fp)) {
        if (starts_with(buffer, MY_IP)) {
            memcpy(&my_address->ip, &buffer[strlen(MY_IP)], 
                strcspn(buffer, "\r\n")-strlen(MY_IP));
            if (!is_valid_ip(my_address->ip)) {
                fprintf(stderr, ">> Invalid client IP: %s\n", my_address->ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, MY_PORT)) {
            memcpy(&my_address->port, &buffer[strlen(MY_PORT)], 
                strcspn(buffer, "\r\n")-strlen(MY_PORT));
            if (!is_valid_port(my_address->port)) {
                fprintf(stderr, ">> Invalid client port: %s\n", 
                    my_address->port);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, PEER_IP)) {
            memcpy(peer_address.ip, &buffer[strlen(PEER_IP)], 
                strcspn(buffer, "\r\n")-strlen(PEER_IP));
            if (!is_valid_ip(peer_address.ip)) {
                fprintf(stderr, ">> Invalid peer IP: %s\n", peer_address.ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, PEER_PORT)) {
            memcpy(peer_address.port, &buffer[strlen(PEER_PORT)], 
                strcspn(buffer, "\r\n")-strlen(PEER_PORT));
            if (!is_valid_port(peer_address.port)) {
                fprintf(stderr, ">> Invalid peer port: %s\n", 
                    peer_address.port);
                exit(EXIT_FAILURE);
            }
        }
    }
    fclose(fp);

    retrieving_files = malloc(file_count * sizeof(FilePath_t*));
    srand(time(0));

    network = malloc(sizeof(PeerAddress_t*));
    network[0] = my_address;
    peer_count = 1;

    // Setup the client and server threads 
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    if (peer_address.ip[0] != 'x' && peer_address.port[0] != 'x')
    {   
        pthread_create(&client_thread_id, NULL, client_thread, &peer_address);
    } 
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    // Start the threads. Note that the client is only started if a peer is 
    // provided in the config. If none is we will assume this peer is the first
    // on the network and so cannot act as a client.
    if (peer_address.ip[0] != 'x' && peer_address.port[0] != 'x')
    {
        pthread_join(client_thread_id, NULL);
    }
    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}