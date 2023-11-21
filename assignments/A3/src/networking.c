#include <stdlib.h>
#include <stdio.h>
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

#include "./networking.h"
#include "./sha256.h"

char server_ip[IP_LEN];
char server_port[PORT_LEN];
char my_ip[IP_LEN];
char my_port[PORT_LEN];

int c;

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
 * Combine a password and salt together and hash the result to form the 
 * 'signature'. The result should be written to the 'hash' variable. Note that 
 * as handed out, this function is never called. You will need to decide where 
 * it is sensible to do so.
 */
void get_signature(char* password, char* salt, hashdata_t* hash)
{
    char to_hash[USERNAME_LEN + SALT_LEN + 1];

    // to_hash contains the password and salt and is then hashed
    memcpy(to_hash, password, PASSWORD_LEN);
    memcpy(to_hash + PASSWORD_LEN, salt, SALT_LEN + 1);
    get_data_sha(to_hash, (uint8_t*)hash, PASSWORD_LEN + SALT_LEN + 1, SHA256_HASH_SIZE);
    // You can use this to confirm that you are hashing what you think you are
    // hashing
    /* for (uint8_t i=0; i<strlen(to_hash); i++)
    {
        printf("[%c]", to_hash[i]);
    }
    printf("\n"); */
}

/*
 * Register a new user with a server by sending the username and signature to 
 * the server
 */
void register_user(char* username, char* password, char* salt)
{
    // Intro message to make the terminal easier to read
    printf("\nProceeding to register new user with username: %s\n", username);


    // We start off by initializing and setting the memory to zeros to make sure the memory is clean
    char buffer[REQUEST_HEADER_LEN];
    memset(buffer, 0, REQUEST_HEADER_LEN);
    char sbuffer[MAX_MSG_LEN];
    memset(sbuffer, 0, MAX_MSG_LEN);
    char hbuffer[RESPONSE_HEADER_LEN];
    memset(hbuffer, 0, RESPONSE_HEADER_LEN);
    int status = 0;
    hashdata_t hashvalue;
    memset(hashvalue, 0, SHA256_HASH_SIZE);

    hashdata_t signature;
    memset(signature, 0, SHA256_HASH_SIZE);
    Request_t req;
    memset(&req, 0, sizeof(Request_t));
    RequestHeader_t rh;
    memset(&rh, 0, sizeof(RequestHeader_t));
    size_t size = 0;

    char filename[USERNAME_LEN + 5]; // The 5 is to allocate space for '.txt' aswell
    memset(filename, 0, USERNAME_LEN + 5);
    FILE *file;


    // We put the necessary components together
    get_signature(password, salt, &signature);
    memcpy(rh.username, username, USERNAME_LEN);
    memcpy(rh.salted_and_hashed, signature, SHA256_HASH_SIZE);
    req.header = rh;
    memcpy(buffer, (void*)&req, sizeof(req));


    // We initialize the connection, 
    int fd = compsys_helper_open_clientfd(server_ip, server_port);
    compsys_helper_state_t fdd;
    compsys_helper_readinitb(&fdd, fd);
    compsys_helper_writen(fd, buffer, REQUEST_HEADER_LEN);
    
    
    // We proceed to read the answer
    compsys_helper_readnb(&fdd, hbuffer, (size_t)RESPONSE_HEADER_LEN);


    // We read the status code to check the servers response on our attempt to register
    memcpy(&status, hbuffer + 4, 4);
    status = ntohl(status);
    printf("Server status code from registering user: %d\n", status);


    // We read the package size
    memcpy(&size, hbuffer, 4);
    size = ntohl(size);
    printf("The size of the package to be sent from the server in response to registering user: %zu\n", size);
    compsys_helper_readnb(&fdd, sbuffer, (size_t)size);

    // We copy the recieved header and hash it to compare it to the hash value
    memset(signature, 0, SHA256_HASH_SIZE);
    get_data_sha(sbuffer, signature, size, SHA256_HASH_SIZE);
    memcpy(&hashvalue, hbuffer + 16, SHA256_HASH_SIZE);


    // We check the hash value to see if we recieved the correct header or not
    if (memcmp(signature, hashvalue, SHA256_HASH_SIZE) != 0) {
        printf("Wrong package recieved - aborting local registering. Try again or consider restarting with another user.\n");
        return;
    }


    // Handling the status code by sending the server response when appropriate
    if (status == 2) {
        printf("Server package: %s\n", sbuffer);
        printf("Possible mistmatch in server and local registration if user is not saved locally. Consider restarting with a new user.\n");
    }

    else if (status != 1 && status != 2) {
        printf("Failed to register user: %s\n", username);
        return;
    }

    else {
        printf("Server package: %s\n", sbuffer);
    }
    

    // We close the connection
    close(fd);


    // Create the filename using the username
    snprintf(filename, sizeof(filename), "%s.txt", username);


    // Check whether the filename already exists
    if (access(filename, F_OK) != -1) {
        printf("Local file for username '%s' already exists.\n", username);
        return;
    }


    // Attempt to open a new file for writing
    file = fopen(filename, "w");


    // Handling of failure to do so
    if (file == NULL) {
        printf("Failed to create the file for username '%s'.\n", username);
        return;
    }


    // Write the password and salt to the file
    fprintf(file, "Password: %s\nSalt: %s\n", password, salt);

    // Close the file when done and announce it
    fclose(file);
    printf("User '%s' registered successfully.\n", username);
}


/*
 * Get a file from the server by sending the username and signature, along with
 * a file path. Note that this function should be able to deal with both small 
 * and large files. 
 */
void get_file(char* username, char* password, char* salt, char* to_get)
{
    // Intro message to make terminal easier to read
    printf("\nProceeding to download file '%s' for user: %s\n", to_get, username);

    // We start off by initializing
    char buffer[REQUEST_HEADER_LEN];
    memset(buffer, 0, REQUEST_HEADER_LEN);
    char hbuffer[RESPONSE_HEADER_LEN];
    memset(hbuffer, 0, RESPONSE_HEADER_LEN);
    char sbuffer[MAX_MSG_LEN];
    memset(sbuffer, 0, MAX_MSG_LEN);
    int status = 0;
    int blocks = 0;
    int currentblock = 0;
    char payload[MAX_PAYLOAD][MAX_MSG_LEN];
    for (int i = 0; i < MAX_PAYLOAD; i++) {
        memset(payload[i], 0, MAX_MSG_LEN);
    }
    hashdata_t hashvalue;
    memset(hashvalue, 0, SHA256_HASH_SIZE);
    hashdata_t totalhashvalue;
    memset(totalhashvalue, 0, SHA256_HASH_SIZE);

    FILE* userfile;
    char userfilename[USERNAME_LEN + 5]; // The 5 is to allocate space for the '.txt'
    memset(userfilename, 0, USERNAME_LEN + 5);
    char filename[USERNAME_LEN + 5]; // The 5 is to allocate space for the '.txt'
    memset(filename, 0, USERNAME_LEN + 5);
    FILE *file;

    char* line = NULL;
    size_t len = 0;

    Request_t req;
    memset(&req, 0, sizeof(Request_t));
    RequestHeader_t rh;
    memset(&rh, 0, sizeof(RequestHeader_t));
    PasswordAndSalt_t pas;
    memset(&pas, 0, sizeof(PasswordAndSalt_t));
    hashdata_t signature;
    memset(signature, 0, SHA256_HASH_SIZE);
    size_t size = 0;
    

    // Create the filename using the username
    snprintf(userfilename, USERNAME_LEN + 5, "%s.txt", username);
    userfile = fopen(userfilename, "r");


    // Handling the case where the file doesn't exist
    if (userfile == NULL) {
        printf("User '%s' not registered locally.\nPlease register user.\n", username);
        return;
    }


    // Loop through each line in the file
    while (getline(&line, &len, userfile)) {

        if (line[0] == '\n') {
            printf("Empty line\n");
        }

        // Check if the line contains "Salt: "
        if (strncmp(line, "Salt: ", strlen("Salt: ")) == 0) {

            // Extract the value after "Salt:"
            char *saltValue = strchr(line, ':');
            if (saltValue != NULL) {
                // Move to the next character after ':'
                saltValue++;

                while(*saltValue == ' ') {
                    saltValue++;
                }

                // Print or use the salt value (remove trailing newline if present)
                saltValue[strcspn(saltValue, "\n")] = '\0';
                memcpy(salt, saltValue, strlen(saltValue));
                // Below print statement can be used to check the salt value
                //printf("Extracted the salt: %s\n", salt);
                break;
            }
        }
    }
    fclose(userfile);
    free(line);


    // We put the necessary components together
    memcpy(rh.username, username, USERNAME_LEN);
    get_signature(password, salt, &signature);
    memcpy(rh.salted_and_hashed, signature, SHA256_HASH_SIZE);
    rh.length = htonl(strlen(to_get));
    req.header = rh;
    memcpy(pas.password, password, PASSWORD_LEN);
    memcpy(req.payload, to_get, strlen(to_get));
    memcpy(buffer, (void*)&req, REQUEST_HEADER_LEN + strlen(to_get));


    // We establish the connection and write to the server
    int fd = compsys_helper_open_clientfd(server_ip, server_port);
    compsys_helper_state_t fdd;
    compsys_helper_readinitb(&fdd, fd);
    compsys_helper_writen(fd, buffer, REQUEST_HEADER_LEN + strlen(to_get));


    // We read the servers response and check the server status
    compsys_helper_readnb(&fdd, hbuffer, (size_t)RESPONSE_HEADER_LEN);
    memcpy(&status, hbuffer + 4, sizeof(int));
    status = ntohl(status);
    printf("Server status code from getting file: %d\n", status);


    // We return from the get_file function in case the server doesn't recognize us
    if (status == 4) {
        printf("Server unable to recognize user. Check username and password.\n");
        return;
    }

    if (status != 1) {
        printf("Unable to retrieve file.\n");
        return;
    }


    // We check the total number of blocks to be recieved
    memcpy(&blocks, hbuffer + 12, 4);
    blocks = ntohl(blocks);
    printf("%d blocks to be downloaded\n", blocks);

    
    // We check the size to be sent
    memcpy(&size, hbuffer, 4);
    size = ntohl(size);
    printf("The size of the package to be sent from the server in response to getting a file: %zu\n", size);


    // We read the (first) package and after hashing, any potential others
    compsys_helper_readnb(&fdd, sbuffer, (size_t)size);


    // We copy the recieved header and hash it to compare it to the hash value
    memset(signature, 0, SHA256_HASH_SIZE);
    get_data_sha(sbuffer, signature, size, SHA256_HASH_SIZE);
    memcpy(&hashvalue, hbuffer + 16, SHA256_HASH_SIZE);
    memcpy(&totalhashvalue, hbuffer + 48, SHA256_HASH_SIZE);


    // We check the hash value to see if we recieved the correct header or not
    if (memcmp(signature, hashvalue, SHA256_HASH_SIZE) != 0) {
        printf("Wrong package recieved - aborting request. Try again or consider restarting with another user.\n");
        return;
    }


    // If there's more than one package to be recieved, we get the rest
    if (blocks > 1) {
        memcpy(&currentblock, hbuffer + 8, 4);
        memcpy(&payload[currentblock], sbuffer, MAX_MSG_LEN);

        for (int i = 1; i < blocks; i++) {
            compsys_helper_readnb(&fdd, hbuffer, (size_t)RESPONSE_HEADER_LEN);

            memcpy(&currentblock, hbuffer + 8, 4);
            currentblock = ntohl(currentblock);

            memcpy(&size, hbuffer, 4);
            size = ntohl(size);

            memset(sbuffer, 0, MAX_MSG_LEN);
            compsys_helper_readnb(&fdd, sbuffer, (size_t)size);

            // We copy the new recieved header and hash it to compare it to the hash value to ensure the correctness
            memset(signature, 0, SHA256_HASH_SIZE);
            memset(hashvalue, 0, SHA256_HASH_SIZE);
            get_data_sha(sbuffer, signature, size, SHA256_HASH_SIZE);
            memcpy(&hashvalue, hbuffer + 16, SHA256_HASH_SIZE);

            // We check the hash value to see if we recieved the correct header or not
            if (memcmp(signature, hashvalue, SHA256_HASH_SIZE) != 0) {
                printf("Wrong package recieved - aborting request. Try again or consider restarting with another user.\n");
                return;
            }

            memcpy(&payload[currentblock], sbuffer, size);
        }
    }


    // We close the connection
    close(fd);


    // Check if the file already exists
    memcpy(&filename, to_get, strlen(to_get));
    if ((file = fopen(filename, "r")) != NULL) {
        printf("The requested file, '%s', already exists.\n", filename);
        fclose(file);
        return;
    }


    // Create the filename using the username
    snprintf(filename, sizeof(filename), "%s", to_get);


    // Attempt to open a new file for writing
    file = fopen(filename, "w");

    if (file == NULL) {
        printf("Failed to create the file for '%s'.\n", to_get);
        return;
    }


    // Write the package into the file
    if (blocks == 1) {
        fprintf(file, "%s", sbuffer);
        printf("Finished downloading the '%s' file.\n", to_get);
    }
    
    else if (blocks > 1) {
        for (int i = 0; i < blocks; i++) {
            fprintf(file, "%s", payload[i]);
        }
        printf("Finished downloading the '%s' file.\n", to_get);   
    }

    else {
        printf("Sorry, error occured during download.\n");
    }


    memset(signature, 0, SHA256_HASH_SIZE);
    get_file_sha(filename, signature, SHA256_HASH_SIZE);
    printf("Computed Hash for '%s': ", filename);
    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");
    printf("Expected Hash: ");
    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
        printf("%02x", totalhashvalue[i]);
    }
    printf("\n");
    if (memcmp(totalhashvalue, signature, SHA256_HASH_SIZE) != 0) {
        printf("Warning: File hash isn't as expected. Please, check the content of the file.\n");
    }


    // Close the file and free memory when done
    fclose(file);
}

int main(int argc, char **argv)
{
    // Users should call this script with a single argument describing what 
    // config to use
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    // Random value generation
    srand(time(0));

    // Read in configuration options. Should include a client_directory, 
    // client_ip, client_port, server_ip, and server_port
    char buffer[128];
    fprintf(stderr, "Got config path at: %s\n", argv[1]);
    FILE* fp = fopen(argv[1], "r");
    while (fgets(buffer, 128, fp)) {
        if (starts_with(buffer, CLIENT_IP)) {
            memcpy(my_ip, &buffer[strlen(CLIENT_IP)], 
                strcspn(buffer, "\r\n")-strlen(CLIENT_IP));
            if (!is_valid_ip(my_ip)) {
                fprintf(stderr, ">> Invalid client IP: %s\n", my_ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, CLIENT_PORT)) {
            memcpy(my_port, &buffer[strlen(CLIENT_PORT)], 
                strcspn(buffer, "\r\n")-strlen(CLIENT_PORT));
            if (!is_valid_port(my_port)) {
                fprintf(stderr, ">> Invalid client port: %s\n", my_port);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, SERVER_IP)) {
            memcpy(server_ip, &buffer[strlen(SERVER_IP)], 
                strcspn(buffer, "\r\n")-strlen(SERVER_IP));
            if (!is_valid_ip(server_ip)) {
                fprintf(stderr, ">> Invalid server IP: %s\n", server_ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, SERVER_PORT)) {
            memcpy(server_port, &buffer[strlen(SERVER_PORT)], 
                strcspn(buffer, "\r\n")-strlen(SERVER_PORT));
            if (!is_valid_port(server_port)) {
                fprintf(stderr, ">> Invalid server port: %s\n", server_port);
                exit(EXIT_FAILURE);
            }
        }        
    }
    fclose(fp);

    fprintf(stdout, "Client at: %s:%s\n", my_ip, my_port);
    fprintf(stdout, "Server at: %s:%s\n", server_ip, server_port);

    char username[USERNAME_LEN];
    char password[PASSWORD_LEN];
    char user_salt[SALT_LEN+1];
    
    fprintf(stdout, "Enter a username to proceed: ");
    scanf("%16s", username);
    while ((c = getchar()) != '\n' && c != EOF);
    // Clean up username string as otherwise some extra chars can sneak in.
    for (int i=strlen(username); i<USERNAME_LEN; i++)
    {
        username[i] = '\0';
    }
 
    fprintf(stdout, "Enter your password to proceed: ");
    scanf("%16s", password);
    while ((c = getchar()) != '\n' && c != EOF);
    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(password); i<PASSWORD_LEN; i++)
    {
        password[i] = '\0';
    }

    // Note that a random salt should be used, but you may find it easier to
    // repeatedly test the same user credentials by using the hard coded value
    // below instead, and commenting out this randomly generating section.
    for (int i=0; i<SALT_LEN; i++)
    {
        user_salt[i] = 'a' + rand() % 26;
    }
    user_salt[SALT_LEN] = '\0';


    fprintf(stdout, "Using salt: %s\n", user_salt);


    // Here we run our user interaction
    char interaction[15];
    memset(interaction, 0, 15);
    char filename[15]; // Adjust the size as needed
    memset(filename, 0, 15);

    // Welcome message and if statements to handle inputs
    printf("\nHello and welcome to the Networking program! Type '--help' for a list of available commands.\n");
    while (1) {
        memset(interaction, 0, 15);
        printf("\nPlease enter command: ");
        scanf("%s", interaction);

        if (strcmp(interaction, "register") == 0) {
            register_user(username, password, user_salt);
        }

        else if (strcmp(interaction, "file") == 0) {
            printf("\nType the entire file name otherwise type '--back': ");
            scanf("%s", filename);
            if (strcmp(filename, "--back") == 0) {}
            else {
                get_file(username, password, user_salt, filename);
            }
        }

        else if (strcmp(interaction, "quit") == 0) {
            printf("\nSee you next time!\n");
            break;
        }

        else if (strcmp(interaction, "--help") == 0) {
            printf("\nAvailable commands:\nregister - Registers user\nfile - Downloads file from server\nquit - Quits program\n");
        }

        else {
            printf("\nInvalid command. Type '--help' for a list of commands.\n");
        }
    }


    exit(EXIT_SUCCESS);
}