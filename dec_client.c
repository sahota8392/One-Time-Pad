#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  // ssize_t
#include <sys/socket.h> // send(),recv()
#include <netdb.h>      // gethostbyname()
#include <ctype.h>      //isspace & isupper

/*
Connects to decryption server asking to decrypt ciphertext using key
*/

#define BUFFERSIZE 1000000
#define SERVER_ID "dec_server"
#define CLIENT_ID "dec_client"

// Error function used for reporting issues
void error(const char *msg)
{
    perror(msg);
}

//read message using long int for large file size
long int getFileSize(const char* filename) {
    FILE* file = fopen(filename, "r");
    fseek(file, 0, SEEK_END);   //reads file till end
    long int count = ftell(file); //return cur pos of file pointer in bytes
    fclose(file);
    return count;   //size of file in bytes
}


//validate chars in file till end of file to verify char is space and uppercase letters, if not, exits file
int validateChars(const char* filename) {
    FILE* file = fopen(filename, "r");
    int character = fgetc(file);
    while (character != EOF) {
        if (!isspace(character) && !isupper(character)) {
            fclose(file);
            return 1;
        }
        character = fgetc(file);
    }
    fclose(file);
    return 0;
}


// Set up the address struct
void setupAddressStruct(struct sockaddr_in *address, int portNumber, char *hostname){
    memset((char *)address, '\0', sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(portNumber);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int status = getaddrinfo(hostname, NULL, &hints, &res);
    
    if (status != 0){
        fprintf(stderr, "CLIENT: ERROR, no such host\n");
        exit(1);
    }

    // Copy the first IP address from the DNS entry to sin_addr.s_addr
    struct sockaddr_in* ipaddr = (struct sockaddr_in*) res->ai_addr;
    memcpy((char*) &address->sin_addr.s_addr, &ipaddr->sin_addr, sizeof(struct in_addr));
    freeaddrinfo(res);
}


int main(int argc, char *argv[]){
    int socketFD, charsWritten, charsRead;
    struct sockaddr_in serverAddress;
    char buffer[BUFFERSIZE];
    char ciphertext[BUFFERSIZE];
    char key[BUFFERSIZE];

    // Check usage & args
    if (argc < 3){
        fprintf(stderr, "USAGE: %s hostname port\n", argv[0]);
        exit(1);
    }

    // Create a socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0){
        fprintf(stderr,"CLIENT: ERROR opening socket");
        exit(1);
    }

    // Set up the server address struct
    setupAddressStruct(&serverAddress, atoi(argv[3]), "localhost");

    // Connect to server
    if (connect(socketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0){
        fprintf(stderr, "CLIENT: ERROR connecting");
        exit(2);    //exit 2 if dec_client can't connect to dec_server
    }

    //validate connection is with dec_server
    send(socketFD, CLIENT_ID, strlen(CLIENT_ID) + 1, 0);
    char connectionServer[16];
    recv(socketFD, connectionServer,16,0);
    if (strcmp(connectionServer,SERVER_ID) != 0){
        fprintf(stderr, "CLIENT: ERROR, not connected to dec_server\n");
        exit(2);
    } else {
        fflush(stdout);
        memset(buffer, '\0', sizeof(buffer));
        memset(ciphertext, '\0', sizeof(ciphertext));
        memset(key, '\0', sizeof(key));

    //reading ciphertext file and keyfile from dec_server
    long ct_len = getFileSize(argv[1]);
    long key_len = getFileSize(argv[2]);

    // Validate key is same size as ciphertext or longer
    if(ct_len > key_len){
        fprintf(stderr, "Error: Key is too short for the message.\n");
        exit(1);
    } else if (validateChars(argv[2])){
        fprintf(stderr, "Error: Key contains invalid characters.\n");
        exit(1);
    } else {
        // no errors so open the file
        FILE *ctFile = fopen(argv[1], "r");
        FILE *keyFile = fopen(argv[2], "r");

        fgets(ciphertext, sizeof(ciphertext)-1, ctFile);
        fgets(key, sizeof(key)-1, keyFile);

        // newline removal
        key[strcspn(key, "\n")] = '\0'; 
        ciphertext[strcspn(ciphertext, "\n")] = '\0';
    
        // Message will be sent to the server
        snprintf(buffer, sizeof(buffer), "DEC,%s,%s\n", key, ciphertext);
        fflush(stdout);

        int totalSent = 0;
        while (totalSent < strlen(buffer)) {
            charsWritten = send(socketFD, &buffer[totalSent], 900000, 0); 
            if (charsWritten < 0) {
                fprintf(stderr,"CLIENT: ERROR writing to socket");
                break;
            }
            totalSent += charsWritten;
            // printf("DEBUG: Sending data. Sent: %d\n", totalSent);
        }

        if (totalSent < strlen(buffer)) {
            fprintf(stderr, "CLIENT: WARNING: Not all data written to socket!\n");
        }

        memset(buffer, '\0', sizeof(buffer));
        fflush(stdout);
        int totalRead = 0;

        // Loop until end of message is received
        while (strstr(buffer, "\n") == NULL) {
            //printf("DEBUG: Waiting for response from server...\n");
            charsRead = recv(socketFD, &buffer[totalRead], 1000, 0); 
            if (charsRead < 0) {
                fprintf(stderr, "CLIENT: ERROR reading from socket");
                break;
            }
            totalRead += charsRead;
            //printf("DEBUG: Received %d bytes from server: \"%s\"\n", charsRead, buffer);
        }

        // clear output and close socket
        fflush(stdout);
        printf("%s", buffer);
        fflush(stdout);
        }
    }
    close(socketFD); 
    return 0;
}
