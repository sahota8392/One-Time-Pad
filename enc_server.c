#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h> //send and receive
#include <netinet/in.h> //sockaddr
#include <sys/stat.h>   //umask
#include <sys/wait.h>   // waitpid

/*
Encrypt the plaintext data 

Source 1: https://www.geeksforgeeks.org/daemon-processes/ (daemonized)
Source 2: https://mustafaserdarkonca.medium.com/encryption-and-decryption-algorithm-in-c-26c18080cbd7 (encrypt)
Source 3: https://www.ibm.com/docs/en/i/7.3?topic=functions-memset-set-bytes-value (memset)
Source 4: https://www.geeksforgeeks.org/design-a-concurrent-server-for-handling-multiple-clients-using-fork/ (concurrent-server)
Source 5: https://medium.com/@srupa.thota/modular-arithmetic-historical-ciphers-a40b5b75d63b (modulo)
*/

#define BUFFERSIZE 1000000
#define SERVER_ID "enc_server"
#define CLIENT_ID "enc_client"

// Error function used for reporting issues
void error(const char *msg)
{
    perror(msg);
}


// Set up the address struct for the server socket
void setupAddressStruct(struct sockaddr_in *address, int portNumber){
    memset((char *)address, '\0', sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(portNumber);
    address->sin_addr.s_addr = INADDR_ANY;
}

// encrypt the plaintext data using modulo 27
void encryption(char *plaintext, char *key){
    int pt_len = strlen(plaintext);

    for(int i = 0; i < pt_len; i++){
        int pt_val = (plaintext[i] == ' ') ? 26: (plaintext[i] - 'A');  //convert char to numeric val (A-Z is 0-25 and space is 26)
        int key_val = (key[i] == ' ') ? 26: (key[i] - 'A'); //convert key to numeric val
        int pt_key = (pt_val + key_val) % 27;   //shift plaintext char by key's value staying within 0-26

        //conversion ASCII to char
        if (pt_key == 26){
            plaintext[i] = ' '; //26 is space
        } else {
            plaintext[i] = 'A' + pt_key;    //else chars
        }
    }
}

int main(int argc, char *argv[]){
    int connectionSocket, charsRead;
    struct sockaddr_in serverAddress, clientAddress;
    socklen_t sizeOfClientInfo = sizeof(clientAddress);

    // Check usage & args
    if (argc < 2){
        fprintf(stderr, "USAGE: %s port\n", argv[0]);
        exit(1);
    }
    // Create the socket that will listen for connections
    int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket < 0){
        fprintf(stderr, "ERROR opening socket");
        exit(1);
    }
    // Set up the address struct for the server socket
    setupAddressStruct(&serverAddress, atoi(argv[1]));
    // Associate the socket to the port
    if (bind(listenSocket,(struct sockaddr *)&serverAddress,sizeof(serverAddress)) < 0){
        fprintf(stderr, "ERROR on binding");
        exit(1);
    }
    // Start listening for connetions. Allow up to 5 connections to queue up
    listen(listenSocket, 5);

    // Accept a connection, blocking if one is not available until one connects
    while (1){
        // Accept the connection request which creates a connection socket
        connectionSocket = accept(listenSocket, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);
        if (connectionSocket < 0){
            fprintf(stderr, "ERROR on accept");
        }

        //set buffer size of 16 (enc_server+enc_client is 10)
        char client_id[16];
        recv(connectionSocket, client_id, 16,0);
        send(connectionSocket, SERVER_ID, 16, 0);
        fflush(stdout);     //flush to ensure data buffered in memory is written out

        //string compare the received client_id to our defined client id to ensure connection is valid
        if(strcmp(client_id, CLIENT_ID) == 0){
            //fork child process if no error on accepting
            pid_t spawnpid = fork();
            switch(spawnpid){
                case -1:{
                    perror("ERROR: fork failed.\n");
                    exit(1);
                    break;
                }
                // Child process
                case 0:{
                    //buffer is temp storage, plaintext and key hold respective data, type[10] is for type we will identify, 10 chars
                    char buffer[BUFFERSIZE], plaintText[BUFFERSIZE], key[BUFFERSIZE], type[10];
                    memset(buffer, '\0', sizeof(buffer));   //clear buffer memory
                    int totalRead = 0;

                    //search for first occurrence of newline char in given buffer
                    while(strstr(buffer, "\n") == NULL){
                        charsRead = recv(connectionSocket, &buffer[totalRead], 900000, 0);  //num of bytes to read, setting under predfined buffer size of 1M
                        if(charsRead < 0){
                            perror("ERROR reading from socket");
                            break;
                        }
                        totalRead += charsRead;
                    }
                    fflush(stdout);
                    buffer[strcspn(buffer, "\n")] = '\0';   //return index of first char in buffer
                    char *saveptr;  //pointer for tokenization

                    //extract type, key and plaintext from buffer
                    char *token = strtok_r(buffer, " ", &saveptr);  //split after first space
                    strcpy(type, token);
                    token = strtok_r(NULL, ",", &saveptr);  //split after ,
                    strcpy(key, token);
                    token = strtok_r(NULL, ",", &saveptr);
                    strcpy(plaintText, token);

                    // encrypting message to client
                    encryption(plaintText, key);
                    fflush(stdout);
                    strcat(plaintText, "\n");
                    fflush(stdout);

                    // send encrypted message to client
                    int totalSent = 0;
                    int charsWritten = 0;
                    while(totalSent < strlen(plaintText)){
                        charsWritten = send(connectionSocket, &plaintText[totalSent], 900000, 0);
                        if(charsWritten < 0){
                            perror("ERROR writing to socket");
                            break;
                        }
                        totalSent += charsWritten;
                    }
                    close(connectionSocket);
                    exit(0);
                    break;
                }
                default:{
                    // Parent process
                    close(connectionSocket);
                    break;
                }
            }
        } else {
            close(connectionSocket);
        }
    }
    close(listenSocket);
    return 0;
}
