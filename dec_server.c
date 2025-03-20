#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h> //send and receive
#include <netinet/in.h>
#include <sys/stat.h>   //umask
#include <sys/wait.h>   // waitpid

/*
Responsible for decrypting the data for ciphertext
*/

#define BUFFERSIZE 1000000
#define SERVER_ID "dec_server"
#define CLIENT_ID "dec_client"

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

// DECRYPT the ciphertext using modulo 27
void decryption(char *ciphertext, char *key){
    int cp_len = strlen(ciphertext);

    for(int i = 0; i < cp_len; i++){
        int ct_val = (ciphertext[i] == ' ') ? 26: (ciphertext[i] - 'A');  //convert char to numeric val (A-Z is 0-25 and space is 26)
        int key_val = (key[i] == ' ') ? 26: (key[i] - 'A'); //convert key to numeric val
        int ct_key = (ct_val - key_val + 27) % 27;   //shift ciphertext char by key's value staying within 0-26

        //conversion ASCII to char
        if (ct_key == 26){
            ciphertext[i] = ' '; //26 is space
        } else {
            ciphertext[i] = 'A' + ct_key;    //else convert to character
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
                    char buffer[BUFFERSIZE], ciphertext[BUFFERSIZE], key[BUFFERSIZE], type[10];
                    memset(buffer, '\0', sizeof(buffer));   //clear buffer memory
                    int totalRead = 0;

                    //search for first occurrence of newline char in given buffer
                    while(strstr(buffer, "\n") == NULL){
                        charsRead = recv(connectionSocket, &buffer[totalRead], 900000, 0); //num of bytes to read, setting under predfined buffer size of 1M
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
                    strcpy(ciphertext, token);

                    // decrypt message to client
                    decryption(ciphertext, key);
                    fflush(stdout);
                    strcat(ciphertext, "\n");
                    fflush(stdout);

                    // send decrypted message to client
                    int totalSent = 0;
                    int charsWritten = 0;
                    while(totalSent < strlen(ciphertext)){
                        charsWritten = send(connectionSocket, &ciphertext[totalSent], 900000, 0);
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
