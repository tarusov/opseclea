#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include "opsec/lea.h"
#include "opsec/lea_filter.h"
#include "opsec/opsec.h"

#define MAX_BUF_SIZE  8192

int LeaStartHandler(OpsecSession *);
int LeaEndHandler(OpsecSession *);
int LeaRecordHandler(OpsecSession *, lea_record *, int []);
int LeaDictionaryHandler(OpsecSession *, int, LEA_VT, int);
int LeaEofHandler(OpsecSession *);
int LeaSwitchHandler(OpsecSession *);
int LeaSessionEstablished(OpsecSession *);

// Application globals.
OpsecEntity        *pClient    = NULL;
OpsecEntity        *pServer    = NULL;
OpsecEnv           *pEnv       = NULL;
struct sockaddr_in  serveraddr;
int                 sock_descr    = 0;
int                 resolve_names = 0;

// Halt func free used memory and return exit code.
void Halt(int exit_code) {
    if (pClient) opsec_destroy_entity(pClient);
    if (pServer) opsec_destroy_entity(pServer);
    if (pEnv)    opsec_env_destroy(pEnv);

    if (sock_descr > 0) {
        close(sock_descr);
    }

    exit(exit_code);
}

// Interrupt func handle OS interrupt signal, end close application.
void Interrupt(int signal) {
    switch (signal) {
    case SIGTERM:
        fprintf(stdout, "INFO: Caught SIGTERM, Exiting.\n");
        break;
    case SIGQUIT: 
        fprintf(stdout, "INFO: Caught SIGQUIT, Exiting.\n");
        break;
    case SIGINT: 
        fprintf(stdout, "INFO: Caught SIGINT, Exiting.\n");
        break;
    case SIGHUP:
        fprintf(stdout, "INFO: Caught SIGHUP, Exiting.\n");
        break;
    default:
        fprintf(stdout, "ERROR: Unknown interrupt signal, Exiting.\n");
        break;
    }

    Halt(0);
}

// GetEnvVar func try to read data from environment.
char* GetEnvVar(char *name) {
    char* dst = NULL;

    if (!pEnv) {
        fprintf(stdout, "ERROR: Environment not inited, Exiting.\n");
        Halt(-1);
    }

    if ((dst = opsec_get_conf(pEnv, name, OPSEC_EOL)) == NULL) {
        fprintf(stdout, "ERROR: Parameter %s not defined in configuration file.\n", name);
        Halt(-1);
    }

    return dst;
}

// Dial create TCP connection with collector.
void Dial(char *addr, int port) {
    if ((sock_descr = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stdout, "ERROR: Unable to init socket\n");
        Halt(-1);
    }

    memset(&serveraddr, 0x00, sizeof(struct sockaddr_in));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(port);
    serveraddr.sin_addr.s_addr = inet_addr(addr);

    // Connect to server.
    if(connect(sock_descr, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
        fprintf(stdout, "ERROR: Unable to connect %s:%d.\n", addr, port);
        close(sock_descr);
        Halt(-1);
    }
}

// Send func push message to lea_record recivier.
int Send(char* buf) {
    int len   = strlen(buf);
    int total = 0;        // how many bytes we've sent
    int bytesleft = len; // how many we have left to send
    int n;

    while(total < len) {
        n = write(sock_descr, buf+total, bytesleft);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }

    return n==-1? -1 : 0; // return -1 on failure, 0 on success
}

// Application entry point.
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stdout, "application usage:\n\n%s <config_file>\n\n", argv[0]);
        Halt(-1);
    }

    FILE *file;
    if ((file = fopen(argv[1], "r")) != NULL) {
        fclose(file);
    } else {
        fprintf(stdout, "ERROR: Unable to open config file: %s for reading.\n", argv[1]);
        Halt(-1);
    }

    // Read environment from config file.
    if ((pEnv = opsec_init(OPSEC_CONF_FILE, argv[1], OPSEC_EOL)) == NULL) {
	    fprintf(stdout,"ERROR: Unable to create environment: %s\n",
		opsec_errno_str(opsec_errno));
        Halt(-1);
	}

    // Get session params.
    char* log_filename  = GetEnvVar("log_filename");

    int online_mode = LEA_OFFLINE;
    if (strcmp("true", GetEnvVar("online_mode")) == 0) {
        online_mode = LEA_ONLINE;
    }

    int read_from_pos = LEA_AT_START;
    if (strcmp("end", GetEnvVar("read_from_pos")) == 0) {
        read_from_pos = LEA_AT_END;
    }

    if (strcmp("true", GetEnvVar("resolve_names")) == 0) {
        resolve_names = 1;
    }

    // Establish connection with collector server.
    char* dst_server_addr = GetEnvVar("dst_server_addr");
    int dst_server_port = atoi(GetEnvVar("dst_server_port"));
    if ((dst_server_port == 0) || (dst_server_port > 0xffff)) {
        fprintf(stdout,"ERROR: Invalid dst_server_port. Must be in range (1..65535)\n");
        Halt(-1);
    }

    Dial(dst_server_addr, dst_server_port);

    // Init OPSEC LEA client.
    pClient = opsec_init_entity (pEnv, LEA_CLIENT,
    		   LEA_RECORD_HANDLER, LeaRecordHandler,
    		   LEA_DICT_HANDLER, LeaDictionaryHandler,
    		   LEA_EOF_HANDLER, LeaEofHandler,
    		   LEA_SWITCH_HANDLER, LeaSwitchHandler,
    		   OPSEC_SESSION_START_HANDLER, LeaStartHandler,
    		   OPSEC_SESSION_END_HANDLER, LeaEndHandler,
    		   OPSEC_SESSION_ESTABLISHED_HANDLER, LeaSessionEstablished, 
    		   OPSEC_EOL);

    // Init OPSEC LEA server.
    pServer = opsec_init_entity (pEnv, LEA_SERVER, 
                OPSEC_ENTITY_NAME, "lea_server",
    	        OPSEC_EOL);

    if ((!pClient) || (!pServer)) {
	    fprintf(stdout,"ERROR: Unable to create client-server pair: %s\n",
		opsec_errno_str(opsec_errno));
        Halt(-1);
	}

    // Create new session.
    OpsecSession *pSession = lea_new_suspended_session(pClient, pServer,
                online_mode, 
                LEA_FILENAME, log_filename,
                read_from_pos);

    if (!pSession) {
        fprintf(stdout,"ERROR: Failed to create session: %s\n",
        opsec_errno_str(opsec_errno));
        Halt(-1);
    }

    // Register handlers to quit app when called.
    signal(SIGTERM, Interrupt);
    signal(SIGQUIT, Interrupt);
    signal(SIGINT, Interrupt);
    signal(SIGHUP, Interrupt);

    lea_session_resume (pSession);    
	opsec_start_keep_alive (pSession, 0);
	opsec_mainloop(pEnv);

    Halt(0);
}

// ----------------------------------------------------------------------
// LeaRecordHandler func parse lea_record and send data to collector.
// ----------------------------------------------------------------------
int LeaRecordHandler(OpsecSession *pSession, lea_record *pRec, int pnAttribPerm[]) {
    char  buf[MAX_BUF_SIZE];         // Message buffer.
	char *szAttrName;
    char *szResValue;

    strcat(buf, "");

    // Get fields.
    for(int i = 0; i < pRec->n_fields; i++) {
        szAttrName = lea_attr_name(pSession, pRec->fields[i].lea_attr_id);

        if (resolve_names) {
            szResValue = lea_resolve_field(pSession, pRec->fields[i]);
        } else {
            unsigned long  ul;
            unsigned short us;
            switch (pRec->fields[i].lea_val_type) {
                /*
                * create dotted string of IP address. this differs between
                * Linux and Solaris.
                */
                case LEA_VT_IP_ADDR:
                    ul = pRec->fields[i].lea_value.ul_value;
                    if (BYTE_ORDER == LITTLE_ENDIAN) {
                        sprintf(szResValue,"%d.%d.%d.%d", (int)((ul & 0xff) >> 0), (int)((ul & 0xff00) >> 8), (int)((ul & 0xff0000) >> 16), (int)((ul & 0xff000000) >> 24));
                    } else {
                        sprintf(szResValue,"%d.%d.%d.%d", (int)((ul & 0xff000000) >> 24), (int)((ul & 0xff0000) >> 16), (int)((ul & 0xff00) >> 8), (int)((ul & 0xff) >> 0));
                    }
                    break;
                /*
                * print out the port number of the used service
                */
                case LEA_VT_TCP_PORT:
                case LEA_VT_UDP_PORT:
                    us = pRec->fields[i].lea_value.ush_value;
                    if (BYTE_ORDER == LITTLE_ENDIAN) {
                    us = (us >> 8) + ((us & 0xff) << 8);
                    } 
                    sprintf(szResValue,"%d", us);
                    break;
                /* 
                * for all other data types, use the normal behaviour
                */
                default:
                    szResValue = lea_resolve_field(pSession, pRec->fields[i]);
            }
        } // switch

        if (strlen(buf) + strlen(szAttrName) + strlen(szResValue) > (MAX_BUF_SIZE - 4)) {
            fprintf(stdout, "ERROR: Message buffer oversize, Skipped.\n");
            return OPSEC_SESSION_OK;
        }

        // Put data to message buffer.
        strcat(buf, szAttrName);
	    strcat(buf, "=");
        strcat(buf, szResValue);

        // Not put splitter for last value.
        if (i < pRec->n_fields - 1) {
            strcat(buf, "||");
        }

    } // for

    strcat(buf, "\n");
    if (Send(buf) < 0) {
        fprintf(stdout, "ERROR: Failed to send message to collector.\n");
    }

    return OPSEC_SESSION_OK;
}

// Required no-op hanlders.
int LeaStartHandler(OpsecSession *s) { return OPSEC_SESSION_OK; }
int LeaEndHandler(OpsecSession *s) { return OPSEC_SESSION_OK; }
int LeaDictionaryHandler(OpsecSession *s, int n, LEA_VT vt, int m) { return OPSEC_SESSION_OK; }
int LeaEofHandler(OpsecSession *s) { return OPSEC_SESSION_OK; }
int LeaSwitchHandler(OpsecSession *s) { return OPSEC_SESSION_OK; }
int LeaSessionEstablished(OpsecSession *s) { return OPSEC_SESSION_OK; }