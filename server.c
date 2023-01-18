/* servTCPConcTh2.c - Exemplu de server TCP concurent care deserveste clientii
   prin crearea unui thread pentru fiecare client.
   Asteapta un numar de la clienti si intoarce clientilor numarul incrementat.
	Intoarce corect identificatorul din program al thread-ului.
  
   
   Autor: Lenuta Alboaie  <adria@infoiasi.ro> (c)2009
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#define BUFSIZE 4096

/* portul folosit */
#define PORT 2908

/* codul de eroare returnat de anumite apeluri */
extern int errno;
int download(char *url, int depth);
int download_file(char *url, int depth);
int download_file_https(char *url, int depth);
// Function to extract URLs from the HTML content of a response
void extract_urls(char* html, char* url, int depth)
{
    const char *p = html;
    while((p = strstr(p, "href=\""))!= NULL){
        // Extract the url from the HTML page 
        p+= 6;
        const char *q = strchr(p, '"');
        if(q == NULL){
            break;
        }
        int length = q-p;
        char *link = malloc(length + 1);
        strncpy(link, p, length);
        link[length] = '\0';
        //Check if url is relative path
          // With common part between relative path and the full url
        if(link[0] == '/' && strstr(url,link)!=NULL){
            char *full_url = malloc(strlen(url) + length + 1);
            strcpy(full_url, url);
               char *common = strstr(full_url, link);
            if(common  != NULL){
                size_t prefix_len = strlen(common);
                strcat(full_url, link + prefix_len);
                link = full_url;
            }
        }else if(link[0] == '/' && strstr(url,link) == NULL){
            // Construct the full URL by combinig the url given as parameter with the relative path
            char *full_url = malloc(strlen(url) + length + 1);
            strcpy(full_url, url);
            if(full_url[strlen(full_url)-1] ='/')
                strcat(full_url, link+1);
            else 
                strcat(full_url, link);
            link = full_url;
        }
            download(link, depth-1);
        p=q+1;
    }
}

int download(char *url, int depth){
    if (strncmp(url, "http://", 7) == 0) {
        if(download_file(url, depth) < 0) {
            fprintf(stderr, "Error downloading file : %s\n", url);
            return -1;
        }
    } else if (strncmp(url, "https://", 8) == 0) {
        if(download_file_https(url, depth) < 0){
            fprintf(stderr, "Error downloading file: %s\n", url);
            return -1;
        }
    } else {
        fprintf(stderr, "Unsupported URL scheme\n");
        return -1;
    }
  return 0;
}

int parse_url(char *url, char *host, int *port, char *path, char *filename);
/*
 * Send an HTTP GET request for the specified URL and print the response.
 *
 * url: the URL to request
 * depth: the desired depth of the request
 *
 * Returns 0 on success, -1 on error.
 */
int download_file(char *url, int depth) {
    if(depth < 0) return 0;
    // Parse the URL into its host, port, and path components
    char host[BUFSIZE], path[BUFSIZE], filename[BUFSIZE];
    int port;
    if (parse_url(url, host, &port, path, filename) < 0) {
        fprintf(stderr, "Error parsing URL: %s\n", url);
        return -1;
    }
    if(strlen(filename) <= 0){
        char *p = strrchr(path, '/');
        if(p!= NULL && *(p+1) != '\0'){
            // Use the text after the last '/' character as the filename
            strcpy(filename, p+1);
            if(strchr(filename,'.') == NULL)
            strcat(filename,".html");
        }else{
            //Use a default filename
            strcpy(filename, "default.html");
        }

    }
    // Create a socket and connect to the server
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        return -1;
    }

    struct hostent *server = gethostbyname(host);
    if (server == NULL) {
        fprintf(stderr, "Error resolving hostname: %s\n", host);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Error connecting to server");
        return -1;
    }

    // Send the HTTP GET request
    char request[BUFSIZE];
    snprintf(request, BUFSIZE, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
    if (send(sockfd, request, strlen(request), 0) < 0) {
        perror("Error sending request");
        return -1;
    }

    FILE *file = fopen(filename, "w");
    if(file == NULL){
        perror("Error opening file for writing");
        return -1;
    }

    // Read and save the response
    char response[BUFSIZE];
    int n;
    while ((n = recv(sockfd, response, BUFSIZE, 0)) > 0) {
         if (fwrite(response, 1, n, file) < (size_t)n) {
            perror("Error writing to file");
            return -1;
        }
    }
    if (n < 0) {
        perror("Error receiving response");
        return -1;
    }
    if(depth > 0)
    extract_urls(response, url, depth -1);
    // Close the file and socket
    fclose(file);
    close(sockfd);

    return 0;
}


/*
 * Send an HTTPS GET request for the specified URL and print the response.
 *
 * url: the URL to request
 * depth: the desired depth of the request
 *
 * Returns 0 on success, -1 on error.
 */
int download_file_https(char *url, int depth) {
    if(depth < 0) return 0;
    // Parse the URL into its host, port, and path components
    char host[BUFSIZE], path[BUFSIZE], filename[BUFSIZE];
    int port;
    if (parse_url(url, host, &port, path, filename) < 0) {
        fprintf(stderr, "Error parsing URL: %s\n", url);
        return -1;
    }

    if(strlen(filename) <= 0){
        char *p = strrchr(path, '/');
        if(p!= NULL && *(p+1) != '\0'){
            // Use the text after the last '/' character as the filename
            strcpy(filename, p+1);
        }else{
            //Use a default filename
            strcpy(filename, "default.html");
        }

    }

    // Initialize the OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    // Create a SSL context
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "Error creating SSL context\n");
        return -1;
    }

    // Create a SSL connection
    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "Error creating SSL connection\n");
        return -1;
    }

    // Create a socket and connect to the server
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        return -1;
    }

    struct hostent *server = gethostbyname(host);
    if (server == NULL) {
        fprintf(stderr, "Error resolving hostname: %s\n", host);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Error connecting to server");
        return -1;
    }

    
    // Create an SSL context and set it up for client use
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

    // Create an SSL object and set it up for the connection
    SSL_set_fd(ssl, sockfd);

    // Perform the SSL handshake
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "Error performing SSL handshake\n");
        return -1;
    }

    // Send the HTTPS GET request
    char request[BUFSIZE];
    snprintf(request, BUFSIZE, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
    if (SSL_write(ssl, request, strlen(request)) < 0) {
        fprintf(stderr, "Error sending request\n");
        return -1;
    }
    FILE *file = fopen(filename, "w");
    if(file == NULL){
        perror("Error opening file for writing");
        return -1;
    }

    // Read and print the response
    char response[BUFSIZE];
    int n;
    while ((n = SSL_read(ssl, response, BUFSIZE)) > 0) {
        if (fwrite(response, 1, n, file) < (size_t)n) {
            perror("Error writing to file");
            return -1;
        }
    }
    if (n < 0) {
        fprintf(stderr, "Error receiving response\n");
        return -1;
    }
    if(depth > 0)
    extract_urls(response, url, depth -1);
    // Close the SSL connection and socket
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);

    return 0;
}



/*
 * Parse a URL into its host, port, and path components.
 *
 * url: the URL to parse
 * host: a buffer to store the host component in
 * port: a pointer to an int to store the port component in
 * path: a buffer to store the path component in
 *
 * Returns 0 on success, -1 on error.
 */
int parse_url(char *url, char *host, int *port, char *path, char *filename) {
    // Check for a scheme at the beginning of the URL
    if (strncmp(url, "http://", 7) == 0) {
        *port = 80;
        url += 7;
    } else if (strncmp(url, "https://", 8) == 0) {
        *port = 443;
        url += 8;
    } else {
        fprintf(stderr, "Unsupported URL scheme\n");
        return -1;
    }

    // Split the URL into host and path components
    char *slash = strchr(url, '/');
    if (slash != NULL) {
        strncpy(host, url, slash - url);
        host[slash - url] = '\0';
        strcpy(path, slash);
    } else {
        strcpy(host, url);
        strcpy(path, "/");
    }

    // Split the host into hostname and port components if specified
    char *colon = strchr(host, ':');
    if (colon != NULL) {
        *port = atoi(colon + 1);
        *colon = '\0';
    }

    // Extract the filename from the path
    char *p = strrchr(path, '/');
    strcpy(filename, p+1);


    return 0;
}

typedef struct thData{
	int idThread; //id-ul thread-ului tinut in evidenta de acest program
	int cl; //descriptorul intors de accept
}thData;

static void *treat(void *); /* functia executata de fiecare thread ce realizeaza comunicarea cu clientii */
void raspunde(void *);

int main ()
{
  struct sockaddr_in server;	// structura folosita de server
  struct sockaddr_in from;	
  int nr;		//mesajul primit de trimis la client 
  int sd;		//descriptorul de socket 
  int pid;
  pthread_t th[100];    //Identificatorii thread-urilor care se vor crea
	int i=0;
  

  /* crearea unui socket */
  if ((sd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
      perror ("[server]Eroare la socket().\n");
      return errno;
    }
  /* utilizarea optiunii SO_REUSEADDR */
  int on=1;
  setsockopt(sd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on));
  
  /* pregatirea structurilor de date */
  bzero (&server, sizeof (server));
  bzero (&from, sizeof (from));
  
  /* umplem structura folosita de server */
  /* stabilirea familiei de socket-uri */
    server.sin_family = AF_INET;	
  /* acceptam orice adresa */
    server.sin_addr.s_addr = htonl (INADDR_ANY);
  /* utilizam un port utilizator */
    server.sin_port = htons (PORT);
  
  /* atasam socketul */
  if (bind (sd, (struct sockaddr *) &server, sizeof (struct sockaddr)) == -1)
    {
      perror ("[server]Eroare la bind().\n");
      return errno;
    }

  /* punem serverul sa asculte daca vin clienti sa se conecteze */
  if (listen (sd, 2) == -1)
    {
      perror ("[server]Eroare la listen().\n");
      return errno;
    }
  /* servim in mod concurent clientii...folosind thread-uri */
  while (1)
    {
      int client;
      thData * td; //parametru functia executata de thread     
      int length = sizeof (from);

      printf ("[server]Asteptam la portul %d...\n",PORT);
      fflush (stdout);

      // client= malloc(sizeof(int));
      /* acceptam un client (stare blocanta pina la realizarea conexiunii) */
      if ( (client = accept (sd, (struct sockaddr *) &from, &length)) < 0)
	{
	  perror ("[server]Eroare la accept().\n");
	  continue;
	}
	
        /* s-a realizat conexiunea, se astepta mesajul */
    
	// int idThread; //id-ul threadului
	// int cl; //descriptorul intors de accept

	td=(struct thData*)malloc(sizeof(struct thData));	
	td->idThread=i++;
	td->cl=client;

	pthread_create(&th[i], NULL, &treat, td);	      
				
	}//while    
};				
static void *treat(void * arg)
{		
		struct thData tdL; 
		tdL= *((struct thData*)arg);	
		printf ("[thread]- %d - Asteptam mesajul...\n", tdL.idThread);
		fflush (stdout);		 
		pthread_detach(pthread_self());		
		raspunde((struct thData*)arg);
		/* am terminat cu acest client, inchidem conexiunea */
		close ((intptr_t)arg);
		return(NULL);	
  		
};


void raspunde(void *arg)
{
        int nr, i=0;
	struct thData tdL; 
    char *url;
    int depth;
    char buff[BUFSIZE];

	tdL= *((struct thData*)arg);
	if (read (tdL.cl, buff,BUFSIZE) <= 0)
			{
			  printf("[Thread %d]\n",tdL.idThread);
			  perror ("Eroare la read() de la client.\n");
			
			}
	
	printf ("[Thread %d]Mesajul a fost receptionat...%s\n",tdL.idThread, buff);
		      
		      /*pregatim mesajul de raspuns */
    int status;
    char sth[BUFSIZE];
    strcpy(sth, strtok(buff, "|"));
    char number[BUFSIZE];
    strcpy(number, strtok(NULL, "\0"));
    depth = atoi(number);
     if (strncmp(sth, "http://", 7) == 0) {
        if((status=download_file(sth, depth)) < 0) {
            fprintf(stderr, "Error downloading file : %s\n", url);
        }
    } else if (strncmp(sth, "https://", 8) == 0) {
        if((status = download_file_https(sth, depth)) < 0){
            fprintf(stderr, "Error downloading file: %s\n", url);
        }
    } else {
        status = -1;
        fprintf(stderr, "Unsupported URL scheme\n");
    }

    if(status != 0){
        strcpy(buff, "DOWNLOAD UNSUCCESSFULL! :C");
    }else{
        strcpy(buff, "DOWNLOAD SUCCESSFULL! :D");
    }

	printf("[Thread %d]Trimitem mesajul inapoi...%s\n",tdL.idThread, buff);
		      
		      
		      /* returnam mesajul clientului */
	 if (write (tdL.cl, buff, BUFSIZE) <= 0)
		{
		 printf("[Thread %d] ",tdL.idThread);
		 perror ("[Thread]Eroare la write() catre client.\n");
		}
	else
		printf ("[Thread %d]Mesajul a fost trasmis cu succes.\n",tdL.idThread);	

}