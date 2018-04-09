/*  simpletun.c include header files */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

#include <memory.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CLIENT_CERTF "./certs/client.crt"
#define CLIENT_KEYF "./certs/client.key"
#define CACERT "./certs/ca.crt"
#define SERVER_CERTF "./certs/server.crt"
#define SERVER_KEYF "./certs/server.key"
#define FORGED_CERT_CLIENT "./certs/forged_cert_client.crt"
#define FORGED_CERT_SERVER "./certs/forged_cert_server.crt"

#define KEY_LEN 16
#define IV_LEN 16

/* BEGIN openssl macros */
#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }
/* END openssl macros */

/* BEGIN simpletun.c macros */
/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define SSL_PORT 20407

#define UDP_TUN_PORT 20405
#define UDP_TUN_NAME "tun0" 

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

char *progname;
int debug = 1;
/* END simpletun.c macros */

int verbose_debug = 0;

/*
	testnum1	[action] change the value of the received hash	[result] packet should be dropped
	testnum2	[action] forged host certificate	[result] other host should not verify and no tunnel is made
	testnum3	[action] print out keys and iv on both sides        [result] the IV and KEYs are printed at both sides
	testnum4	[action] print out certificates on both sides       [result] the certificates for other host is printed at each host
	testnum5	[action] show plaintext, cipher text, digest       
	testnum6	[action] show hash verified   
*/
int testnum = 0;

char MC02_IP[] = "128.10.12.202";
char MC03_IP[] = "128.10.12.203";

unsigned char KEY[KEY_LEN+1];
unsigned char IV[IV_LEN+1];

void create_iv(unsigned char *iv_buff) {
	int i;
	srand(time(NULL));
	for (i=0;i<IV_LEN;i++) {
		iv_buff[i] = rand() % (57 + 1 - 48) + 48;
	}
	iv_buff[i] = '\0';	
}

void create_key(unsigned char *key_buff) {
	int i;
	srand(time(NULL));
	for (i=0;i<KEY_LEN;i++) {
		key_buff[i] = rand() % (122 + 1 - 97) + 97;
	}
	key_buff[i] = '\0';	
}

void hash_data(unsigned char *input, int inputlen, unsigned char *outbuf, int *outbuflen, 
	unsigned char *key) {
	
	HMAC_CTX hmac_ctx;
	HMAC_CTX_init(&hmac_ctx);
	HMAC_Init_ex(&hmac_ctx, key, strlen(key), EVP_sha256(), NULL);
	HMAC_Update(&hmac_ctx, input, inputlen);
	HMAC_Final(&hmac_ctx, outbuf, outbuflen);
	HMAC_CTX_cleanup(&hmac_ctx);
}

void print_hashed_data(unsigned char *data, int datalen) {
	int i;
	for (i=0;i<datalen;i++) 
		printf("%02x", (unsigned char)data[i]);	
	printf("\n");
}

int encrypt_decrypt_data(char *input, int *inlen, char *outbuf, int *outbuflen, unsigned char *key,
	unsigned char *iv, int do_encrypt) {
	
	int outlen,remaininglen;

        EVP_CIPHER_CTX ctx;
        EVP_CIPHER_CTX_init(&ctx);
        EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, do_encrypt);

        /* Now we can set key and IV */
        EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);
        if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, input, inlen)) {
                /* Error */
		EVP_CIPHER_CTX_cleanup(&ctx);
                return 0;
        }
        if(!EVP_CipherFinal_ex(&ctx, outbuf + outlen, &remaininglen)) {
                /* Error */
		EVP_CIPHER_CTX_cleanup(&ctx);
                return 0;
        }
	outlen = outlen + remaininglen;
	*outbuflen = outlen;
	EVP_CIPHER_CTX_cleanup(&ctx);
	return 1;
}

void do_client_key_exchange(char *remote_ip) {
	int err;
	int sd;
	struct sockaddr_in sa;
	SSL_CTX* ctx;
	SSL*     ssl;
	X509*    server_cert;
	char*    str;
	char     buf [4096];
	SSL_METHOD *meth;

	SSLeay_add_ssl_algorithms();
	meth = SSLv23_client_method();
	SSL_load_error_strings();
	ctx = SSL_CTX_new (meth);                        CHK_NULL(ctx);

	CHK_SSL(err);

	SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
	SSL_CTX_load_verify_locations(ctx,CACERT,NULL);

	if (testnum==2) {
		if (SSL_CTX_use_certificate_file(ctx, FORGED_CERT_CLIENT, SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(-2);
		}
	} else {
		if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERTF, SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(-2);
		}

	}

	if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-3);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		printf("Private key does not match the certificate public keyn");
		exit(-4);
	}

	/* ----------------------------------------------- */
	/* Create a socket and connect to server using normal socket calls. */

	sd = socket (AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");

	memset (&sa, '\0', sizeof(sa));

	sa.sin_family      = AF_INET;
	// sa.sin_addr.s_addr = inet_addr ("127.0.0.1");   /* Server IP */
	sa.sin_addr.s_addr = inet_addr (remote_ip);   /* Server IP */
	sa.sin_port        = htons     (SSL_PORT);          /* Server Port number */

	err = connect(sd, (struct sockaddr*) &sa,
			sizeof(sa));                   CHK_ERR(err, "connect");

	/* ----------------------------------------------- */
	/* Now we have TCP conncetion. Start SSL negotiation. */

	ssl = SSL_new (ctx);                         CHK_NULL(ssl);
	SSL_set_fd (ssl, sd);
	err = SSL_connect (ssl);                     CHK_SSL(err);

	/* Following two steps are optional and not required for
	   data exchange to be successful. */

	/* Get the cipher - opt */

	printf ("SSL connection using %s\n", SSL_get_cipher (ssl));

	/* Get server's certificate (note: beware of dynamic allocation) - opt */

	server_cert = SSL_get_peer_certificate (ssl);       CHK_NULL(server_cert);
		

	if (testnum==4 || verbose_debug==1) {
		printf("\n-------------------------------\n");	
		printf ("Server certificate:\n");
	}
	str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
	CHK_NULL(str);
	if (testnum==4 || verbose_debug==1) {
		printf ("\t subject: %s\n", str);
	}	
	OPENSSL_free (str);

	str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
	CHK_NULL(str);
	if (testnum==4 || verbose_debug==1) {
		printf ("\t issuer: %s\n", str);
		printf("\n-------------------------------\n");	
	}	
	OPENSSL_free (str);

	/* We could do all sorts of certificate verification stuff here before
	   deallocating the certificate. */

	X509_free (server_cert);

	/* Now that the peer has been authenticated, the client now generates
		a random key and IV */
	
	create_iv(IV);
	create_key(KEY);	
	
	if (testnum==3 || verbose_debug==1) {
		printf("\n-------------------------------\n");	
		printf("Following are the KEY and the IV generated by the client:\n");	
		printf("KEY = %s\nIV = %s\n",KEY,IV);
		printf("\n-------------------------------\n");	
	}

	/* concatenating the iv and key to send to the other side */
	char *new_str ;
	if((new_str = malloc(strlen(IV)+strlen(KEY)+1)) != NULL){
		new_str[0] = '\0';   // ensures the memory is an empty string
		strcat(new_str,IV);
		strcat(new_str,KEY);
	} else {
		printf("malloc failed!\n");
		exit(1);
	}
	
	/* --------------------------------------------------- */
	/* DATA EXCHANGE - Send a message and receive a reply. */

	err = SSL_write (ssl, new_str, strlen(new_str));  CHK_SSL(err);

	err = SSL_read (ssl, buf, sizeof(buf) - 1);                     CHK_SSL(err);
	buf[err] = '\0';
	printf ("Got %d chars:'%s'\n", err, buf);
	SSL_shutdown (ssl);  /* send SSL/TLS close_notify */

	/* Clean up. */

	close (sd);
	SSL_free (ssl);
	SSL_CTX_free (ctx);

//	return 0;
}

void do_server_key_exchange() {
	int err;
	int listen_sd;
	int sd;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	// size_t client_len;
	socklen_t client_len;
	SSL_CTX* ctx;
	SSL*     ssl;
	X509*    client_cert;
	char*    str;
	char     buf [4096];
	SSL_METHOD *meth;

	/* SSL preliminaries. We keep the certificate and key with the context. */

	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new (meth);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(2);
	}

	SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL); /* whether verify the certificate */
	SSL_CTX_load_verify_locations(ctx,CACERT,NULL);

	if (testnum==2) {
		if (SSL_CTX_use_certificate_file(ctx, FORGED_CERT_SERVER, SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(3);
		}
	} else {
		if (SSL_CTX_use_certificate_file(ctx, SERVER_CERTF, SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(3);
		}

	}
	if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr,"Private key does not match the certificate public key\n");
		exit(5);
	}

	/* ----------------------------------------------- */
	/* Prepare TCP socket for receiving connections */

	listen_sd = socket (AF_INET, SOCK_STREAM, 0);   CHK_ERR(listen_sd, "socket");

	memset (&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family      = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port        = htons (SSL_PORT);          /* Server Port number */

	err = bind(listen_sd, (struct sockaddr*) &sa_serv,
			sizeof (sa_serv));                   CHK_ERR(err, "bind");

	/* Receive a TCP connection. */

	err = listen (listen_sd, 5);                    CHK_ERR(err, "listen");

	client_len = sizeof(sa_cli);
	sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
	CHK_ERR(sd, "accept");
	close (listen_sd);

	printf ("Connection from %lx, port %x\n",
			sa_cli.sin_addr.s_addr, sa_cli.sin_port);

	/* ----------------------------------------------- */
	/* TCP connection is ready. Do server side SSL. */

	ssl = SSL_new (ctx);                           CHK_NULL(ssl);
	SSL_set_fd (ssl, sd);
	err = SSL_accept (ssl);                        CHK_SSL(err);

	/* Get the cipher - opt */

	printf ("SSL connection using %s\n", SSL_get_cipher (ssl));

	/* Get client's certificate (note: beware of dynamic allocation) - opt */

	client_cert = SSL_get_peer_certificate (ssl);
	if (client_cert != NULL) {
		if (testnum==4 || verbose_debug==1) {
			printf("\n-------------------------------\n");	
			printf ("Client certificate:\n");
		}
		str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
		CHK_NULL(str);
		if (testnum==4 || verbose_debug==1) {
			printf ("\t subject: %s\n", str);
		}	
		OPENSSL_free (str);

		str = X509_NAME_oneline (X509_get_issuer_name  (client_cert), 0, 0);
		CHK_NULL(str);
		if (testnum==4 || verbose_debug==1) {
			printf ("\t issuer: %s\n", str);
			printf("\n-------------------------------\n");	
		}	
		OPENSSL_free (str);


		/* We could do all sorts of certificate verification stuff here before
		   deallocating the certificate. */

		X509_free (client_cert);
	} else
		printf ("Client does not have certificate.\n");


	/* KEY EXCHANGE - Receive message and send reply. */	

	err = SSL_read (ssl, buf, sizeof(buf) - 1);                   CHK_SSL(err);
	buf[err] = '\0';
	printf ("Got %d chars:'%s'\n", err, buf);

	// now we write the IV and the KEY in the respective variables on the server side
	int i,j;
	for (i=0;i<IV_LEN;i++) {	
		IV[i] = buf[i];
//		printf("%c",buf[i]);
	}
	IV[i] = '\0';
	printf("\n");
	for (j=0;j<KEY_LEN;j++) {
		KEY[j] = buf[i];
//		printf("%c",buf[i]);
		i++;
	}
	KEY[j] = '\0';
	printf("\n");


	if (testnum==3 || verbose_debug == 1) {
		printf("\n-------------------------------\n");	
		printf("Following are the KEY and the IV received by the server:\n");	
		printf("KEY = %s\nIV = %s\n",KEY,IV);
		printf("\n-------------------------------\n");	
	}

	err = SSL_write (ssl, "Authenticated.", strlen("Authenticated."));  CHK_SSL(err);

	/* Clean up. */

	close (sd);
	SSL_free (ssl);
	SSL_CTX_free (ctx);
}

void usage() {
        fprintf(stderr, "Usage: minivp [-s|-c <server_physical_machine_IP>|-v]\n");
	fprintf(stderr, "-v produces verbose debugging statements\n");
     	fprintf(stderr, "-t <test number> runs the test corresponding to the test number\n");
	fprintf(stderr, "-c runs the program as client and connects to the server with the IP mentioned on the command line\n");
	exit(1);
}

void append_hash(char *outbuf,int outbuf_len,char *encrypted_buf, int encrypted_buf_len,
		unsigned char *digest, int digest_len) {
	int i;
	// copy the ciphertext in the outbuf
	for (i=0;i<encrypted_buf_len;i++) {
		outbuf[i] = encrypted_buf[i];
	}
	// append the hash to the outbuf
	i=encrypted_buf_len;
	int j;
	for (j=0;j<digest_len;j++) {
		outbuf[i] = digest[j];
		i++;
	}
	// printing the two thigns now
	if (verbose_debug == 1) {
		printf("Appended packet with ciphertext and hash:\n");
		for (i=0;i<outbuf_len;i++) {
			printf("%02x",(unsigned char)outbuf[i]);
		}
		printf("\n");
	}
}

/* alters the first byte/character of the digest to check that the 
packet is dropped if hashes do not match */
void change_received_hash(unsigned char* digest, int digest_len) {
	digest[0] = (digest[0] + 1) % 127;
}

void extract_ciphertext_and_hash(char *buf, int buf_len,char *ciphertext, int ciphertext_len, 
		unsigned char* digest, int digest_len) {

			int i,j;
			j=0;
			for (i=0;i<ciphertext_len;i++) {
				ciphertext[j] = buf[i];
				j++;
			}
			j=0;
			for (i=(buf_len-digest_len);i<buf_len;i++) {
				digest[j] = buf[i];
				j++;		
			}
			if (testnum==5 || verbose_debug == 1) {
				printf("\n-------------------------------\n");	
				printf("Extracting ciphertext and message digest from the following data:\n");
				for (i=0;i<buf_len;i++)
					printf("%02x",(unsigned char)buf[i]);
				printf("\n");								
				printf("The extracted ciphertext is:\n");
				for (i=0;i<ciphertext_len;i++) {
					printf("%02x",(unsigned char)ciphertext[i]);
				}
				printf("\n");
				printf("The extracted hash value is:\n");
				for (i=0;i<digest_len;i++) {
					printf("%02x", (unsigned char)digest[i]);	
				}
				printf("\n");
				printf("-------------------------------\n");	
			}
}

/* BEGIN: TUN/TAP FUNCTIONS */

/**************************************************************************
 * do_debug: prints debugging stuff                                       *
 **************************************************************************/
void do_debug(char *msg, ...){

  va_list argp;

  if(debug){
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;

  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {
  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);
  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){

  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

int cread_udp(int fd, char *buf, int n,struct sockaddr *remote, int *remote_len){

  int nread;

  if((nread=recvfrom(fd, buf, n,0,remote, remote_len))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){

  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

int cwrite_udp(int fd, char *buf, int n,struct sockaddr *remote, int *remote_len){

  int nwrite;

  if((nwrite=sendto(fd, buf, n,0,remote,*remote_len))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;
}

int read_n_udp(int fd, char *buf, int n,struct sockaddr *remote, int *remote_len) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread_udp(fd, buf, left,remote,remote_len))==0){
      return 0 ;
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;
}

/* main udp tunnel function to initiate and transfer data on the tunnel*/
void run_udp_tunnel(char *ifname, unsigned char *iv, unsigned char *key) {
	int tap_fd;
	int flags = IFF_TUN;
	int header_len = IP_HDR_LEN;
	int maxfd;
	uint16_t nread, nwrite, plength;
	char buffer[BUFSIZE];
	struct sockaddr_in local, remote;
	char remote_ip[16] = "";
	int sock_fd, net_fd, optval = 1;
	socklen_t remotelen;
	unsigned long int tap2net = 0, net2tap = 0;

	/* initialize tun/tap interface */
	if ( (tap_fd = tun_alloc(ifname, flags | IFF_NO_PI)) < 0 ) {
		my_err("Error connecting to tun/tap interface %s!\n", ifname);
		exit(1);
	}
	do_debug("Successfully connected to interface %s\n", ifname);
	
	if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket()");
		exit(1);
	}

	/* Change second argument as follows:
	If the local machine is the client gateway (GatewayA) then it must
	be running on MC03 => second argument should be of server machine
	(GatewayB) => MC02_IP

	If the local machine is the server (GatewayB) then it must be 
	running o MC02 => the second argument shoud be of the client 
	machine (GatwayA) => MC03_IP
	 */
	strncpy(remote_ip,MC02_IP,15);
	
	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = inet_addr(remote_ip);
	remote.sin_port = htons(UDP_TUN_PORT);

	if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
		perror("setsockopt()");
		exit(1);
	}


	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_port = htons(UDP_TUN_PORT);
	if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
		perror("bind()");
		exit(1);
	}

	net_fd = sock_fd;

	do_debug("Tunnel ready...\n");

	maxfd = (tap_fd > net_fd) ? tap_fd:net_fd;

	while (1) {
		int ret;
		fd_set rd_set;

		FD_ZERO(&rd_set);
		FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

		ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

		if (ret < 0 && errno == EINTR){
			continue;
		}

		if (ret < 0) {
			perror("select()");
			exit(1);
		}

		if(FD_ISSET(tap_fd,&rd_set)) {
			/* data from the tun/tap virtual interface (inner network): read, encrypt, write to
				network */		
			printf("\n*******************************\n");	
			printf("Got a packet from the tun/tap virtual interface.\n");

			nread = cread(tap_fd, buffer, BUFSIZE);

			char outbuf2[BUFSIZE + EVP_MAX_BLOCK_LENGTH];
			int outbuflen2;
			if(encrypt_decrypt_data(buffer,nread,outbuf2,&outbuflen2,key,iv,1) < 0) {
				printf("encryption failed\n");	
				exit(1);
			} else {
				if (testnum==5 || verbose_debug == 1) {
					int i;
					printf("Printing the plaintext:\n");
					for (i=0;i<nread;i++) {
						printf("%02x", (unsigned char)buffer[i]);	
					}
					printf("\n");
					printf("Printing the Ciphertext:\n");
					for (i=0;i<outbuflen2;i++) {
						printf("%02x", (unsigned char)outbuf2[i]);	
					}
					printf("\n");
				}
			}

			/* after encryption, take the hash of the cipher text and append it to the packet: Encrypt then Authenticate
				scheme*/
			int digestbuflen = 32;
			unsigned char digestbuf[digestbuflen];			
			hash_data( (unsigned char *)outbuf2,outbuflen2,digestbuf,&digestbuflen,key);
			
			if (testnum==6 || verbose_debug == 1) {
				printf("Printing the message digest of the ciphertext:\n");
				print_hashed_data(digestbuf,digestbuflen);	
			}

			int eta_buf_len = outbuflen2 + digestbuflen;
			char eta_buf[eta_buf_len];
			append_hash(eta_buf,eta_buf_len,outbuf2,outbuflen2,digestbuf,digestbuflen);
			
			if (testnum==5 || testnum==6 || verbose_debug==1) {
				printf("Printing the combined message to be sent over the wire in the format CIPHERTEXT||HASH(CIPHERTEXT) \n");
				print_hashed_data((unsigned char*) eta_buf,eta_buf_len);
			}

			tap2net++;

			do_debug("[TAP2NET %lu: Read %d bytes from the tap interface]\n", tap2net, nread);

			/* write length + packet */
			plength = htons(eta_buf_len);
			remotelen = sizeof(remote);

			nwrite = cwrite_udp(net_fd, (char *)&plength, sizeof(plength),(struct sockaddr*)&remote, &remotelen);
			nwrite = cwrite_udp(net_fd, eta_buf, eta_buf_len,(struct sockaddr*)&remote, &remotelen);

			do_debug("[TAP2NET %lu: Written %d bytes to the network]\n", tap2net, nwrite);
		
			printf("\n*******************************\n");	
		}

		if(FD_ISSET(net_fd, &rd_set)){
			/* data from the network: read it, and write it to the tun/tap interface. 
			 * We need to read the length first, and then the packet */
			printf("\n*******************************\n");	
			printf("Got a packet from the network.\n");

			/* Read length */
			remotelen = sizeof(remote);
			nread = read_n_udp(net_fd, (char *)&plength, sizeof(plength),(struct sockaddr*)&remote, &remotelen);
			if(nread == 0) {
				/* ctrl-c at the other end */
				break;
			}

			net2tap++;

			/* read packet */
			nread = read_n_udp(net_fd, buffer, ntohs(plength),(struct sockaddr*)&remote, &remotelen);

			/* before decrypting the packet, must separate the encrypted data from the hash! */
			int digestbuflen = 32;
			int ciphertext_len = ntohs(plength)-digestbuflen;
			unsigned char hash_value[digestbuflen];			
			char ciphertext[ciphertext_len];			
		
			extract_ciphertext_and_hash(buffer,ntohs(plength),ciphertext,ciphertext_len,hash_value,digestbuflen);

			/* after separating the message digest, verify that it is correct -> message integrity check*/
			unsigned char digestbuf[digestbuflen];			
			hash_data((unsigned char*) ciphertext,ciphertext_len,digestbuf,&digestbuflen,KEY);
			
			if (testnum==5 || testnum==6 || verbose_debug == 1) {			
				printf("Received the following hash for the received ciphertext:\n");
				print_hashed_data(hash_value,digestbuflen);
				printf("Computed the following hash for the received ciphertext:\n");
				print_hashed_data(digestbuf,digestbuflen);
			}

			/* testing for if the packet is dropped if the hash values do not match: */
			if (testnum == 1) {
				void change_received_hash(unsigned char* hash_val, int buflen);
				change_received_hash(hash_value,digestbuflen);
			}

			int messageMatched = 1;
			if (strncmp(digestbuf,hash_value,digestbuflen) != 0) {
				printf("The recieved hash value is different from the computed hash value for the recieved ciphertext => drop packet!\n");
				messageMatched = 0;
			} else {
				if (testnum==6 || verbose_debug==1)
					printf("The hash value received and the one calculated match => integrity verified!\n");
			}

			if (messageMatched == 1) {

				char outbuf2[BUFSIZE + EVP_MAX_BLOCK_LENGTH];
				int outbuflen2;	
				if(encrypt_decrypt_data(ciphertext,ciphertext_len,outbuf2,&outbuflen2,key,iv,0) < 0) {
					printf("decryption failed\n");	
					exit(1);
				} else {
					if (testnum==5 || verbose_debug == 1) {
						//printf("[Verbose] Length of the decrypted data is: %d\n",outbuflen2);
						printf("Decrypting the received ciphertext...\n");
						int i;
						printf("The received ciphertext is:\n");
						for (i=0;i<ciphertext_len;i++) {
							printf("%02x", (unsigned char)ciphertext[i]);	
						}
						printf("\n");
						printf("The corresponding plaintext is:\n");
						for (i=0;i<outbuflen2;i++) {
							printf("%02x", (unsigned char)outbuf2[i]);	
						}
						printf("\n");
					}
				}

				do_debug("[NET2TAP %lu: Read %d bytes from the network]\n", net2tap, nread);

				nwrite = cwrite(tap_fd, outbuf2, outbuflen2);
				do_debug("[NET2TAP %lu: Written %d bytes to the tap interface]\n", net2tap, nwrite);
			} else {
				do_debug("[HASH DID NO MATCH. DROPPED THE PACKET.]\n");
			}
			printf("\n*******************************\n");	
		}
	}
}

/* END: TUN/TAP FUNCTIONS  */

int main(int argc, char *argv[]) {
	int tap_fd, option;
	int flags = IFF_TUN;
	char if_name[IFNAMSIZ] = "tun0";
	int header_len = IP_HDR_LEN;
	int maxfd;
	uint16_t nread, nwrite, plength;
	char buffer[BUFSIZE];
	struct sockaddr_in local, remote;
	char remote_ip[16] = "";
	unsigned short int ssl_port = SSL_PORT;
	int sock_fd, net_fd, optval = 1;
	socklen_t remotelen;
	int cliserv = -1;    /* must be specified on cmd line */
	unsigned long int tap2net = 0, net2tap = 0;

	progname = argv[0];

	/* Check command line options */
	while((option = getopt(argc, argv, "hsvc:t:")) > 0){
		switch(option) {
			case 'h':
				usage();
				break;
			case 's':
				cliserv = SERVER;
				break;
			case 'c':
				cliserv = CLIENT;
				strncpy(remote_ip,optarg,15);
				break;
			case 'v':
				verbose_debug = 1;
				break;
			case 't':
				testnum = atoi(optarg);
				break;
			default:
				my_err("Unknown option entered\n", option);
				usage();
		}
	}

	// if after reading through the command line the client/server param has not been set then print options and exit the program
	if (cliserv == -1)
		usage();

	// now that the program knows whether to act as a client or a server, we start the authentication process and key exchange
	if(cliserv==CLIENT) {
		do_client_key_exchange(remote_ip);
	} else {
		do_server_key_exchange();
	}

	printf("Keys and IV have been exchanged. Launching the tunnel now..\n");
	
	run_udp_tunnel(if_name,IV,KEY);

	printf("%s","\n\nDone\n\n");
	return 1;
} 

