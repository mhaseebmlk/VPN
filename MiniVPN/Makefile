INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	g++ -I$(INC) -L$(LIB) minivpn.c -o minivpn -lssl -lcrypto -ldl -fpermissive -w
clean:
	rm -rf *~ minivpn_client minivpn_server minivpn
