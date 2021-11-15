.PHONY: receiver sender
all: receiver sender
receiver:
	g++ receiver.cpp -o receiver -lcrypto
sender:
	g++ sender.cpp -o sender -lcrypto