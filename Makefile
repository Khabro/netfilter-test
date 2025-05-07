all: netfilter-test

netfilter-test: main.cpp
	g++ -o netfilter-test main.cpp -lnetfilter_queue

clean:
	rm -f netfilter-test
