/*
 * tracepath.c
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

/**
 Modified by John-Michael Reed for the purpose of getting NAT divergence point - 
 * The point at which a series of outbound packets bound for different destination addresses diverges.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/errqueue.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
//#include <resolv.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <getopt.h> 

#ifndef IP_PMTUDISC_PROBE
#define IP_PMTUDISC_PROBE	3
#endif

struct Header_History {
    int num_hops; // ttl of the sent packet (the number of hops it made before being dropped)
    struct timeval sendtime; // time at which a packet was sent (immediately prior sending)
};

struct Header_History history[64];

// This is the index in the array of histories. It goes from zero to 63, then loops around.
int history_pointer;

struct sockaddr_in target_host; // for host whose nat we would like to penetrate.
struct sockaddr_in target_alt1; // for first alternate ip
struct sockaddr_in target_alt2; // for second alternat ip

const __u16 base_port = 44444;

const int overhead = 28; // size of Probe_Header = 24, then add 4.
const int packet_size = 50;

// This stores all the Round-Trip-Times for all the probe packets.
int round_trip_times_in_micro_s[64][3];

struct Probe_Header {
    __u32 ttl;
    struct timeval time_value;
};
struct Probe_Header *packet_buffer_target;
struct Probe_Header *packet_buffer_alt1;
struct Probe_Header *packet_buffer_alt2;

int hops_to_destination = -11; // Not -1 because if you trace to localhost, hops can be decremented to -1.

void clear_socket_error_queue(const int socket_fd) {
    //fprintf(stderr, "Emptying queue. \n");
    msghdr message_header;
    recvmsg(socket_fd, &message_header, MSG_ERRQUEUE); // This receives a message from the error queue
    recvmsg(socket_fd, &message_header, MSG_ERRQUEUE);
    recvmsg(socket_fd, &message_header, MSG_ERRQUEUE);
}

const int FAILURE_TO_RECEIVE = -1;

int receive_error_packet(const int socket_fd, const int ttl, int index); // forward declaration.

const int INT_MAX = 2147483647;
const int DONE = INT_MAX;
const int NOT_DONE = -2147483648; // min int.

const int default_datency_ms = 500;
const int default_latency_micro_s = 500000;

timeval calculate_ideal_wait_time(const int ttl, int index) {

    // get the max real round trip time in micro seconds.
    long max_RTT_micro_s = 0;
    for (int i = 0; i <= ttl; ++i) {
        for (int j = 0; j < 3; ++j) {
            if (round_trip_times_in_micro_s[i][j] > max_RTT_micro_s) {
                max_RTT_micro_s = round_trip_times_in_micro_s[i][j];
            }
        }
    }
    fprintf(stderr, "\nMax wait time recorded in s^-6 = %ld. \n", max_RTT_micro_s);
    if (max_RTT_micro_s == 0) {
        struct timeval time_value;
        time_value.tv_sec = 0;
        time_value.tv_usec = default_latency_micro_s;
        fprintf(stderr, "\n Waiting default amount: %d \n", default_latency_micro_s);
        return time_value;
    } else if ((ttl == 0) || (ttl == 1) || (ttl == 2)) {
        // We need more time to collect RTT data.
        struct timeval time_value;
        time_value.tv_sec = 0;
        // return either the default wait or the max wait, whichever is bigger.
        time_value.tv_usec = max_RTT_micro_s > default_latency_micro_s ? max_RTT_micro_s : default_latency_micro_s;
        fprintf(stderr, "\n Low ttl Max wait time in s^-6 = %ld. \n", time_value.tv_usec);
        return time_value;

    } else {
        long max_wait_time_micro_s = max_RTT_micro_s;
        if (max_wait_time_micro_s < 20000) {
            max_wait_time_micro_s = 20000;
        }
        if (index == 0) {
            max_wait_time_micro_s = 3 * max_wait_time_micro_s; // Because increasing by 1 hop causes a big jump.
        }
        const long max_wait_time_seconds = max_wait_time_micro_s / 1000000;
        struct timeval time_value;
        time_value.tv_sec = max_wait_time_seconds;
        time_value.tv_usec = max_wait_time_micro_s - (1000000 * max_wait_time_seconds);
        fprintf(stderr, "\nMax wait after data collection = %ld. \n", max_wait_time_micro_s);
        return time_value;
    }

}

/**
 * Waits for up to 2 seconds for some packet to arrive.
 * @param socket_fd - The socket file descriptor that we are waiting on.
 * @return DONE, NOT_DONE, or failureToReceive
 */
int receive_three_packets(const int socket_fd, const int ttl) {
    {
        fd_set socket_set;
        struct timeval time_value = calculate_ideal_wait_time(ttl, 0);
        FD_ZERO(&socket_set); // Initializes the file descriptor set fdset to have zero bits for all file descriptors.
        FD_SET(socket_fd, &socket_set); // Sets the bit for the file descriptor fd in the file descriptor set fdset.
        //time_value.tv_sec = 1;
        //time_value.tv_usec = 0; // micro-seconds

        const int numReadySockets0 = select(socket_fd + 1, &socket_set, NULL, NULL, &time_value); // wait for up to 1 second (for reading).
        if (numReadySockets0 != 1) {
            fprintf(stderr, "Failure to receive packet 1/3. \n");
            return FAILURE_TO_RECEIVE;
        } else {
            fprintf(stderr, "Successfully received packet 1/3. \n");
        }
        const int ret0 = receive_error_packet(socket_fd, ttl, 0);
        if (ret0 == DONE) {
            fprintf(stderr, "Done 1. \n");
            return DONE;
        } else if (ret0 == packet_size) {
            // keep going, not done
        } else {
            fprintf(stderr, "Unexpected receive in place of packet 1. \n");
            exit(0);
        }
    }
    {
        fd_set socket_set;
        struct timeval time_value = calculate_ideal_wait_time(ttl, 1);
        FD_ZERO(&socket_set); // Initializes the file descriptor set fdset to have zero bits for all file descriptors.
        FD_SET(socket_fd, &socket_set); // Sets the bit for the file descriptor fd in the file descriptor set fdset.
        //time_value.tv_sec = 1;
        //time_value.tv_usec = 0; // micro-seconds

        const int numReadySockets1 = select(socket_fd + 1, &socket_set, NULL, NULL, &time_value); // wait for up to 1 second (for reading).
        if (numReadySockets1 != 1) {
            fprintf(stderr, "Failure to receive packet 2/3. \n");
            return FAILURE_TO_RECEIVE;
        }
        const int ret1 = receive_error_packet(socket_fd, ttl, 1);
        if (ret1 == DONE) {
            fprintf(stderr, "Done 2. \n");
            return DONE;
        } else if (ret1 == packet_size) {
            // keep going, not done
        } else {
            fprintf(stderr, "Unexpected receive in place of packet 2. \n");
            exit(1);
        }
    }
    {
        fd_set socket_set;
        struct timeval time_value = calculate_ideal_wait_time(ttl, 2);
        FD_ZERO(&socket_set); // Initializes the file descriptor set fdset to have zero bits for all file descriptors.
        FD_SET(socket_fd, &socket_set); // Sets the bit for the file descriptor fd in the file descriptor set fdset.
        //time_value.tv_sec = 1;
        //time_value.tv_usec = 0; // micro-seconds

        const int numReadySockets2 = select(socket_fd + 1, &socket_set, NULL, NULL, &time_value); // wait for up to 1 second (for reading).
        if (numReadySockets2 != 1) {
            fprintf(stderr, "Failure to receive packet 3/3. \n");
            return FAILURE_TO_RECEIVE;
        }
        const int ret2 = receive_error_packet(socket_fd, ttl, 2);
        if (ret2 == DONE) {
            fprintf(stderr, "Done 3. \n");
            return DONE;
        } else if (ret2 == packet_size) {
            return NOT_DONE;
        } else {
            fprintf(stderr, "Unexpected receive in place of packet 3. \n");
            exit(2);
        }
    }
}

char hopAddresses[64][3][128]; // address stored for each hop en-route to target
in_addr_t hopAddressInts[64][3]; // Those addresses stored as longs.

/**
 * Waits for and receives three error packets. If any of the packets are un-equal
 * in their return address or if any of them do not return, return DONE. Otherwise, return
 * NOT_DONE.
 * @param socket_fd - socket to receive error packet
 * @param ttl - ttl of packet whose error replies are being received
 * @return DONE when destination reached or packet size when destination not reach but error queue emptied.
 */
int receive_error_packet(const int socket_fd, const int ttl, const int index) {
    fprintf(stderr, "Started receive_error_packet with index %d \n", index);
    struct Probe_Header rcvbuf;
    char control_buffer[512];
    struct iovec input_output_vector;
    struct msghdr message;
    struct cmsghdr *control_message;
    struct sock_extended_err *socket_error_message;
    struct sockaddr_in addr;
    struct timeval current_time_value;
    struct timeval *return_time_value;
    int slot;
    int send_hops;

    for (int ind = 0; ind < 999999; ++ind) {
        fprintf(stderr, "Receiving error packet in for loop with loop index: %d. \n", ind);
        memset(&rcvbuf, -1, sizeof (rcvbuf));
        input_output_vector.iov_base = &rcvbuf;
        input_output_vector.iov_len = sizeof (rcvbuf);
        message.msg_name = (__u8*) & addr;
        message.msg_namelen = sizeof (addr);
        message.msg_iov = &input_output_vector;
        message.msg_iovlen = 1;
        message.msg_flags = 0;
        message.msg_control = control_buffer;
        message.msg_controllen = sizeof (control_buffer);

        gettimeofday(&current_time_value, NULL);

        const int messageLength = recvmsg(socket_fd, &message, MSG_ERRQUEUE); // This receives a message from the error queue

        if (messageLength < 0) {
            if (errno == EAGAIN) { // EAGAIN = "there is no data available right now, try again later". (non-blocking io)
                fprintf(stderr, "In receive_error_packet, there is no longer data available in the error queue. \n");
                fprintf(stderr, "That is impossible. I just finished waiting (selecting) on data.");
                exit(1);
            } else {
                fprintf(stderr, "Only EAGAIN errors are supposed to come in on recvmsg. \n");
                exit(7);
                continue; // try again.
            }
        } else {
            fprintf(stderr, "Index %d: received an error message packet of length: %d \n", index, messageLength); // first time around
        }

        send_hops = -1;
        socket_error_message = NULL;
        return_time_value = NULL; // 0
        slot = ntohs(addr.sin_port) - base_port; // network to host byte order short
        if (slot >= 0 && slot < 63 && history[slot].num_hops) {
            fprintf(stderr, "history[slot].num_hops is assigned to %d. \n", history[slot].num_hops); // goes 1, 2, 3, etc.
            send_hops = history[slot].num_hops;
            return_time_value = &history[slot].sendtime;
            //history[slot].num_hops = 0; // this zeros it out for the other two packets.
        } else {
            fprintf(stderr, "history[slot].num_hops is %d \n", history[slot].num_hops); // history[slot] is 0.
        }

        if (messageLength == sizeof (rcvbuf)) {
            if (rcvbuf.ttl == 0 || rcvbuf.time_value.tv_sec == 0) {
                fprintf(stderr, "The router must be broken because the packet data is corrupted. Invalid ttl/timestamp. \n");
            } else {
                fprintf(stderr, "Assigning something to return_time_value. \n");
                send_hops = rcvbuf.ttl;
                return_time_value = &rcvbuf.time_value;
            }
        } else {
            fprintf(stderr, "messageLength != sizeof (rcvbuf) \n");
        }

        for (control_message = CMSG_FIRSTHDR(&message); control_message; control_message = CMSG_NXTHDR(&message, control_message)) {
            if (control_message->cmsg_level == SOL_IP) {
                if (control_message->cmsg_type == IP_RECVERR) {
                    socket_error_message = (struct sock_extended_err *) CMSG_DATA(control_message);
                } else if (control_message->cmsg_type == IP_TTL) {
                    // We're not using this
                } else {
                    //fprintf(stderr, "cmsg:%d\n ", control_message->cmsg_type);
                }
            }
        }
        if (socket_error_message == NULL) {
            fprintf(stderr, "no info. socket_error_message is null. \n");
            exit(1);
            return 0;
        }
        if (socket_error_message->ee_origin == SO_EE_ORIGIN_LOCAL) {
            //fprintf(stderr, "Received message of origin localhost. \n");
        } else if (socket_error_message->ee_origin == SO_EE_ORIGIN_ICMP) {
            //fprintf(stderr, "Received message of origin ICMP. \n");
            struct sockaddr_in *addr_in = (struct sockaddr_in*) (socket_error_message + 1);
            //fprintf(stderr, "Received raw address: %d at index %d. \n", addr_in->sin_addr.s_addr, index);

            hopAddressInts[ttl][index] = addr_in->sin_addr.s_addr;

            inet_ntop(AF_INET, &addr_in->sin_addr, hopAddresses[ttl][index], sizeof (hopAddresses[ttl][index])); // convert IPv4 and IPv6 addresses from binary to text form

            if (send_hops > 0) {
                //fprintf(stderr, "Hops:%d    ", send_hops);
            } else {
                //fprintf(stderr, "TTL:%d    ", ttl);
            }
            //fprintf(stderr, "Address:%s    as int: %d", hopAddresses[ttl][index], hopAddressInts[ttl][index]);
        }

        if (return_time_value) { // This gets the RTT
            int diff = (current_time_value.tv_sec - return_time_value->tv_sec)*1000000 + (current_time_value.tv_usec - return_time_value->tv_usec);
            // diff = RTT in seconds^6. Dividing by 1000 gives seconds^3 (ms)
            fprintf(stderr, "RTT: %3d.%03d ms \n", diff / 1000, diff % 1000); // This appears to be what prints the RTT in ms. 3 decimal places.
            round_trip_times_in_micro_s[ttl][index] = diff;
        }

        fprintf(stderr, "\nEntering big switch statement of errors. \n");
        switch (socket_error_message->ee_errno) {
            case ETIMEDOUT:
                fprintf(stderr, "Error message is a timeout error. This was not supposed to happen. \n");
                exit(1);
                break;
            case EMSGSIZE:
                fprintf(stderr, "UDP packet write exceeds Maximum Transmission Unit for this target IP address. Exceeded message size error. \n");
                fprintf(stderr, "This should be impossible because the packet size is only %d bytes. \n", packet_size);
                exit(1); // impossible scenario that should never, ever occur unless something is wrong with the OS.
                break;
            case ECONNREFUSED:
                //fprintf(stderr, "Connection refused error. \n");
                fprintf(stderr, "Destination reached. \n\n");
                hops_to_destination = send_hops < 0 ? ttl : send_hops; // DONE.
                // Assuming that the destination you reached is your target (NAT traversal) destination.
                return DONE;
            case EPROTO:
                fprintf(stderr, "!P\n E protocol error. This was not supposed to happen. \n");
                exit(1);
                return 0;
            case EHOSTUNREACH:
                fprintf(stderr, "Error. Host unreachable --> TTL expired. \n");
                if (socket_error_message->ee_origin == SO_EE_ORIGIN_ICMP &&
                        socket_error_message->ee_type == 11 &&
                        socket_error_message->ee_code == 0) {
                    //fprintf(stderr, "\n");
                    if (index == 2) {

                        memset(&rcvbuf, -1, sizeof (rcvbuf));
                        input_output_vector.iov_base = &rcvbuf;
                        input_output_vector.iov_len = sizeof (rcvbuf);
                        message.msg_name = (__u8*) & addr;
                        message.msg_namelen = sizeof (addr);
                        message.msg_iov = &input_output_vector;
                        message.msg_iovlen = 1;
                        message.msg_flags = 0;
                        message.msg_control = control_buffer;
                        message.msg_controllen = sizeof (control_buffer);

                        gettimeofday(&current_time_value, NULL);

                        const int messageLength2 = recvmsg(socket_fd, &message, MSG_ERRQUEUE); // This receives a message from the error queue
                        if (messageLength2 < 0) {
                            //fprintf(stderr, "The message que is empty after 3 packets. \n");
                            if (errno == EAGAIN) {
                                fprintf(stderr, "The message queue is empty after 3 packets. \n");
                            } else {
                                fprintf(stderr, "Fail. The message que is not really empty after 3 packets. \n");
                                fprintf(stderr, "Errno: %s\n", strerror(errno));
                                exit(1);
                            }
                        } else {
                            fprintf(stderr, "Bad. The message que is not empty after 3 packets. \n");
                            exit(-1);
                        }
                    }
                    return packet_size;
                } else {
                    fprintf(stderr, "I was not expecting this sort of packet. Error. \n");
                    exit(1);
                }
            case ENETUNREACH:
                fprintf(stderr, "Internet unreachable error. Maybe you don't have internet. \n");
                fprintf(stderr, "!N\n");
                exit(1);
                return 0;
            case EACCES:
                fprintf(stderr, "Internet access error. Maybe you don't have access privileges to bind to a port or use internet. \n");
                fprintf(stderr, "!A\n");
                exit(1);
                return 0;
            default:
                fprintf(stderr, "Some other error message was picked up. Value: %d \n", socket_error_message->ee_errno);
                errno = socket_error_message->ee_errno;
                fprintf(stderr, "NET ERROR. errno: %s \n", strerror(errno));
                exit(1);
                return 0;
        }
    }
    const int impossible = -9999999;
    return impossible;
}

const int FAILURE_TO_SEND_PACKET = -2;

/**
 * Sends a probe packet that has the given time-to-live.
 * @param socket_fd - socket to send out probe packet
 * @param ttl - time to live of probe packet
 * @return -2 on failure to send short-ttl probe, FAILURE_TO_RECEIVE if failed to receive ICMP reply, 
 * DONE on done (reached destination), or ret>=0 corresponding to ICMP error packet length. 
 */
int send_probe_with_ttl(const int socket_fd, const int ttl) {
    struct Probe_Header *header = packet_buffer_target;
    struct Probe_Header *header1 = packet_buffer_alt1;
    struct Probe_Header *header2 = packet_buffer_alt2;

    memset(packet_buffer_target, 0, packet_size);
    memset(packet_buffer_alt1, 0, packet_size);
    memset(packet_buffer_alt2, 0, packet_size);

    target_host.sin_port = htons(base_port + history_pointer);
    target_alt1.sin_port = htons(base_port + history_pointer);
    target_alt2.sin_port = htons(base_port + history_pointer);

    header->ttl = ttl; // puts the ttl into the header
    header1->ttl = ttl;
    header2->ttl = ttl;

    gettimeofday(&header->time_value, NULL); // puts the time value into the header.
    gettimeofday(&header1->time_value, NULL);
    gettimeofday(&header2->time_value, NULL);

    history[history_pointer].num_hops = ttl; // Note the histories are shared for all three sockets. 3 sockets get 1 history.
    history[history_pointer].sendtime = header->time_value; // puts the time value into the shared history entry.

    clear_socket_error_queue(socket_fd); // Make sure there is nothing in the queue before sending out new stuff.

    //fprintf(stderr, "\n");

    if (target_alt1.sin_addr.s_addr == target_alt2.sin_addr.s_addr) {
        fprintf(stderr, "Each is supposed to have their own address \n");
        exit(3);
    }

    // send to all three targets consecutively
    int numBytesSent = sendto(socket_fd, packet_buffer_target, packet_size - overhead, 0, (struct sockaddr*) &target_host, sizeof (target_host));
    if ((numBytesSent < 0)) {
        fprintf(stderr, "A failure to send occurred while TTL == %d. \n", ttl);
        fprintf(stderr, "Error number: %s \n", strerror(errno));
        return FAILURE_TO_SEND_PACKET; // failed to probe ttl.
    } else {
        fprintf(stderr, "Sent %d byte(s) to %u with ttl of %d. \n", numBytesSent, target_host.sin_addr.s_addr, ttl);
    }

    numBytesSent = sendto(socket_fd, packet_buffer_alt1, packet_size - overhead, 0, (struct sockaddr*) &target_alt1, sizeof (target_alt1));
    if ((numBytesSent < 0)) {
        fprintf(stderr, "A failure to send occurred while TTL == %d. \n", ttl);
        fprintf(stderr, "Error number: %s \n", strerror(errno));
        return FAILURE_TO_SEND_PACKET; // failed to probe ttl.
    } else {
        fprintf(stderr, "Sent %d byte(s) to %u with ttl of %d. \n", numBytesSent, target_alt1.sin_addr.s_addr, ttl);
    }

    numBytesSent = sendto(socket_fd, packet_buffer_alt2, packet_size - overhead, 0, (struct sockaddr*) &target_alt2, sizeof (target_alt2));
    if ((numBytesSent < 0)) {
        fprintf(stderr, "A failure to send occurred while TTL == %d. \n", ttl);
        fprintf(stderr, "Error number: %s \n", strerror(errno));
        return FAILURE_TO_SEND_PACKET; // failed to probe ttl.
    } else {
        fprintf(stderr, "Sent %d byte(s) to %u with ttl of %d. \n", numBytesSent, target_alt2.sin_addr.s_addr, ttl);
    }
    // phantom bug occasionally occurs after sending 3 times. Returns 0 or ttl. May just be bad printf buffer.
    history_pointer = (history_pointer + 1)&63;

    const int done_notDone_or_failureToReceive = receive_three_packets(socket_fd, ttl); // wait up to 2 seconds for three packets to arrive.
    fprintf(stderr, "Done probing \n");
    return done_notDone_or_failureToReceive;
}

static void usage(void) __attribute((noreturn));

static void usage(void) {
    fprintf(stderr, "Usage: tracepath <destination>\n");
    exit(-1);
}

int hostname_to_ip(const char * hostname, char* ip) {
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
    if ((he = gethostbyname(hostname)) == NULL) {
        // get the host info
        herror("gethostbyname");
        return 1;
    }
    addr_list = (struct in_addr **) he->h_addr_list;
    for (i = 0; addr_list[i] != NULL; i++) {
        //Return the first one;
        strcpy(ip, inet_ntoa(*addr_list[i]));
        return 0;
    }
    return 1;
}

//char ip[128];
const char * localhost = "localhost";

int
main(int argc, char **argv) {
    //setvbuf(stdout, NULL, _IONBF, 0); // auto flushing.

    if (argc != 2) {
        usage();
    }
    const int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (socket_fd < 0) {
        fprintf(stderr, "Socket error. Error number: %s\n", strerror(errno));
        exit(1);
    }

    target_host.sin_family = AF_INET;
    target_alt1.sin_family = AF_INET;
    target_alt2.sin_family = AF_INET;

    //char original_hostname[128];
    //strcpy(original_hostname, argv[1]);
    //char * target_hostname = argv[1];
    char * target_hostname = (char *) "53.53.53.53";
    char * alternate_ip_1_local = (char *) "144.133.133.133"; // IP for somewhere in Australia.
    char * alternate_ip_2_local = (char *) "202.202.202.202"; // IP for international university in China

    //fprintf(stderr, "The target ip is: %s port #%d \n", target_hostname, base_port);
    //fprintf(stderr, "The first alternate ip is: %s port #%d \n", alternate_ip_1_local, base_port);
    //fprintf(stderr, "The second alternate ip is: %s port #%d \n", alternate_ip_2_local, base_port);

    ///hostname_to_ip(target_hostname, ip);
    //fprintf(stderr, "%s was resolved to %s. \n", original_hostname, ip);
    target_host.sin_addr.s_addr = inet_addr(target_hostname); //inet_addr(ip);
    target_alt1.sin_addr.s_addr = inet_addr(alternate_ip_1_local);
    target_alt2.sin_addr.s_addr = inet_addr(alternate_ip_2_local);

    //fprintf(stderr, "Decimals: %u\n", target_host.sin_addr.s_addr);
    //fprintf(stderr, "Decimals: %u\n", target_alt1.sin_addr.s_addr);
    //fprintf(stderr, "Decimals: %u\n", target_alt2.sin_addr.s_addr);

    const int option_flag = 1;
    if (setsockopt(socket_fd, SOL_IP, IP_RECVERR, &option_flag, sizeof (option_flag))) {
        perror("IP_RECVERR");
        exit(1);
    }

    packet_buffer_target = (struct Probe_Header *) malloc(packet_size);
    packet_buffer_alt1 = (struct Probe_Header *) malloc(packet_size);
    packet_buffer_alt2 = (struct Probe_Header *) malloc(packet_size);

    if (!packet_buffer_target || !packet_buffer_alt1 || !packet_buffer_alt2) {
        perror("malloc");
        exit(1);
    }

    static int numNoReplies = 0;
    strcpy(hopAddresses[0][0], localhost); // just because "localhost" would be missing otherwise.
    for (int ttl = 1; ttl < 32; ttl++) {
        fprintf(stderr, "Starting ttl loop: %d \n", ttl);
        if (setsockopt(socket_fd, SOL_IP, IP_TTL, &ttl, sizeof (ttl))) {
            perror("IP_TTL");
            exit(1);
        }

        //for (int i = 0; i < 3; i++) {
        int done_notDone_or_failureToReceive = send_probe_with_ttl(socket_fd, ttl);
        if (done_notDone_or_failureToReceive == FAILURE_TO_SEND_PACKET) {
            fprintf(stderr, "Something is really wrong. You are nor able to send packets to probe with. \n");
            exit(1);
        }
        //fprintf(stderr, "\n");
        if (done_notDone_or_failureToReceive == DONE) {
            for (int i = 0; i < ttl; ++i) {
                fprintf(stderr, "Hop %d: %s \n", i, hopAddresses[i][0]);
            }
            fprintf(stderr, "Hop %d: %s , %s , %s \n", ttl, hopAddresses[ttl][0], hopAddresses[ttl][1], hopAddresses[ttl][2]);
            fprintf(stderr, "Hops to reach destination: %d. \n", ttl);
            return ttl;

            return hops_to_destination;
        } else if (done_notDone_or_failureToReceive == NOT_DONE) {
            if (hopAddressInts[ttl][0] != hopAddressInts[ttl][1]) {
                //fprintf(stderr, "At least one ip inequality \n");
                if (hopAddressInts[ttl][1] != hopAddressInts[ttl][2]) {

                    if ((hopAddresses[ttl][0][0] == '1') && (hopAddresses[ttl][0][1] == '0')
                            && (hopAddresses[ttl][0][2] == '.')) {
                        fprintf(stderr, "The address starts with 10. , you're still under NAT. \n");
                        continue;
                    } else {
                        if (hopAddresses[ttl][0][0] == hopAddresses[ttl][1][0]
                                || hopAddresses[ttl][0][0] == hopAddresses[ttl][2][0]) {
                            if (hopAddresses[ttl][0][1] == hopAddresses[ttl][1][1]
                                    || hopAddresses[ttl][0][1] == hopAddresses[ttl][2][1]) {
                                fprintf(stderr, "The addresses start with the same two numbers. You may still be under one network (Ex. T-mobile). \n");
                                continue;
                            }
                        }
                    }
                    //fprintf(stderr, "At least two ip inequality. \n");
                    for (int i = 0; i < ttl; ++i) {
                        fprintf(stderr, "Hop %d: %s \n", i, hopAddresses[i][0]);
                    }
                    fprintf(stderr, "Hop %d: %s , %s , %s \n", ttl, hopAddresses[ttl][0], hopAddresses[ttl][1], hopAddresses[ttl][2]);
                    fprintf(stderr, "Hops to reach open internet: %d. \n", ttl);
                    return ttl;
                } else {
                    //fprintf(stderr, "Two of the three addresses differ.");
                }
            } else {
                //fprintf(stderr, "Keep going. Open internet not yet reached\n");
            }
            continue; // goes to next ttl. Set to "break" if exiting from making multiple tries.
        } else if (done_notDone_or_failureToReceive == FAILURE_TO_RECEIVE) {
            fprintf(stderr, "No reply received.\n");
            ++numNoReplies;
            //fprintf(stderr, "Failed to receive a triple reply %d times. \n", numNoReplies);
            if (numNoReplies > 4) {
                //fprintf(stderr, "This isn't working. Stop here. \n\n");
                for (int i = 0; i < ttl; ++i) {
                    fprintf(stderr, "Hop %d: %s \n", i, hopAddresses[i][0]);
                }
                fprintf(stderr, "Estimated # hops to reach open internet (given lack of reply): %d. \n", ttl - 1); // because ttl is unreachable
                exit(0);
            } else {
                fprintf(stderr, "Num no replies = 1 or 2 \n");
            }
            // --ttl; // We want to re-do this ttl. Fill in the missing table entries.
            continue; // try again.
        } else {
            fprintf(stderr, "Invalid return value from function probe_with_ttl.");
            exit(66);
        }
        //}
    }
    fprintf(stderr, "Apparently you are either behind more than 32 layers of NAT/ISP or there is a massive bug. \n");
    exit(0);
}
