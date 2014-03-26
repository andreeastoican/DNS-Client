#include "dns_message.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h> 
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PORT	53
#define BUFLEN  1024
#define TIMEOUT  3

// functie ce preia un domeniu din raspunsul de la server

int getDomain(int no, char* domain_rr, unsigned char* buffer) {
    int no_domain = no;
    int NO = 49152;
    int no_domain_rr = 0;
    int jump = 0;
    int n;
    while (buffer[no_domain] != 0) {

        if (buffer[no_domain] < 192) {

            n = buffer[no_domain];
            memcpy(domain_rr + no_domain_rr, buffer + no_domain + 1, n);
            no_domain_rr += n;
            domain_rr[no_domain_rr++] = '.';
            no_domain += n + 1;

            if (jump == 0) {
                no += n + 1;
            }

        } else {
            if (jump == 0) {
                no += 2;
                jump = 1;
            }

            no_domain = buffer[no_domain]*256 + buffer[no_domain + 1] - NO;
        }
    }
    if (jump == 0) no = no + 1;
    domain_rr[no_domain_rr] = 0;
    return no;
}

int main(int argc, char *argv[]) {
    int sockfd, ind = 0;
    char* domain_name, domain_name_copy[128];
    FILE * file, *file_out;
    char ip[128], tip_interogare[50];
    unsigned char buffer[BUFLEN];
    struct sockaddr_in addr;
    socklen_t len;
    dns_header_t header;
    dns_question_t question;
    dns_rr_t rr;
    unsigned short id = (unsigned short) htons(getpid());
    char ipr[128];
    unsigned char d[200];
    struct timeval tv;
    tv.tv_usec = 0;
    tv.tv_sec = TIMEOUT;

    if (argc < 2) {
        printf("Fromat client : %s nume_domeniu tip_interogare.\n", argv[0]);
        exit(1);
    }

    domain_name = argv[1];
    sprintf(tip_interogare, "%s", argv[2]);

    file = fopen("dns_servers.conf", "r");
    if (file == NULL) {
        printf("Eroare deschidere fisier dns_servers.conf.\n");
        exit(1);
    } else {
        printf("S-a deschis pentru citire fisierul dns_servers.conf.\n");
    }

    file_out = fopen("logfile", "a");
    if (file_out == NULL) {
        printf("Eroare deschidere fisier logfile.\n");
        exit(1);
    } else {
        printf("S-a deschis pentru scriere fisierul logfile.\n");
    }

    char* token;
    int length_domain = strlen(domain_name) + 2;
    char domain[length_domain];
    int length = 0;
    strcpy(domain_name_copy, domain_name);
    // se codifica domeniul punand in fata fiecarei secvente de caractere numarul de caractere din acea secventa
    token = strtok(domain_name_copy, ".");
    while (token != NULL) {
        ind += length;
        length = strlen(token);
        domain[ind] = length;
        sprintf(domain + ind + 1, "%s", token);
        length += 1;
        token = strtok(NULL, ".");
    }
    domain[ind + length] = 0;

    // se creaza structura header
    header.id = id;
    header.rd = 1;
    header.tc = 0;
    header.aa = 0;
    header.opcode = 0;
    header.qr = 0;
    header.rcode = 0;
    header.z = 0;
    header.ra = 0;
    header.qdcount = htons(1);
    header.ancount = htons(0);
    header.nscount = htons(0);
    header.arcount = htons(0);
    id++;

    // se creaza structura question
    question.qclass = htons(1);

    // se adauga tipul interogarii
    if (tip_interogare[0] == 'A') {
        question.qtype = htons(1);
    } else if (strncmp(tip_interogare, "MX", 2) == 0) {
        question.qtype = htons(15);
    } else if (strncmp(tip_interogare, "NS", 2) == 0) {
        question.qtype = htons(2);
    } else if (strncmp(tip_interogare, "CNAME", 5) == 0) {
        question.qtype = htons(5);
    } else if (strncmp(tip_interogare, "SOA", 3) == 0) {
        question.qtype = htons(6);
    } else if (strncmp(tip_interogare, "TXT", 3) == 0) {
        question.qtype = htons(16);
    } else {
        printf("Tipul interogarii este incorect.\n");
        exit(1);
    }

    while (!feof(file)) {
        memset(ip, 0, 128);
        memset(ipr, 0, 128);

        // se citeste un ip din fisier
        fgets(ipr, 128, file);

        if (ipr[0] == '#' || ipr[0] == '\n') {
            continue;
        }

        strcpy(ip, strtok(ipr, "\n"));
        sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sockfd < 0) {
            perror("Eroare deschidere socket");
            exit(1);
        }

        addr.sin_family = AF_INET;
        addr.sin_port = htons(PORT);
        addr.sin_addr.s_addr = inet_addr(ip);

        // se creaza mesajul de trimis catre server si se trimite
        memset(buffer, 0, BUFLEN);
        int no = 0;
        memcpy(buffer, &header, sizeof (dns_header_t));
        no = sizeof (header);
        memcpy(buffer + no, domain, length_domain);
        no += length_domain;
        memcpy(buffer + no, &question, sizeof (question));
        no += sizeof (question);

        // se seteaza parametrii pentru timeout pe socketul sockfd
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof (tv));

        int s = sendto(sockfd, buffer, no, 0, ((struct sockaddr*) &addr), sizeof (struct sockaddr_in));
        if (s < 0) {
            printf("Eroare sendto.\n");
            printf("Se alege un alt ip...\n");
            continue;
        } else {
            printf("\nS-a trimis mesajul de tip %s (server ip = %s).\n", tip_interogare, ip);
        }

        // se primeste raspuns de la server
        memset(buffer, 0, BUFLEN);
        int r = recvfrom(sockfd, buffer, BUFLEN, 0, ((struct sockaddr*) &addr), &len);

        if (r < 0) {
            printf("Eroare recvfrom. Se alege un alt ip...\n");
            continue;
        }

        printf("\nS-a primit mesaj de la server.\n");

        // se preiau structurile header si questions dar si domeniul din mesajul primit de la server
        memcpy(&header, buffer, sizeof (dns_header_t));
        memcpy(&domain, buffer + sizeof (dns_header_t), length_domain);
        memcpy(&question, buffer + sizeof (dns_header_t) + length_domain, sizeof (question));

        // se calculeaza numarul total de raspunsuri
        int rr_no = ntohs(header.ancount) + ntohs(header.nscount) + ntohs(header.arcount);
        printf("S-au primit %i raspunsuri.\n", rr_no);
        int rr_no_copy = rr_no;
        char domain_rr[200];

        // se scrie in fisier
        if (rr_no > 0) {
            fprintf(file_out, "; %s - %s %s\n\n", ip, domain_name, tip_interogare);
        }
        if (ntohs(header.ancount) > 0) {
            fprintf(file_out, ";; ANSWER SECTION:\n");
        }

        while (rr_no != 0) {

            memset(domain_rr, 0, 200);
            memset(d, 0, 200);

            no = getDomain(no, domain_rr, buffer);

            memcpy(&rr, buffer + no, 10);

            no += 10;

            memcpy(d, buffer + no, ntohs(rr.rdlength));

            int type = ntohs(rr.type);
            if (type == 1 || type == 2 || type == 5 || type == 15 || type == 6 || type == 16)
                fprintf(file_out, "%s\tIN\t", domain_rr);

            // se scrie in fisier ce se cere in functie de tipul raspunsului
            if (type == 1) {

                fprintf(file_out, "A\t%i.%i.%i.%i\n", d[0], d[1], d[2], d[3]);

            } else if (type == 15) {

                int preference = *(unsigned short*) d;
                char exchange[100];
                getDomain(no + 2, exchange, buffer);
                fprintf(file_out, "MX\t%i\t%s\n", ntohs(preference), exchange);

            } else if (type == 2) {

                char nsdname[100];
                getDomain(no, nsdname, buffer);
                fprintf(file_out, "NS\t%s\n", nsdname);

            } else if (type == 5) {

                char cname[100];
                getDomain(no, cname, buffer);
                fprintf(file_out, "CNAME\t%s\n", cname);

            } else if (type == 6) {

                char mname[100], rname[100];
                unsigned int serial, refresh, retry, expire, minimum;

                int n1 = getDomain(no, mname, buffer);
                n1 = getDomain(n1, rname, buffer);
                serial = *(unsigned int*) (buffer + n1);
                n1 += 4;
                refresh = *(unsigned int *) (buffer + n1);
                n1 += 4;
                retry = *(unsigned int *) (buffer + n1);
                n1 += 4;
                expire = *(unsigned int *) (buffer + n1);
                n1 += 4;
                minimum = *(unsigned int *) (buffer + n1);

                fprintf(file_out, "SOA\t%s\t%s\t%u\t%u\t%u\t%u\t%u\n", mname, rname, ntohl(serial), ntohl(refresh), ntohl(retry), ntohl(expire), ntohl(minimum));

            } else if (type == 16) {

                fprintf(file_out, "TXT\t%s\n", d + 1);
            }

            no += ntohs(rr.rdlength);

            rr_no--;

            if (rr_no == ntohs(header.nscount) + ntohs(header.arcount) && ntohs(header.nscount) > 0) {
                fprintf(file_out, "\n;; AUTHORITY SECTION:\n");
            }

            if (rr_no == ntohs(header.arcount) && ntohs(header.arcount) > 0) {
                fprintf(file_out, "\n;; ADDITIONAL SECTION:\n");
            }

        }
        if (rr_no_copy != 0) {
            fprintf(file_out, "\n");
        }

        break;
    }

    fclose(file);
    fclose(file_out);
    close(sockfd);

    return 0;
}