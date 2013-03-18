#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <signal.h>
#include <pcap.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <net/if.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <libutil.h>
#include <Judy.h>

#define DeltaUSec(t1,t2) \
    (   ((double)t1.tv_sec * 1000000.0 + (double)t1.tv_usec) \
      - ((double)t2.tv_sec * 1000000.0 + (double)t2.tv_usec) )

struct key {
    struct in_addr	ip1;
    u_short		port1;
    struct in_addr	ip2;
    u_short		port2;
};

SLIST_HEAD(head_struct, val) vals_head;
struct val {
    struct timeval	timeval;
    u_int32_t		count;

    struct key		*key;
    SLIST_ENTRY(val)	next;
};

Pvoid_t Array = NULL;

int running = 1;

void usage(char *myname)
{
    printf("Usage: %s [-d] [-v] [-P <pidfile>] -i <if> -f <filter> <file>\n\n" \
            "-d - debug mode. Does not daemonize and print to stdout.\n" \
	    "-v - verbose. Write debug info ti debug log file (or stdout if -d specified)\n" \
            "-P - PID file name\n" \
	    "-i - an interface name\n" \
	    "-f - filter rules (see man tcpdump)\n" \
            "file       - file for writting timming info\n\n" \
	    "Example:\n" \
	    "%s -i em0 -f 'port 80 or port 81' tcp-time.log\n\n", myname, myname);
    exit(1);
}

void
sighandler(int i)
{
    running = 0;
}

int
main(int argc, char *argv[])
{
    FILE *f, *f1=NULL;
    int j, bpf, daemonize=1, verbose=0;
    char errbuf[PCAP_ERRBUF_SIZE], time_str[30], time_zone[10];
    char pidfile[100], myname[100], file[100], filename[100];
    char c, interface[10], filter[255], *p;
    pcap_t *cap;
    struct ifreq ifr;
    struct bpf_program fp;
    struct pcap_pkthdr *header;
    const u_char *packet;
    struct ip *ip;
    struct tcphdr *tcp;
    struct key *key;
    struct val *val, *val_temp;
    Word_t *PValue;
    pid_t opid;
    struct pidfh *pfh=NULL;
    time_t now, last_purge;

    p = strrchr(argv[0], '/');
    p++;
    strncpy(myname, p, sizeof(myname)-1);
    pidfile[0] = '\0';
    interface[0] = '\0';
    filter[0] = '\0';
    while((c = getopt(argc, argv, "df:i:P:v")) != -1) {
	switch(c) {
	    case 'd':
		daemonize = 0;
		break;
	    case 'v':
		verbose = 1;
		break;
	    case 'f':
		strcpy(filter, "tcp and ");
		strncat(filter, optarg, sizeof(filter)-9);
		break;
	    case 'i':
		strncpy(interface, optarg, sizeof(interface)-1);
		break;
	    case 'P':
		strncpy(pidfile, optarg, sizeof(pidfile)-1);
		break;
	    default:
		usage(myname);
	}
    }

    argc -= optind;
    argv += optind;

    if(interface[0] == '\0' || filter[0] == '\0')
	usage(myname);

    if(argc == 0)
	if(daemonize)
	    usage(myname);
	else
	    strcpy(filename, "/dev/stdout");
    else
	strncpy(filename, argv[0], sizeof(filename)-1);

    if((f = fopen(filename, "a")) == NULL)
	errx(1, "Can't create file %s", argv[0]);

    if(daemonize) {
	strcpy(filename, "/var/log/");
	strcat(filename, myname);
	strcat(filename, ".debug");
    } else
	strcpy(filename, "/dev/stdout");

    if(verbose)
        if((f1 = fopen(filename, "a")) == NULL)
	    errx(1, "Can't create file %s", filename);

    for (j = 0; j < 255; j++) {
	snprintf(file, sizeof(file), "/dev/bpf%d", j);
	bpf = open(file, O_WRONLY);
	if(bpf != -1 || errno != EBUSY)
	    break;
    }

    bzero(&ifr, sizeof(ifr));
    strlcpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
    if(ioctl(bpf, BIOCSETIF, (char *)&ifr) < 0)
	errx(1, "Can't BIOCSETIF");

    if((cap = pcap_open_live(interface, 1500, 0, 100, errbuf)) == NULL)
	errx(1, "pcap_open_live(%s): %s", interface, errbuf);
    if(pcap_compile(cap, &fp, filter, 0, 0) < 0)
	errx(1, "pcap_compile");
    if(pcap_setfilter(cap, &fp) < 0)
	errx(1, "pcap_setfilter");

    if(daemonize) {
	if(daemon(0,0) == -1)
	    errx(1, "Can't daemonize");
	/* Default PID filename */
	if(strlen(pidfile) == 0) {
	    strcpy(pidfile, "/var/run/");
            strcat(pidfile, myname);
            strcat(pidfile, ".pid");
        }

        if((pfh = pidfile_open(pidfile, 0644, &opid)) == NULL) {
            if (errno == EEXIST)
                errx(1, "PID file already exists: %s", pidfile);
            errx(1, "Can't create PID file: %s", pidfile);
        }
        pidfile_write(pfh);
    }
    signal(SIGINT,  sighandler);
    signal(SIGTERM, sighandler);

    SLIST_INIT(&vals_head);

    last_purge = time(NULL);
    while(running) {
	if(pcap_next_ex(cap, &header, &packet) > 0) {
	    /* Ignore too small packet */
	    if(header->caplen < ETHER_HDR_LEN)
		continue;
	    ip = (struct ip *)(packet + ETHER_HDR_LEN);
	    tcp = (struct tcphdr *)(packet + ETHER_HDR_LEN + sizeof(struct ip));

	    /* SYN w/o ACK - a connection begins. Save the data. */
	    if(tcp->th_flags & TH_SYN && !(tcp->th_flags & TH_ACK)) {
		key = malloc(sizeof(struct key));
		if(key == NULL)
		    errx(1, "malloc()");
		bzero(key, sizeof(struct key));
		memcpy(&key->ip1, &ip->ip_src, sizeof(struct in_addr));
		key->port1 = tcp->th_sport;
		memcpy(&key->ip2, &ip->ip_dst, sizeof(struct in_addr));
		key->port2 = tcp->th_dport;

		/* Store the value into Array */
		JHSI(PValue, Array, key, sizeof(struct key));
		if((PValue == PJERR))
		    errx(1, "no memory");
		/* We don't have a value with this key */
		if(*PValue == 0) {
		    val = malloc(sizeof(struct val));
		    if(val == NULL )
			errx(1, "malloc()");
		    memcpy(&val->timeval, &header->ts, sizeof(struct timeval));
		    val->count=0;
		    val->key = key;
		    *PValue = (Word_t)val;
		    /* Save the value in values list */
		    SLIST_INSERT_HEAD(&vals_head, val, next);
		} else {
		    /* We have one */
		    ((struct val *)*PValue)->count++;
		    memcpy(&((struct val *)*PValue)->timeval, &header->ts, sizeof(struct timeval));
		    if(verbose) {
		        strftime(time_str, sizeof(time_str), "%d/%b/%Y:%H:%M:%S", localtime((const time_t*)&header->ts.tv_sec));
		        fprintf(f1, "%s duplicate #%d from %s:%u\n", time_str, ((struct val *)*PValue)->count, inet_ntoa(key->ip1), ntohs(key->port1));
		        fflush(f1);
		    }
		}
		continue;
	    }

	    /* Remove an antry if RST */
	    if(tcp->th_flags & TH_RST) {
		key = malloc(sizeof(struct key));
		if(key == NULL)
		    errx(1, "malloc()");
		bzero(key, sizeof(struct key));
		memcpy(&key->ip1, &ip->ip_src, sizeof(struct in_addr));
		key->port1 = tcp->th_sport;
		memcpy(&key->ip2, &ip->ip_dst, sizeof(struct in_addr));
		key->port2 = tcp->th_dport;
		JHSG(PValue, Array, key, sizeof(struct key));
		/* Found it. Remove it */
		if(PValue != NULL) {
		    if(verbose) {
		        strftime(time_str, sizeof(time_str), "%d/%b/%Y:%H:%M:%S", localtime((const time_t*)&header->ts.tv_sec));
		        fprintf(f1, "%s RST from %s:%u\n", time_str, inet_ntoa(key->ip1), ntohs(key->port1));
		        fflush(f1);
		    }
		    SLIST_REMOVE(&vals_head, (struct val*)*PValue, val, next);
		    free(((struct val*)*PValue)->key);
		    free((void*)*PValue);
		    JHSD(j, Array, key, sizeof(struct key));
		} else {
		    /* Did not find it. Swap the pair and try again */
		    memcpy(&key->ip2, &ip->ip_src, sizeof(struct in_addr));
		    key->port2 = tcp->th_sport;
		    memcpy(&key->ip1, &ip->ip_dst, sizeof(struct in_addr));
		    key->port1 = tcp->th_dport;
		    JHSG(PValue, Array, key, sizeof(struct key));
		    if(PValue != NULL) {
			if(verbose) {
		            strftime(time_str, sizeof(time_str), "%d/%b/%Y:%H:%M:%S", localtime((const time_t*)&header->ts.tv_sec));
		            fprintf(f1, "%s RST from %s:%u\n", time_str, inet_ntoa(key->ip1), ntohs(key->port1));
		            fflush(f1);
			}
			SLIST_REMOVE(&vals_head, (struct val*)*PValue, val, next);
			free(((struct val*)*PValue)->key);
			free((void*)*PValue);
			JHSD(j, Array, key, sizeof(struct key));
		    }
		}
		free(key);
		continue;
	    }

	    /* FIN from a client. It wants to close connection. */
	    if(tcp->th_flags & TH_FIN) {
		key = malloc(sizeof(struct key));
		if(key == NULL)
		    errx(1, "malloc()");
		bzero(key, sizeof(struct key));
		memcpy(&key->ip1, &ip->ip_src, sizeof(struct in_addr));
		key->port1 = tcp->th_sport;
		memcpy(&key->ip2, &ip->ip_dst, sizeof(struct in_addr));
		key->port2 = tcp->th_dport;

		JHSG(PValue, Array, key, sizeof(struct key));
		/* Find it. */
		if(PValue != NULL) {
		    val = (struct val*)*PValue;
		    strftime(time_str, sizeof(time_str), "%d/%b/%Y:%H:%M:%S", localtime((const time_t*)&header->ts.tv_sec));
		    strftime(time_zone, sizeof(time_zone), "%z", localtime((const time_t*)&header->ts.tv_sec));
		    fprintf(f, "%s %s ", time_str, time_zone);
		    fprintf(f, "%s:%u ", inet_ntoa(key->ip1), ntohs(key->port1));
		    fprintf(f, "%f\n", DeltaUSec(header->ts, val->timeval)/1000000);
		    fflush(f);

		    SLIST_REMOVE(&vals_head, (struct val*)*PValue, val, next);
		    free(((struct val*)*PValue)->key);
		    free((void*)*PValue);
		    JHSD(j, Array, key, sizeof(struct key));
		}
		free(key);
		continue;
	    }
	}
	/* Remove stale entries */
	if(!SLIST_EMPTY(&vals_head)) {
	    now = time(NULL);
	    if(now - last_purge > 3600) {
		SLIST_FOREACH_SAFE(val, &vals_head, next, val_temp) {
		    if(now - val->timeval.tv_sec > 900) {
			if(verbose)
			    fprintf(f1, "Purged: %u sec: %s:%u\n", now - val->timeval.tv_sec, inet_ntoa(key->ip1), ntohs(key->port1));
			SLIST_REMOVE(&vals_head, val, val, next);
			free(val->key);
			JHSD(j, Array, val->key, sizeof(struct key));
			free(val);
		    }
		}
		if(verbose) {
	            fprintf(f1, "Purging done\n");
	            fflush(f1);
		}
		last_purge = now;
	    }
	}
    }

    if(pfh)
	pidfile_remove(pfh);

    fclose(f);
    if(verbose)
        fclose(f1);
    return 0;
}
