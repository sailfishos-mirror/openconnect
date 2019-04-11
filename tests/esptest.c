#include <config.h>

#include "../openconnect-internal.h"
#include <signal.h>

static void write_progress(void *vpninfo, int level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

static int pkt_size = 1400;
static long count;
static int done;

static void handle_alrm(int sig)
{
	done = 1;
}

int main(void)
{
	openconnect_init_ssl();

	struct openconnect_info *vpninfo = openconnect_vpninfo_new("", NULL, NULL, NULL, write_progress, NULL);
	struct pkt *pkt = malloc(128 + pkt_size);
	int ret;

	vpninfo->verbose = PRG_DEBUG;

	vpninfo->esp_enc = 2; /* AES128-CBC */
	vpninfo->esp_hmac = 2; /* HMAC-SHA1 */
	vpninfo->enc_key_len = 16;
	vpninfo->hmac_key_len = 20;

	vpninfo->esp_out.spi = 0x12345678;
	memset(vpninfo->esp_out.enc_key, 0x5a, vpninfo->enc_key_len);
	memset(vpninfo->esp_out.hmac_key, 0x5a, vpninfo->hmac_key_len);

	vpninfo->esp_in[0] = vpninfo->esp_out;

	vpninfo->dtls_state = DTLS_SLEEPING;
	vpninfo->dtls_addr = (void *)vpninfo;

	ret = openconnect_setup_esp_keys(vpninfo, 0);
	if (ret) {
		printf("setup ESP failed: %d\n", ret);
		exit(1);
	}

	memset(pkt->data, 0x5a, pkt_size);

	signal(SIGALRM, handle_alrm);

	alarm(5);
	while (!done) {
		pkt->len = pkt_size;
		openconnect_construct_esp_packet(vpninfo, pkt, IPPROTO_IPV6);
		count++;
	}
	printf("Encrypted %ld packets in 5s (%ld Mb/s)\n", count, count * pkt_size / 5 / 250000);

	done = 0;
	count = 0;
	alarm(5);
	while (!done) {
		pkt->len = pkt_size;
		pkt->len = openconnect_construct_esp_packet(vpninfo, pkt, IPPROTO_IPV6);
		pkt->len -= (sizeof(pkt->esp) + vpninfo->hmac_out_len);
		if (vpninfo->decrypt_esp_packet(vpninfo, &vpninfo->esp_in[0], pkt))
			exit(1);
		count++;
	}
	printf("Encrypted+decrypted %ld packets in 5s (%ld Mb/s)\n", count, count * pkt_size / 5 / 250000);
}
