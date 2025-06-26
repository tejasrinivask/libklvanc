/*
 * Copyright (c) 2016-2019 Kernel Labs Inc. All Rights Reserved
 *
 * Address: Kernel Labs Inc., PO Box 745, St James, NY. 11780
 * Contact: sales@kernellabs.com
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <libgen.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <sys/time.h>
#include <libklvanc/vanc.h>
#include "udp.h"
#include "url.h"
#include "pes_extractor.h"
#include "version.h"
#include "hexdump.h"

#define DEFAULT_FIFOSIZE 1048576
#define DEFAULT_PID 0x80

static struct app_context_s
{
	int verbose;
	int running;
	char *input_url;
	struct url_opts_s *i_url;
	unsigned int pid;
	int pes_packets_found;
	int vanc_packets_found;
	int smpte12_2_packets_found;

	struct iso13818_udp_receiver_s *udprx;
	struct pes_extractor_s *pe;
	struct klvanc_context_s *vanchdl;
} app_context;

static struct app_context_s *ctx = &app_context;

/* SMPTE 12-2 Timecode callback - streamlined for integration with SMPTE 2038 display */
static int cb_SMPTE_12_2(void *callback_context, struct klvanc_context_s *ctx_vanc,
			 struct klvanc_packet_smpte_12_2_s *pkt)
{
	struct app_context_s *ctx = (struct app_context_s *)callback_context;
	ctx->smpte12_2_packets_found++;

	/* Display timecode type */
	printf("    DBB1 = %02x ", pkt->dbb1);
	switch (pkt->dbb1) {
	case 0x00: printf("(Linear time code - ATC_LTC)"); break;
	case 0x01: printf("(ATC_VITC1)"); break;
	case 0x02: printf("(ATC_VITC2)"); break;
	default: printf("(Unknown type)"); break;
	}
	printf("\n");

	/* Display DBB2 flags */
	printf("    DBB2 = %02x\n", pkt->dbb2);
	printf("    DBB2 VITC line select = 0x%02x\n", (pkt->dbb2 >> 6) & 0x3);
	printf("    DBB2 line duplication flag = %d\n", (pkt->dbb2 >> 5) & 0x1);
	printf("    DBB2 time code validity = %d\n", (pkt->dbb2 >> 4) & 0x1);
	printf("    DBB2 (User bits) process bit = %d\n", (pkt->dbb2 >> 3) & 0x1);

	/* Display the actual timecode */
	printf("    Timecode = %02d:%02d:%02d:%02d\n", 
	       pkt->hours, pkt->minutes, pkt->seconds, pkt->frames);

	/* Display timecode flags */
	printf("    Drop frame flag = %d\n", pkt->flag14);
	printf("    Color frame flag = %d\n", pkt->flag15);

	return 0;
}

/* When the PES extractor has depacketized a PES packet of data, we're
 * called with the entire PES array. Parse it, dump SMPTE 12-2 packets to console.
 */
static pes_extractor_callback pes_cb(void *cb_context, uint8_t *buf, int byteCount)
{
	struct app_context_s *ctx = cb_context;
	if (ctx->verbose) {
		printf("%s() - Processing PES packet of %d bytes\n", __func__, byteCount);
	}

	/* Parse the PES section */
	struct klvanc_smpte2038_anc_data_packet_s *pkt = 0;
	klvanc_smpte2038_parse_pes_packet(buf, byteCount, &pkt);
	if (pkt) {
		ctx->pes_packets_found++;

		if (ctx->verbose) {
			printf("SMPTE2038 PES packet #%d has %d line(s)\n", 
			       ctx->pes_packets_found, pkt->lineCount);
		}

		/* Look for SMPTE 12-2 packets and show detailed SMPTE 2038 structure */
		int has_smpte12_2 = 0;
		for (int i = 0; i < pkt->lineCount; i++) {
			struct klvanc_smpte2038_anc_data_line_s *l = &pkt->lines[i];
			if ((l->DID & 0xff) == 0x60 && (l->SDID & 0xff) == 0x60) {
				has_smpte12_2 = 1;
				break;
			}
		}

		if (has_smpte12_2) {
			printf("\n=== SMPTE 2038 Packet with SMPTE 12-2 Timecode ===\n");
			/* Display SMPTE 2038 packet header information */
			printf("SMPTE 2038 Header:\n");
			printf("  packet_start_code_prefix = %d (0x%x)\n", pkt->packet_start_code_prefix, pkt->packet_start_code_prefix);
			printf("  stream_id = %d (0x%x)\n", pkt->stream_id, pkt->stream_id);
			printf("  PES_packet_length = %d (0x%x)\n", pkt->PES_packet_length, pkt->PES_packet_length);
			printf("  PTS = %" PRIu64 " (0x%" PRIx64 ")\n", pkt->PTS, pkt->PTS);
			printf("  lineCount = %d\n", pkt->lineCount);
			printf("\n");
		}

		/* Process each line looking for SMPTE 12-2 packets */
		for (int i = 0; i < pkt->lineCount; i++) {
			struct klvanc_smpte2038_anc_data_line_s *l = &pkt->lines[i];

			/* Check if this line contains SMPTE 12-2 data (DID=0x60, SDID=0x60) */
			if ((l->DID & 0xff) == 0x60 && (l->SDID & 0xff) == 0x60) {
				printf("SMPTE 2038 Line Entry[%d] - SMPTE 12-2 Ancillary Time Code:\n", i);
				printf("  line_number = %d (0x%x)\n", l->line_number, l->line_number);
				printf("  c_not_y_channel_flag = %d\n", l->c_not_y_channel_flag);
				printf("  horizontal_offset = %d (0x%x)\n", l->horizontal_offset, l->horizontal_offset);
				printf("  DID = %d (0x%x) [SMPTE 12-2]\n", l->DID & 0xff, l->DID & 0xff);
				printf("  SDID = %d (0x%x) [SMPTE 12-2]\n", l->SDID & 0xff, l->SDID & 0xff);
				printf("  data_count = %d (0x%x)\n", l->data_count & 0xff, l->data_count & 0xff);
				printf("  checksum_word = %d (0x%x)\n", l->checksum_word, l->checksum_word);
				
				/* Show original raw payload */
				printf("  Original Raw Payload (10-bit words): ");
				for (int j = 0; j < (l->data_count & 0xff); j++) {
					printf("%03x ", l->user_data_words[j]);
					if ((j + 1) % 16 == 0 && j < (l->data_count & 0xff) - 1) {
						printf("\n                                         ");
					}
				}
				printf("\n");

				/* Show 8-bit extracted payload */
				printf("  8-bit Extracted Payload: ");
				for (int j = 0; j < (l->data_count & 0xff); j++) {
					printf("%02x ", l->user_data_words[j] & 0xff);
					if ((j + 1) % 16 == 0 && j < (l->data_count & 0xff) - 1) {
						printf("\n                            ");
					}
				}
				printf("\n");

				/* Convert line to VANC words for parsing */
				uint16_t *words;
				uint16_t wordCount;
				if (klvanc_smpte2038_convert_line_to_words(l, &words, &wordCount) == 0) {
					printf("  VANC Format (for parsing): ");
					for (int j = 0; j < wordCount; j++) {
						printf("%03x ", words[j]);
						if ((j + 1) % 16 == 0 && j < wordCount - 1) {
							printf("\n                              ");
						}
					}
					printf("\n");

					/* Parse and decode the SMPTE 12-2 timecode */
					printf("\n  Decoded SMPTE 12-2 Timecode:\n");
					if (klvanc_packet_parse(ctx->vanchdl, l->line_number, words, wordCount) < 0) {
						fprintf(stderr, "  ERROR: Failed to parse SMPTE 12-2 VANC packet\n");
					}

					free(words);
				} else {
					fprintf(stderr, "  ERROR: Failed to convert SMPTE 12-2 line to words\n");
				}
				printf("\n");
			} else {
				/* Show non-SMPTE 12-2 lines briefly if in verbose mode */
				if (ctx->verbose > 1) {
					printf("SMPTE 2038 Line Entry[%d] - Other ANC Data:\n", i);
					printf("  line_number = %d, DID = 0x%02x, SDID = 0x%02x\n", 
					       l->line_number, l->DID & 0xff, l->SDID & 0xff);
				}
			}

			ctx->vanc_packets_found++;
		}

		if (has_smpte12_2) {
			printf("=== End SMPTE 2038 Packet ===\n\n");
		}

		/* Free the parsed SMPTE2038 packet */
		klvanc_smpte2038_anc_data_packet_free(pkt);
	} else {
		fprintf(stderr, "Error parsing PES packet\n");
	}

	return 0;
}

/* We're called with blocks of UDP data */
static tsudp_receiver_callback udp_cb(void *userContext, uint8_t *buf, int byteCount)
{
	struct app_context_s *ctx = userContext;

	if (ctx->verbose > 1) {
		printf("%s() pushing %d bytes\n", __func__, byteCount);
	}
	pe_push(ctx->pe, buf, byteCount / 188);
	return 0;
}

static void signal_handler(int signum)
{
	ctx->running = 0;
}

static int _usage(const char *progname, int status)
{
	fprintf(stderr, COPYRIGHT "\n");
	fprintf(stderr, "Extract and decode SMPTE 12-2 timecode from SMPTE2038 VANC frames in a transport stream.\n");
	fprintf(stderr, "Usage: %s [OPTIONS]\n"
		"    -i <input> Input file or UDP URL (e.g., udp://224.0.0.1:5000 or /path/to/file.ts)\n"
		"    -P <pid 0xNNNN> VANC PID to process (def: 0x%x)\n"
		"    -v Increase verbose level\n"
		"    -h Show this help\n",
	basename((char *)progname),
	DEFAULT_PID
	);

	exit(status);
}

static int _main(int argc, char *argv[])
{
	int opt;
	int exitStatus = 0;
	ctx->running = 1;
	ctx->pid = DEFAULT_PID;
	ctx->verbose = 0;
	enum {
		IT_UDP = 0,
		IT_FILE
	} inputType = IT_UDP;
	static struct klvanc_callbacks_s callbacks;

	while ((opt = getopt(argc, argv, "?hi:P:v")) != -1) {
		switch (opt) {
		case 'i':
			ctx->input_url = optarg;
			if (url_parse(ctx->input_url, &ctx->i_url) < 0) {
				/* NOT a valid URL, assume its a file */
				if (access(optarg, R_OK) != 0) {
					fprintf(stderr, "Cannot access input file: %s\n", optarg);
					_usage(argv[0], 1);
				}
				inputType = IT_FILE;
			} else {
				inputType = IT_UDP;
			}
			break;
		case 'P':
			if ((sscanf(optarg, "0x%x", &ctx->pid) != 1) || (ctx->pid > 0x1fff)) {
				fprintf(stderr, "Invalid PID: %s\n", optarg);
				_usage(argv[0], 1);
			}
			break;
		case 'v':
			ctx->verbose++;
			break;
		case '?':
		case 'h':
			_usage(argv[0], 0);
		}
	}

	if (ctx->input_url == NULL) {
		fprintf(stderr, "Missing mandatory -i option\n");
		_usage(argv[0], 1);
	}

	printf("SMPTE 12-2 Timecode Extractor\n");
	printf("Input: %s (PID: 0x%x)\n", ctx->input_url, ctx->pid);
	printf("================================\n\n");

	pe_alloc(&ctx->pe, ctx, (pes_extractor_callback)pes_cb, ctx->pid);
	signal(SIGINT, signal_handler);

	if (klvanc_context_create(&ctx->vanchdl) < 0) {
		fprintf(stderr, "Error initializing klvanc library context\n");
		exit(1);
	}
	ctx->vanchdl->verbose = ctx->verbose;

	/* Set up callback for SMPTE 12-2 packets */
	callbacks.smpte_12_2 = cb_SMPTE_12_2;
	ctx->vanchdl->callbacks = &callbacks;
	ctx->vanchdl->callback_context = ctx;

	if (inputType == IT_UDP) {
		int fs = DEFAULT_FIFOSIZE;
		if (ctx->i_url->has_fifosize)
			fs = ctx->i_url->fifosize;

		if (iso13818_udp_receiver_alloc(&ctx->udprx, fs,
			ctx->i_url->hostname, ctx->i_url->port, (tsudp_receiver_callback)udp_cb, ctx, 0) < 0) {
			fprintf(stderr, "Unable to allocate a UDP Receiver for %s:%d\n",
			ctx->i_url->hostname, ctx->i_url->port);
			goto cleanup;
		}

		/* Add a multicast NIC if required */
		if (ctx->i_url->has_ifname) {
			iso13818_udp_receiver_join_multicast(ctx->udprx, ctx->i_url->ifname);
		}

		/* Start UDP receive and wait for CTRL-C */
		iso13818_udp_receiver_thread_start(ctx->udprx);
		printf("Listening for UDP packets... Press Ctrl-C to stop.\n");
		while (ctx->running) {
			usleep(100 * 1000);
		}

		/* Shutdown */
		iso13818_udp_receiver_free(&ctx->udprx);
	} else if (inputType == IT_FILE) {
		FILE *fh = fopen(ctx->input_url, "rb");
		if (fh) {
			printf("Processing file: %s\n", ctx->input_url);
			
			uint8_t pkt[188];
			int packets_processed = 0;
			while (!feof(fh) && ctx->running) {
				if (fread(pkt, 188, 1, fh) != 1)
					break;

				udp_cb(ctx, pkt, sizeof(pkt));
				packets_processed++;
				
				if (ctx->verbose && (packets_processed % 10000 == 0)) {
					printf("Processed %d TS packets...\n", packets_processed);
				}
			}
			fclose(fh);
			printf("Processed %d TS packets total.\n", packets_processed);
		} else {
			fprintf(stderr, "Cannot open input file: %s\n", ctx->input_url);
			exitStatus = 1;
		}
	}

cleanup:
	pe_free(&ctx->pe);

	/* Print summary */
	printf("\n=== Summary ===\n");
	printf("Total PES packets found: %d\n", ctx->pes_packets_found);
	printf("Total VANC packets found: %d\n", ctx->vanc_packets_found);
	printf("Total SMPTE 12-2 packets found: %d\n", ctx->smpte12_2_packets_found);
	printf("Total VANC checksum failures: %d\n", ctx->vanchdl->checksum_failures);

	klvanc_context_destroy(ctx->vanchdl);
	return exitStatus;
}

int main(int argc, char *argv[])
{
	return _main(argc, argv);
} 