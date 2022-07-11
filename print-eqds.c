/* Copyright (c) 2020, Costin Raiciu (Correct Networks)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* \summary: EQDS (Edge-Queued Datagram Service) printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "extract.h"

#define NDP_FLAG_SYN     (1 << 0)
#define NDP_FLAG_NACK    (1 << 1)
#define NDP_FLAG_SACK    (1 << 2)
#define NDP_FLAG_ACK     (1 << 3)
#define NDP_FLAG_EMPTY   (1 << 4)
#define NDP_FLAG_PAUSE   (1 << 5)
#define NDP_FLAG_FIN     (1 << 6)
#define NDP_FLAG_TRIMMED (1 << 7)

static const struct tok eqds_flags [] = {
    { 1<<7, "TRIM" },
    { 1<<6, "FIN" },  
    { 1<<5, "PAUSE" },
    { 1<<4, "EMPTY" },  
    { 1<<3, "ACK" },  
    { 1<<2, "SACK" },
    { 1<<1, "NACK" },
    { 1<<0, "SYN" },
    { 0, NULL }
};

#define EQDS_HDR_LEN 8

void
eqds_print(netdissect_options *ndo, const u_char *bp, u_int len)
{
    uint8_t flags;

    ndo->ndo_protocol = "eqds";
    ND_PRINT("EQDS ");
    if (len < EQDS_HDR_LEN) {
        ND_PRINT(" (len %u < %u)", len, EQDS_HDR_LEN);
        goto invalid;
    }

    flags = GET_U_1(bp);
    bp += 1;
    len -= 1;
    ND_PRINT("[%s], ", bittok2str_nosep(eqds_flags, "none", flags));

    if ((flags & NDP_FLAG_SACK) || (flags & NDP_FLAG_ACK) || (flags & NDP_FLAG_NACK)) {
        /*
         * This is a control header.
         */
        uint8_t path_id = GET_U_1(bp);
        bp += 1;
        len -= 1;
        uint16_t wsize = GET_BE_U_2(bp);
        bp += 2;
        len -= 2;      
        uint16_t ackno = GET_BE_U_2(bp);
        bp += 2;
        len -= 2;
        uint16_t pullno = GET_BE_U_2(bp);
        bp += 2;
        len -= 2;

        if (flags & NDP_FLAG_SACK)
            ND_PRINT("SACK %u, PULL %u", ackno, pullno);
        else if (flags & NDP_FLAG_NACK)
            ND_PRINT("NACK %u, PULL %u", ackno, pullno);
        else if (flags & NDP_FLAG_ACK)
            ND_PRINT("ACK %u, PULL %u", ackno, pullno);      
        else
            ND_PRINT("ERROR: unknown flags");

        if (ndo->ndo_vflag) 
            ND_PRINT(" [Wsize %u, Path ID %u]", wsize, path_id);
      
        ND_PRINT(": ");
        return;
    } else {
        /* 
         * This is a data header
         */
        uint8_t path_id = GET_U_1(bp);
        bp += 1;
        len -= 1;

        uint8_t next_proto = GET_U_1(bp);
        bp += 1;
        len -= 1;
            
        uint16_t rsvd = GET_U_1(bp);
        bp += 1;
        len -= 1;                  
            
        uint16_t seqno = GET_BE_U_2(bp);
        bp += 2;
        len -= 2;
            
        uint8_t pull_target = GET_BE_U_2(bp);
        bp += 2;
        len -= 2;

        ND_PRINT("Seq %u, Pull Target %u", seqno, pull_target);

        if (ndo->ndo_vflag)
            ND_PRINT(" [Path ID %u RSVD %u]", path_id, rsvd);

        ND_PRINT(": ");

        if (!(flags & NDP_FLAG_TRIMMED)){
            switch (next_proto) {
                case 4:
                    ip_print(ndo, bp, len);
                    break;
                case 0xFC:
                    ND_PRINT("EQDS Native Protocol");
                    break;
                default:
                    ND_PRINT("ERROR: unknown-next-protocol %u", next_proto);
                    goto invalid;
            }
        }
    }

invalid:
    nd_print_invalid(ndo);
}

