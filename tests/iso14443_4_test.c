/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "iso14443_4.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint8_t sent[256];
static uint16_t sent_size;
static unsigned sends;
static void capture(void *ctx, const uint8_t *frame, uint16_t size) {
    (void)ctx; assert(size <= sizeof(sent));
    memcpy(sent, frame, size); sent_size = size; sends++;
}
static uint16_t crc_frame(uint8_t *frame, uint16_t n) {
    uint16_t crc = iso_dep_crc_a(frame,n);
    frame[n] = crc; frame[n+1] = crc >> 8; return n+2;
}
static void ready(iso_dep_picc_t *s, uint16_t size) {
    for (uint16_t i=0; i<size; i++) s->m_resp_buf[i] = i;
    s->m_resp_len=size; s->m_response_ready=true;
    iso_dep_picc_respond(s,capture,NULL);
}
static void test_picc(void) {
    iso_dep_picc_t s;
    iso_dep_picc_reset(&s); assert(!iso_dep_picc_rats(&s,0x90));
    assert(iso_dep_picc_rats(&s,0x00));
    uint8_t first[]={0x12,0,0xA4};
    assert(iso_dep_picc_receive(&s,first,sizeof(first),capture,NULL)==ISO_DEP_IGNORED);
    assert(sent_size==1 && sent[0]==0xA3 && s.m_apdu_len==2 && !s.m_apdu_pending);
    iso_dep_picc_receive(&s,first,sizeof(first),capture,NULL);
    assert(s.m_apdu_len==2 && sent[0]==0xA3);
    uint8_t last[]={0x03,4,0,0};
    assert(iso_dep_picc_receive(&s,last,sizeof(last),capture,NULL)==ISO_DEP_APDU);
    uint8_t command[]={0,0xA4,4,0,0};
    assert(s.m_apdu_len==5 && !memcmp(s.m_apdu_buf,command,5));
    ready(&s,40);
    assert(sent[0]==0x13 && sent_size==14); /* FSD=16 minus CRC=2 */
    uint8_t saved[256]; memcpy(saved,sent,sent_size);
    uint8_t nak[]={0xB2};
    iso_dep_picc_receive(&s,nak,1,capture,NULL);
    assert(sent_size==14 && !memcmp(sent,saved,14));
    uint8_t ack[]={0xA2};
    iso_dep_picc_receive(&s,ack,1,capture,NULL);
    assert(sent[0]==0x12 && sent[1]==13);
    ack[0]=0xA3; iso_dep_picc_receive(&s,ack,1,capture,NULL);
    assert(sent[0]==0x13 && sent[1]==26);
    ack[0]=0xA2; iso_dep_picc_receive(&s,ack,1,capture,NULL);
    assert(sent[0]==0x02 && sent_size==2 && sent[1]==39 && !s.sending_chain);
    uint8_t de[]={0xC2};
    assert(iso_dep_picc_receive(&s,de,1,capture,NULL)==ISO_DEP_DESELECTED);
    assert(sent[0]==0xC2 && !s.m_apdu_pending && !s.last_frame_len);

    assert(iso_dep_picc_rats(&s,0x47));
    uint8_t cid_cmd[]={0x0A,7,0,0xA4,4,0};
    assert(iso_dep_picc_receive(&s,cid_cmd,sizeof(cid_cmd),capture,NULL)==ISO_DEP_APDU);
    iso_dep_picc_respond(&s,capture,NULL);
    assert(sent_size==3 && sent[0]==0xFA && sent[1]==7 && sent[2]==59);
    s.m_resp_buf[0]=0x90; s.m_resp_buf[1]=0; s.m_resp_len=2; s.m_response_ready=true;
    unsigned before=sends;
    uint8_t wtx[]={0xFA,7,59};
    iso_dep_picc_receive(&s,wtx,3,capture,NULL);
    assert(sends==before+1 && sent_size==4 && sent[0]==0x0A && sent[2]==0x90);
    before=sends; cid_cmd[1]=6;
    iso_dep_picc_receive(&s,cid_cmd,sizeof(cid_cmd),capture,NULL); assert(sends==before);
    assert(iso_dep_picc_rats(&s,0));
    uint8_t nad[]={0x06,0,0,0};
    assert(iso_dep_picc_receive(&s,nad,4,capture,NULL)==ISO_DEP_IGNORED);
    /* Overflow never exposes a partial APDU to the application. */
    uint8_t chunk[15]; memset(chunk,0x55,sizeof(chunk));
    for (unsigned i=0;i<20;i++) {
        chunk[0]=0x12|(i&1);
        assert(iso_dep_picc_receive(&s,chunk,sizeof(chunk),capture,NULL)==ISO_DEP_IGNORED);
    }
    assert(!s.m_apdu_pending);
    puts("PICC: chaining, retransmit, CID, WTX, DESELECT, NAD and overflow passed");
}

typedef struct { unsigned step; int mode; uint8_t expected; uint16_t total; } fixture_t;
static bool scripted(void *ctx,const uint8_t *tx,uint16_t tx_size,
        uint8_t *rx,uint16_t *rx_size,uint16_t timeout) {
    fixture_t *f=ctx;
    assert(tx_size<=64 && tx_size>=3 && timeout>0);
    assert(iso_dep_crc_a(tx,tx_size-2)==(uint16_t)(tx[tx_size-2]|tx[tx_size-1]<<8));
    uint16_t n=0;
    if (f->mode==0) { /* card response chaining + duplicated first block */
        if(f->step==0) { assert(tx[0]==0x02); rx[0]=0x12; rx[1]=0x11; n=2; }
        else if(f->step==1) { assert(tx[0]==0xA3); rx[0]=0x12; rx[1]=0x11; n=2; }
        else { assert(tx[0]==0xA3); rx[0]=0x03; rx[1]=0x90; rx[2]=0; n=3; }
    } else if(f->mode==1) { /* persistent block number across two APDUs */
        assert(tx[0]==(0x02|(f->step&1))); rx[0]=tx[0]; rx[1]=0x90;rx[2]=0;n=3;
    } else if(f->mode==2) { /* outgoing command chaining at FSC=16 */
        assert(tx_size<=16 && (tx[0]&1)==f->expected);
        f->total+=tx_size-3;
        if(tx[0]&0x10) { f->expected^=1; rx[0]=0xA2|f->expected;n=1; }
        else { rx[0]=0x02|f->expected; rx[1]=0x90;rx[2]=0;n=3; }
    } else if(f->mode==3) { /* WTX request/response */
        if(f->step==0) {assert(tx[0]==2);rx[0]=0xF2;rx[1]=2;n=2;}
        else {assert(tx_size==4 && tx[0]==0xF2 && tx[1]==2);rx[0]=2;rx[1]=0x90;rx[2]=0;n=3;}
    } else if(f->mode==4) { /* card R(NAK) retransmits identical command */
        assert(tx[0]==2 && tx[1]==0);
        if(f->step==0) {rx[0]=0xB2;n=1;}else{rx[0]=2;rx[1]=0x90;rx[2]=0;n=3;}
    } else if(f->mode==5) {rx[0]=2; memset(rx+1,0x55,10);n=11;}
    else if(f->mode==6) {rx[0]=0xF2;rx[1]=0;n=2;}
    else if(f->mode==7) {rx[0]=2;rx[1]=0x90;rx[2]=0;n=3;}
    else if(f->mode==8) {return false;}
    else {rx[0]=0xF2;rx[1]=1;n=2;}
    f->step++;
    n=crc_frame(rx,n);assert(n<=*rx_size);*rx_size=n;
    if(f->mode==7) rx[n-1]^=1;
    return true;
}
static void test_reader(void) {
    iso_dep_reader_t s;
    uint8_t ats[]={2,5}, command[]={0,0xA4,4,0,0}, response[512];
    uint16_t size;
    assert(iso_dep_crc_a((uint8_t[]){0xE0,0x40},2)==0xB53D);
    assert(iso_dep_reader_init(&s,ats,2));
    assert(!iso_dep_reader_init(&s,(uint8_t[]){2,9},2));
    assert(!iso_dep_reader_init(&s,(uint8_t[]){3,0x25},2));
    for(int mode=0;mode<10;mode++) {
        assert(iso_dep_reader_init(&s,ats,2));
        fixture_t f={.mode=mode}; size=sizeof(response);
        iso_dep_result_t r;
        if(mode==2) {
            uint8_t big[260]; memset(big,0,sizeof(big));s.frame_size=16;
            r=iso_dep_reader_exchange(&s,big,sizeof(big),response,&size,scripted,&f);
            assert(r==ISO_DEP_OK && f.total==260);
        } else {
            if(mode==5)size=4;
            r=iso_dep_reader_exchange(&s,command,sizeof(command),response,&size,scripted,&f);
        }
        if(mode<5)assert(r==ISO_DEP_OK);
        if(mode==0)assert(size==3 && response[0]==0x11 && response[1]==0x90 && f.step==3);
        if(mode==1) {
            size=sizeof(response);
            assert(iso_dep_reader_exchange(&s,command,5,response,&size,scripted,&f)==ISO_DEP_OK);
            assert(s.block_num==0 && f.step==2);
        }
        if(mode==5)assert(r==ISO_DEP_OVERFLOW && size==0);
        if(mode==6||mode==7)assert(r==ISO_DEP_PROTOCOL_ERROR && size==0);
        if(mode==8)assert(r==ISO_DEP_IO_ERROR && size==0);
        if(mode==9)assert(r!=ISO_DEP_OK && size==0 && f.step==9);
    }
    puts("Reader: session, bidirectional chaining, duplicate, WTX, NAK, CRC, bounds and errors passed");
}
int main(void) {test_picc();test_reader();return 0;}
