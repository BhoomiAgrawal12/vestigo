;--------------------------------------------------------
; File Created by SDCC : free open source ANSI-C Compiler
; Version 4.0.0 #11528 (Linux)
;--------------------------------------------------------
	.module plain
	.optsdcc -mz80
	
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _main
	.globl _process_block
	.globl _puts
	.globl _printf
	.globl _state
;--------------------------------------------------------
; special function registers
;--------------------------------------------------------
;--------------------------------------------------------
; ram data
;--------------------------------------------------------
	.area _DATA
_state::
	.ds 16
;--------------------------------------------------------
; ram data
;--------------------------------------------------------
	.area _INITIALIZED
;--------------------------------------------------------
; absolute external ram data
;--------------------------------------------------------
	.area _DABS (ABS)
;--------------------------------------------------------
; global & static initialisations
;--------------------------------------------------------
	.area _HOME
	.area _GSINIT
	.area _GSFINAL
	.area _GSINIT
;--------------------------------------------------------
; Home
;--------------------------------------------------------
	.area _HOME
	.area _HOME
;--------------------------------------------------------
; code
;--------------------------------------------------------
	.area _CODE
;plain.c:8: void process_block(uint8_t* input) {
;	---------------------------------
; Function process_block
; ---------------------------------
_process_block::
	push	ix
	ld	ix,#0
	add	ix,sp
;plain.c:9: printf("[LOG] Processing block: ");
	ld	hl, #___str_0
	push	hl
	call	_printf
	pop	af
;plain.c:10: for(int i=0; i<16; i++) {
	ld	bc, #0x0000
00103$:
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00101$
;plain.c:12: state[i] = input[i] ^ 0xFF; 
	ld	hl, #_state
	add	hl, bc
	ex	de, hl
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	add	hl, bc
	ld	a, (hl)
	cpl
	ld	(de), a
;plain.c:13: printf("%02x ", state[i]);
	ld	e, a
	ld	d, #0x00
	push	bc
	push	de
	ld	hl, #___str_1
	push	hl
	call	_printf
	pop	af
	pop	af
	pop	bc
;plain.c:10: for(int i=0; i<16; i++) {
	inc	bc
	jr	00103$
00101$:
;plain.c:15: printf("\n");
	ld	hl, #___str_3
	push	hl
	call	_puts
	pop	af
;plain.c:16: }
	pop	ix
	ret
___str_0:
	.ascii "[LOG] Processing block: "
	.db 0x00
___str_1:
	.ascii "%02x "
	.db 0x00
___str_3:
	.db 0x00
;plain.c:18: int main() {
;	---------------------------------
; Function main
; ---------------------------------
_main::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-16
	add	hl, sp
	ld	sp, hl
;plain.c:20: uint8_t data[16] = {
	ld	hl, #0
	add	hl, sp
	ex	de, hl
	ld	a, #0x32
	ld	(de), a
	ld	l, e
	ld	h, d
	inc	hl
	ld	(hl), #0x43
	ld	l, e
	ld	h, d
	inc	hl
	inc	hl
	ld	(hl), #0xf6
	ld	l, e
	ld	h, d
	inc	hl
	inc	hl
	inc	hl
	ld	(hl), #0xa8
	ld	hl, #0x0004
	add	hl, de
	ld	(hl), #0x88
	ld	hl, #0x0005
	add	hl, de
	ld	(hl), #0x5a
	ld	hl, #0x0006
	add	hl, de
	ld	(hl), #0x30
	ld	hl, #0x0007
	add	hl, de
	ld	(hl), #0x8d
	ld	hl, #0x0008
	add	hl, de
	ld	(hl), #0x31
	ld	hl, #0x0009
	add	hl, de
	ld	(hl), #0x31
	ld	hl, #0x000a
	add	hl, de
	ld	(hl), #0x98
	ld	hl, #0x000b
	add	hl, de
	ld	(hl), #0xa2
	ld	hl, #0x000c
	add	hl, de
	ld	(hl), #0xe0
	ld	hl, #0x000d
	add	hl, de
	ld	(hl), #0x37
	ld	hl, #0x000e
	add	hl, de
	ld	(hl), #0x07
	ld	hl, #0x000f
	add	hl, de
	ld	(hl), #0x34
;plain.c:25: printf("--- System Start (Baseline) ---\n");
	push	de
	ld	hl, #___str_5
	push	hl
	call	_puts
	pop	af
	pop	de
;plain.c:27: for(int i=0; i<4; i++) {
	ld	bc, #0x0000
00103$:
	ld	a, c
	sub	a, #0x04
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00101$
;plain.c:28: process_block(data);
	ld	l, e
	ld	h, d
	push	bc
	push	de
	push	hl
	call	_process_block
	pop	af
	pop	de
	pop	bc
;plain.c:27: for(int i=0; i<4; i++) {
	inc	bc
	jr	00103$
00101$:
;plain.c:31: printf("--- System Shutdown ---\n");
	ld	hl, #___str_7
	push	hl
	call	_puts
	pop	af
;plain.c:32: return 0;
	ld	hl, #0x0000
;plain.c:33: }
	ld	sp, ix
	pop	ix
	ret
___str_5:
	.ascii "--- System Start (Baseline) ---"
	.db 0x00
___str_7:
	.ascii "--- System Shutdown ---"
	.db 0x00
	.area _CODE
	.area _INITIALIZER
	.area _CABS (ABS)
