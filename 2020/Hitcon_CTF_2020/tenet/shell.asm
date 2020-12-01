[BITS 64]

global _start

_start:
  ; store cookie to MMX
  mov rax, 0x2170000
  movq xmm0, [rax]
  ; ymm0[127:0] -> ymm0[255:128]
  vperm2f128 ymm0, ymm0, ymm0, 0

  ; set the cookie to 0
  xor rbx, rbx

  ; swallow the cookie
  mov rax, 0x2170000
  mov [rax], rbx
  mov rax, 0x2170000

  ; get the cookie
  movq rbx, xmm0

  ; ymm0[255:128] -> ymm0[127:0]
  vperm2f128 ymm0, ymm0, ymm0, 1

  ; break out of loop
  mov rdi, 0x1
  mov rax, 0x3c
  sysenter


