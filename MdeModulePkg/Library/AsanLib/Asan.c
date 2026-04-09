/** @file
  The compiler instrumentation routines for AddressSanitizer(ASan).

  Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/


#include <Uefi.h>
#include <Library/Asan.h>
#include <Library/HobLib.h>

static const UINT64 kDefaultShadowScale = 3;
#define SHADOW_SCALE kDefaultShadowScale

UINT64 mShadowOffset = 0x5000000;
#define SHADOW_OFFSET mShadowOffset

#define MEM_TO_SHADOW(mem) (((mem) >> SHADOW_SCALE) + (SHADOW_OFFSET))

#define SHADOW_GRANULARITY (1ULL << SHADOW_SCALE)

#define __cpuid_extended1(value, arg0)                          \
  unsigned int _a __attribute__((unused)) = 0;                  \
  unsigned int _b __attribute__((unused)) = 0;                  \
  unsigned int _c __attribute__((unused)) = 0;                  \
  unsigned int _d __attribute__((unused)) = 0;                  \
  __asm__ __volatile__("cpuid\n\t"                              \
                       : "=a"(_a), "=b"(_b), "=c"(_c), "=d"(_d) \
                       : "a"(value), "D"(arg0));

// #define HARNESS_ASSERT()
#define HARNESS_ASSERT()                                   \
  do {                                                     \
    unsigned int value = (0x0005U << 0x10U) | 0x4711U; \
    __cpuid_extended1(value, 0x0000U);               \
  } while (0);

#define ASAN_ASSERT(Expression)   \
do {                            \
  if (!(Expression)) {          \
    SerialOutput ("ASAN_ASSERT! ");   \
    SerialOutput (__FILE__);    \
    SerialOutput (", line:");   \
    CHAR8 NumStr[19];       \
    Num2Str64bit ( __LINE__ , NumStr);\
    SerialOutput (NumStr);    \
    SerialOutput (": ");        \
    SerialOutput (#Expression); \
    SerialOutput ("\n");        \
    ANALYZER_UNREACHABLE ();    \
  }                             \
} while (FALSE)


static BOOLEAN asan_inited = FALSE;
static BOOLEAN asan_is_deactivated = TRUE;
static BOOLEAN AsanCtorFlag = FALSE;
UINT64 mAsanShadowMemoryStart = 0;
UINT64 mAsanShadowMemorySize = 0;
UINT64 mAsanShadowMemoryEnd = 0;
#define SHADOW_TO_MEM(shadow) (((shadow) - SHADOW_OFFSET) << SHADOW_SCALE)

VOID
SerialOutput(
  IN  CONST CHAR8      *String
  );

VOID
SerialOutput2(
  IN  CONST CHAR8      *String
  );

VOID
Num2Str8bit(
  IN  UINT8 Number,
  IN  CHAR8* NumStr
  );

VOID
Num2Str16bit(
  IN  UINT16 Number,
  IN  CHAR8* NumStr
  );

VOID
Num2Str64bit(
  IN  UINT64 Number,
  IN  CHAR8* NumStr
  );

UINTN RoundUpTo(UINTN size, UINTN boundary);
UINTN RoundDownTo(UINTN x, UINTN boundary);

void asan_print_bug2(UINTN addr, UINTN size, CHAR8 *file, UINTN line)
{
    // Determine the error type.
  const CHAR8 *bug_descr = "unknown-crash";
  UINT8 shadow_val = 0;
  int read_after_free_bonus = 0;
  BOOLEAN far_from_bounds = FALSE;
  UINT8 *shadow_addr = (UINT8*)MEM_TO_SHADOW(addr);
  // If we are accessing 16 bytes, look at the second shadow byte.
  if (*shadow_addr == 0 && size > SHADOW_GRANULARITY)
    shadow_addr++;
  // If we are in the partial right redzone, look at the next shadow byte.
  if (*shadow_addr > 0 && *shadow_addr < 128)
    shadow_addr++;
  far_from_bounds = FALSE;
  shadow_val = *shadow_addr;
//    int bug_type_score = 0;
  // For use-after-frees reads are almost as bad as writes.
  read_after_free_bonus = 0;
  switch (shadow_val) {
    case kAsanHeapLeftRedzoneMagic:
    case kAsanArrayCookieMagic:
      bug_descr = "heap-buffer-overflow";
      break;
    case kAsanHeapFreeMagic:
      bug_descr = "heap-use-after-free";
      break;
    case kAsanStackLeftRedzoneMagic:
      bug_descr = "stack-buffer-underflow";
      break;
    case kAsanInitializationOrderMagic:
      bug_descr = "initialization-order-fiasco";
      break;
    case kAsanStackMidRedzoneMagic:
    case kAsanStackRightRedzoneMagic:
      bug_descr = "stack-buffer-overflow";
      break;
    case kAsanStackAfterReturnMagic:
      bug_descr = "stack-use-after-return";
      break;
    case kAsanUserPoisonedMemoryMagic:
      bug_descr = "use-after-poison";
      break;
    case kAsanContiguousContainerOOBMagic:
      bug_descr = "container-overflow";
      break;
    case kAsanStackUseAfterScopeMagic:
      bug_descr = "stack-use-after-scope";
      break;
    case kAsanGlobalRedzoneMagic:
      bug_descr = "global-buffer-overflow";
      break;
    case kAsanIntraObjectRedzone:
      bug_descr = "intra-object-overflow";
      break;
    case kAsanAllocaLeftMagic:
     case kAsanAllocaRightMagic:
      bug_descr = "dynamic-stack-buffer-overflow";
      break;
    }
  SerialOutput("bug_descr=");
  SerialOutput(bug_descr);
  SerialOutput(" in file: ");
  SerialOutput(file);
  SerialOutput(" at line: ");
  CHAR8 NumStr[19];
  Num2Str64bit(line, NumStr);
  SerialOutput(NumStr);
  SerialOutput("\n");
}

static void asan_print_16_bytes_no_bug2(CONST CHAR8 *prefix,
                                        UINTN address) {
  // printf("%s0x%X:", prefix, address);
  CHAR8 NumStr[19];
  SerialOutput(prefix);
  Num2Str64bit(address, NumStr);
  SerialOutput(NumStr);
  SerialOutput(":");
  
  for (int i = 0; i < 16; i++) {
    // printf(" %02X", *(UINT8 *)(address + i));
    SerialOutput(" ");
    Num2Str64bit(*(UINT8 *)(address + i), NumStr); 
    SerialOutput(NumStr);
  }
  SerialOutput("\n");
}

static void asan_print_16_bytes_with_bug2(CONST CHAR8 *prefix,
                                          UINTN address,
                                          INTN buggy_offset) {
  // printf("%s0x%X:", prefix, address);
  CHAR8 NumStr[19];
  SerialOutput(prefix);
  Num2Str64bit(address, NumStr);
  SerialOutput(NumStr);
  SerialOutput(":");

  for (int i = 0; i < buggy_offset; i++){
    // printf(" %02X", *(UINT8 *)(address + i));
    SerialOutput(" ");
    Num2Str64bit(*(UINT8 *)(address + i), NumStr);
    SerialOutput(NumStr);
  }
  // printf("[%02X]", *(UINT8 *)(address + buggy_offset));
  SerialOutput("[");
  Num2Str64bit(*(UINT8 *)(address + buggy_offset), NumStr);
  SerialOutput(NumStr);
  SerialOutput("]");
  if (buggy_offset < 15){
    // printf("%02X", *(UINT8 *)(address + buggy_offset + 1));
    SerialOutput(" ");
    Num2Str64bit(*(UINT8 *)(address + buggy_offset + 1), NumStr);
    SerialOutput(NumStr);
  }
  for (int i = buggy_offset + 2; i < 16; i++){
    // printf(" %02X", *(UINT8 *)(address + i));
    SerialOutput(" ");
    Num2Str64bit(*(UINT8 *)(address + i), NumStr);
    SerialOutput(NumStr);
  }
  // printf("\n");
  SerialOutput("\n");
}

static void asan_print_shadow_memory2(UINTN address, INTN range_before,
                                      INTN range_after) {
  UINTN shadow_address = MEM_TO_SHADOW(address);
  UINTN aligned_shadow = shadow_address & 0xfffffff0;
  INTN buggy_offset = shadow_address - aligned_shadow;

  // printf("[ASan] Shadow bytes around the buggy address 0x%X (shadow 0x%X):\n", address, shadow_address);
  CHAR8 NumStr[19];
  SerialOutput("[ASan] Shadow bytes around the buggy address ");
  Num2Str64bit(address, NumStr);
  SerialOutput(NumStr);
  SerialOutput(" (shadow ");
  Num2Str64bit(shadow_address, NumStr);
  SerialOutput(NumStr);
  SerialOutput("):\n");

  for (INTN i = range_before; i > 0; i--) {
    asan_print_16_bytes_no_bug2("[ASan]   ", aligned_shadow - i * 16);
  }

  asan_print_16_bytes_with_bug2("[ASan] =>", aligned_shadow, buggy_offset);

  for (INTN i = 1; i <= range_after; i++) {
    asan_print_16_bytes_no_bug2("[ASan]   ", aligned_shadow + i * 16);
  }
}

//
// Map a shadow magic value to the canonical libASan bug-class string
// used in "==ERROR: AddressSanitizer:" lines. Kept in sync with
// asan_print_bug2 above. Returns "unknown-crash" for unknown values
// instead of NULL so callers can pass the result straight to
// SerialOutput without a NULL check.
//
static CONST CHAR8 *asan_shadow_to_bug_string(UINT8 shadow_val) {
  switch (shadow_val) {
    case kAsanHeapLeftRedzoneMagic:
    case kAsanArrayCookieMagic:
      return "heap-buffer-overflow";
    case kAsanHeapFreeMagic:
      return "heap-use-after-free";
    case kAsanStackLeftRedzoneMagic:
      return "stack-buffer-underflow";
    case kAsanInitializationOrderMagic:
      return "initialization-order-fiasco";
    case kAsanStackMidRedzoneMagic:
    case kAsanStackRightRedzoneMagic:
      return "stack-buffer-overflow";
    case kAsanStackAfterReturnMagic:
      return "stack-use-after-return";
    case kAsanUserPoisonedMemoryMagic:
      return "use-after-poison";
    case kAsanContiguousContainerOOBMagic:
      return "container-overflow";
    case kAsanStackUseAfterScopeMagic:
      return "stack-use-after-scope";
    case kAsanGlobalRedzoneMagic:
      return "global-buffer-overflow";
    case kAsanIntraObjectRedzone:
      return "intra-object-overflow";
    case kAsanAllocaLeftMagic:
    case kAsanAllocaRightMagic:
      return "dynamic-stack-buffer-overflow";
  }
  return "unknown-crash";
}

//
// Emit a single line in the format pkg/report/edk2.go on the syzkaller
// side already understands:
//
//   ==ERROR: AddressSanitizer: <bug_class> on address <addr> at pc <ip>
//
// This is in addition to (not in place of) the existing [ASan] ...
// debug output, so any tooling depending on the original simics format
// keeps working.
//
static void asan_emit_syz_report(UINTN addr, UINTN ip, UINT8 shadow_val) {
  CHAR8 NumStr[19];
  SerialOutput("==ERROR: AddressSanitizer: ");
  SerialOutput(asan_shadow_to_bug_string(shadow_val));
  SerialOutput(" on address ");
  Num2Str64bit(addr, NumStr);
  SerialOutput(NumStr);
  SerialOutput(" at pc ");
  Num2Str64bit(ip, NumStr);
  SerialOutput(NumStr);
  SerialOutput("\n");
}

void asan_bug_report2(UINTN addr, UINTN size,
                      UINTN buggy_shadow_address, UINT8 is_write,
                      UINTN ip, CHAR8 *file, UINTN line) {
  UINTN buggy_address = SHADOW_TO_MEM(buggy_shadow_address);
  UINT8 shadow_val = *(UINT8 *)buggy_shadow_address;
  asan_emit_syz_report(addr, ip, shadow_val);

  // printf("[ASan] ===================================================\n");
  SerialOutput("[ASan] ===================================================\n");
  // printf(
  //     "[ASan] ERROR: Invalid memory access: address 0x%X, size 0x%X, is_write "
  //     "%d, ip 0x%X\n",
  //     addr, size, is_write, ip);
  CHAR8 NumStr[19];
  SerialOutput("[ASan] ERROR: Invalid memory access: address ");
  Num2Str64bit(addr, NumStr);
  SerialOutput(NumStr);
  SerialOutput(", size ");
  Num2Str64bit(size, NumStr);
  SerialOutput(NumStr);
  SerialOutput(", is_write ");
  Num2Str64bit(is_write, NumStr);
  SerialOutput(NumStr);
  SerialOutput(", ip ");
  Num2Str64bit(ip, NumStr);
  SerialOutput(NumStr);
  SerialOutput("\n");
  asan_print_bug2(addr, size, file, line);

  asan_print_shadow_memory2(buggy_address, 3, 3);
  // ASAN_ASSERT(FALSE);
}

// -------------------------- Run-time entry ------------------- {{{1
// exported functions
#define ASAN_REPORT_ERROR(type, is_write, size)                     \
void __asan_report_ ## type ## size(UINTN addr) {                   \
  CHAR8 NumStr[19];                             \
  Num2Str8bit ( size , NumStr);                         \
  SerialOutput ("__asan_report_");                     \
  SerialOutput (NumStr);                            \
  SerialOutput (" is called\n");                     \
  UINTN buggy_shadow_address = MEM_TO_SHADOW(addr);                                  \
  UINTN ip = (UINTN)__builtin_return_address(0);                                     \
  asan_bug_report2(addr, size, buggy_shadow_address, is_write, ip, __FILE__, __LINE__); \
}                                                                   \

ASAN_REPORT_ERROR(load, FALSE, 1)
ASAN_REPORT_ERROR(load, FALSE, 2)
ASAN_REPORT_ERROR(load, FALSE, 4)
ASAN_REPORT_ERROR(load, FALSE, 8)
ASAN_REPORT_ERROR(load, FALSE, 16)
ASAN_REPORT_ERROR(store, TRUE, 1)
ASAN_REPORT_ERROR(store, TRUE, 2)
ASAN_REPORT_ERROR(store, TRUE, 4)
ASAN_REPORT_ERROR(store, TRUE, 8)
ASAN_REPORT_ERROR(store, TRUE, 16)

#define ASAN_REPORT_ERROR_N(type, is_write)                                 \
void __asan_report_ ## type ## _n(UINTN addr, UINTN size) {                 \
  CHAR8 NumStr[19];                             \
  Num2Str8bit ( size , NumStr);                         \
  SerialOutput ("__asan_report_");                     \
  SerialOutput (NumStr);                            \
  SerialOutput ("_n is called\n");                     \
  UINTN buggy_shadow_address = MEM_TO_SHADOW(addr);                                  \
  UINTN ip = (UINTN)__builtin_return_address(0);                                     \
  asan_bug_report2(addr, size, buggy_shadow_address, is_write, ip, __FILE__, __LINE__); \
}  \

ASAN_REPORT_ERROR_N(load, FALSE)
ASAN_REPORT_ERROR_N(store, TRUE)



#define DEFINE_ASAN_REPORT_LOAD_NOABORT(size)             \
void __asan_report_load##size##_noabort(UINTN addr)       \
{                                                         \
  SerialOutput ("__asan_report_load _noabort");           \
  UINTN buggy_shadow_address = MEM_TO_SHADOW(addr);                                  \
  UINTN ip = (UINTN)__builtin_return_address(0);                                     \
  asan_bug_report2(addr, size, buggy_shadow_address, 0, ip, __FILE__, __LINE__); \
}                                                        


#define DEFINE_ASAN_REPORT_STORE_NOABORT(size)                     \
void __asan_report_store##size##_noabort(UINTN addr) \
{                                                          \
  SerialOutput ("__asan_report_store _noabort");           \
  UINTN buggy_shadow_address = MEM_TO_SHADOW(addr);                                  \
  UINTN ip = (UINTN)__builtin_return_address(0);                                     \
  asan_bug_report2(addr, size, buggy_shadow_address, 1, ip, __FILE__, __LINE__); \
}                                                   


DEFINE_ASAN_REPORT_LOAD_NOABORT(1);
DEFINE_ASAN_REPORT_LOAD_NOABORT(2);
DEFINE_ASAN_REPORT_LOAD_NOABORT(4);
DEFINE_ASAN_REPORT_LOAD_NOABORT(8);
DEFINE_ASAN_REPORT_LOAD_NOABORT(16);
DEFINE_ASAN_REPORT_STORE_NOABORT(1);
DEFINE_ASAN_REPORT_STORE_NOABORT(2);
DEFINE_ASAN_REPORT_STORE_NOABORT(4);
DEFINE_ASAN_REPORT_STORE_NOABORT(8);
DEFINE_ASAN_REPORT_STORE_NOABORT(16);

void __asan_report_load_n_noabort(UINTN addr, UINTN size)
{
  SerialOutput ("__asan_report_load_n_noabort");
  UINTN buggy_shadow_address = MEM_TO_SHADOW(addr);                                  \
  UINTN ip = (UINTN)__builtin_return_address(0);                                     \
  asan_bug_report2(addr, size, buggy_shadow_address, 0, ip, __FILE__, __LINE__); \
}


void __asan_report_store_n_noabort(UINTN addr, UINTN size)
{
  SerialOutput ("__asan_report_store_n_noabort");
  UINTN buggy_shadow_address = MEM_TO_SHADOW(addr);                                  \
  UINTN ip = (UINTN)__builtin_return_address(0);                                     \
  asan_bug_report2(addr, size, buggy_shadow_address, 1, ip, __FILE__, __LINE__); \
}


#define SANITIZER_CALLSTACK_DUMP(fun_name)                                \
{                                                                         \
  SerialOutput2 ("ASAN MEMORY ACCESS check fail! ");                      \
  gSerialOutputSwitch = 1;                                                \
  SerialOutput2 (fun_name);                                               \
  SerialOutput (" is called:\n");                                         \
  SerialOutput ("Return IP address is ");                                 \
  SerialOutput ("\n");                                                    \
  HARNESS_ASSERT();                                                       \
}
    // CHAR8 NumStr[19];                                                       \
  // Num2Str64bit ((UINTN)__builtin_return_address(0),NumStr);       \
  // SerialOutput (NumStr);                                                  \

  // Num2Str64bit ((UINTN)__builtin_return_address(1),NumStr);       \
  // SerialOutput (NumStr);                                                  \
  // SerialOutput ("\n");                                                    \
  // Num2Str64bit ((UINTN)__builtin_return_address(2),NumStr);       \
  // SerialOutput (NumStr);                                                  \
  // SerialOutput ("\n");                                                    \
  // Num2Str64bit ((UINTN)__builtin_return_address(3),NumStr);       \
  // SerialOutput (NumStr);                                                  \
  // SerialOutput ("\n");                                                    \
  // Num2Str64bit ((UINTN)__builtin_return_address(4),NumStr);       \
  // SerialOutput (NumStr);                                                  \
  // SerialOutput ("\n");                                                    \
  // Num2Str64bit ((UINTN)__builtin_return_address(5),NumStr);       \
  // SerialOutput (NumStr);                                                  \
  // SerialOutput ("\n");                                                    \
//
// Note: Using __builtin_return_address(1~n) in below code might cause CPU exception
// because the call stack during running don't always have n deep in fact. You can just 
// remove the "Num2Str64bit ((UINTN)__builtin_return_address(n),NumStr)" in 
// below macro.
// But I still leave the __builtin_return_address(1~n) here to permit the execution 
// stop intentionally when memory check fails, because I more hope to trace the call 
// stack details info.
// 
#define DEFINE_ASAN_LOAD(size)                      \
void __asan_load##size(UINTN addr)          \
{                                                   \
  CHAR8 NumStr[19];                                 \
  if (asan_inited && !asan_is_deactivated){         \
    UINTN sp = MEM_TO_SHADOW(addr);                                                 \
    if(mAsanShadowMemoryStart <= sp && sp <= mAsanShadowMemoryEnd) {                \
      UINTN s = size <= SHADOW_GRANULARITY ? *(UINT8 *)(sp)                         \
                                          : *(UINT16 *)(sp);                        \
      if (s) {                                                                      \
        if ((size >= SHADOW_GRANULARITY) || (                                       \
                     ((INT8)((addr & (SHADOW_GRANULARITY - 1)) + size - 1)) >=      \
                         (INT8)s)) {                                                \
              SerialOutput2 ("ASAN MEMORY ACCESS check fail! ");                    \
              gSerialOutputSwitch = 1;                                              \
              Num2Str8bit ( size , NumStr);                                         \
              SerialOutput ("__asan_load");                                         \
              SerialOutput (NumStr);                                                \
              SerialOutput (" is called\n");                                         \
              SerialOutput ("Return IP address is ");                                 \
              Num2Str64bit ((UINTN)__builtin_return_address(0),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(1),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(2),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(3),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(4),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(5),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(6),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(7),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(8),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\nAccess Address= ");                                    \
              Num2Str64bit (addr, NumStr);                                            \
              SerialOutput (NumStr);                                                  \
              SerialOutput (", Shadow Memory Address= ");                             \
              Num2Str64bit ( sp , NumStr);                                            \
              SerialOutput (NumStr);                                                  \
              SerialOutput (", Shadow Memory content= ");                             \
              Num2Str64bit ( s , NumStr);                                             \
              SerialOutput (NumStr);                                                  \
              SerialOutput (", (addr & (SHADOW_GRANULARITY - 1)) + size - 1)= ");     \
              Num2Str64bit (((addr & (SHADOW_GRANULARITY - 1)) + size - 1), NumStr);  \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n\n");                                                  \
              UINTN buggy_shadow_address = MEM_TO_SHADOW(addr);                                  \
              UINTN ip = (UINTN)__builtin_return_address(0);                                     \
              asan_bug_report2(addr, size, buggy_shadow_address, 0, ip, __FILE__, __LINE__); \
        }                                                                             \
      }                                                                               \
    }                                                                                 \
  }                                                                                   \
}



#define DEFINE_ASAN_STORE(size)                     \
void __asan_store##size(UINTN addr)         \
{                                                   \
  CHAR8 NumStr[19];                                 \
  if (asan_inited && !asan_is_deactivated){         \
    UINTN sp = MEM_TO_SHADOW(addr);                                                 \
    if(mAsanShadowMemoryStart <= sp && sp <= mAsanShadowMemoryEnd) {                \
      UINTN s = size <= SHADOW_GRANULARITY ? *(UINT8 *)(sp)                         \
                                          : *(UINT16 *)(sp);                        \
      if (s) {                                                                      \
        if ((size >= SHADOW_GRANULARITY) || (                                       \
                     ((INT8)((addr & (SHADOW_GRANULARITY - 1)) + size - 1)) >=      \
                         (INT8)s)) {                                                \
              SerialOutput2 ("ASAN MEMORY ACCESS check fail! ");                    \
              gSerialOutputSwitch = 1;                                              \
              Num2Str8bit ( size , NumStr);                                         \
              SerialOutput ("__asan_store");                                        \
              SerialOutput (NumStr);                                                \
              SerialOutput (" is called\n");                                          \
              SerialOutput ("Return IP address is ");                                 \
              Num2Str64bit ((UINTN)__builtin_return_address(0),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(1),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(2),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(3),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(4),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(5),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(6),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(7),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(8),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\nAccess Address= ");                                    \
              Num2Str64bit (addr, NumStr);                                            \
              SerialOutput (NumStr);                                                  \
              SerialOutput (", Shadow Memory Address= ");                             \
              Num2Str64bit ( sp , NumStr);                                            \
              SerialOutput (NumStr);                                                  \
              SerialOutput (", Shadow Memory content= ");                             \
              Num2Str64bit ( s , NumStr);                                             \
              SerialOutput (NumStr);                                                  \
              SerialOutput (", (addr & (SHADOW_GRANULARITY - 1)) + size - 1)= ");     \
              Num2Str64bit (((addr & (SHADOW_GRANULARITY - 1)) + size - 1), NumStr);  \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n\n");                                                  \
              UINTN buggy_shadow_address = MEM_TO_SHADOW(addr);                                  \
              UINTN ip = (UINTN)__builtin_return_address(0);                                     \
              asan_bug_report2(addr, size, buggy_shadow_address, 1, ip, __FILE__, __LINE__); \
        }                                                                             \
      }                                                                               \
    }                                                                                 \
  }                                                                                   \
}

#define DEFINE_ASAN_LOAD_NOABORT(size)                \
void __asan_load##size##_noabort(UINTN addr)  \
{                                                   \
  CHAR8 NumStr[19];                                 \
  if (asan_inited && !asan_is_deactivated){         \
    UINTN sp = MEM_TO_SHADOW(addr);                                                 \
    if(mAsanShadowMemoryStart <= sp && sp <= mAsanShadowMemoryEnd) {                \
      UINTN s = size <= SHADOW_GRANULARITY ? *(UINT8 *)(sp)                         \
                                          : *(UINT16 *)(sp);                        \
      if (s) {                                                                      \
        if ((size >= SHADOW_GRANULARITY) || (                                       \
                     ((INT8)((addr & (SHADOW_GRANULARITY - 1)) + size - 1)) >=      \
                         (INT8)s)) {                                                \
              SerialOutput2 ("ASAN MEMORY ACCESS check fail! ");                    \
              gSerialOutputSwitch = 1;                                              \
              Num2Str8bit ( size , NumStr);                                         \
              SerialOutput ("__asan_load");                                         \
              SerialOutput (NumStr);                                                \
              SerialOutput ("_noabort is called\n");                                  \
              SerialOutput ("Return IP address is ");                                 \
              Num2Str64bit ((UINTN)__builtin_return_address(0),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(1),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(2),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(3),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(4),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(5),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(6),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(7),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              SerialOutput ("Access Address= ");                                   \
              Num2Str64bit (addr, NumStr);                                            \
              SerialOutput (NumStr);                                                  \
              SerialOutput (", Shadow Memory Address= ");                             \
              Num2Str64bit ( sp , NumStr);                                            \
              SerialOutput (NumStr);                                                  \
              SerialOutput (", Shadow Memory content= ");                             \
              Num2Str64bit ( s , NumStr);                                             \
              SerialOutput (NumStr);                                                  \
              SerialOutput (", (addr & (SHADOW_GRANULARITY - 1)) + size - 1)= ");     \
              Num2Str64bit (((addr & (SHADOW_GRANULARITY - 1)) + size - 1), NumStr);  \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n\n");                                                  \
              UINTN buggy_shadow_address = MEM_TO_SHADOW(addr);                                  \
              UINTN ip = (UINTN)__builtin_return_address(0);                                     \
              asan_bug_report2(addr, size, buggy_shadow_address, 0, ip, __FILE__, __LINE__); \
        }                                                                             \
      }                                                                               \
    }                                                                                 \
  }                                                                                   \
}


#define DEFINE_ASAN_STORE_NOABORT(size)                 \
void __asan_store##size##_noabort(UINTN addr)   \
{                                                   \
  CHAR8 NumStr[19];                                 \
  if (asan_inited && !asan_is_deactivated){         \
    UINTN sp = MEM_TO_SHADOW(addr);                                                 \
    if(mAsanShadowMemoryStart <= sp && sp <= mAsanShadowMemoryEnd) {                \
      UINTN s = size <= SHADOW_GRANULARITY ? *(UINT8 *)(sp)                         \
                                          : *(UINT16 *)(sp);                        \
      if (s) {                                                                      \
        if ((size >= SHADOW_GRANULARITY) || (                                       \
                     ((INT8)((addr & (SHADOW_GRANULARITY - 1)) + size - 1)) >=      \
                         (INT8)s)) {                                                \
              SerialOutput2 ("ASAN MEMORY ACCESS check fail! ");                    \
              gSerialOutputSwitch = 1;                                              \
              Num2Str8bit ( size , NumStr);                                         \
              SerialOutput ("__asan_store");                                        \
              SerialOutput (NumStr);                                                \
              SerialOutput ("_noabort is called\n");                                  \
              SerialOutput ("Return IP address is ");                                 \
              Num2Str64bit ((UINTN)__builtin_return_address(0),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(1),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(2),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(3),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(4),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(5),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(6),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              Num2Str64bit ((UINTN)__builtin_return_address(7),NumStr);       \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n");                                                    \
              SerialOutput ("Access Address= ");                                      \
              Num2Str64bit (addr, NumStr);                                            \
              SerialOutput (NumStr);                                                  \
              SerialOutput (", Shadow Memory Address= ");                             \
              Num2Str64bit ( sp , NumStr);                                            \
              SerialOutput (NumStr);                                                  \
              SerialOutput (", Shadow Memory content= ");                             \
              Num2Str64bit ( s , NumStr);                                             \
              SerialOutput (NumStr);                                                  \
              SerialOutput (", (addr & (SHADOW_GRANULARITY - 1)) + size - 1)= ");     \
              Num2Str64bit (((addr & (SHADOW_GRANULARITY - 1)) + size - 1), NumStr);  \
              SerialOutput (NumStr);                                                  \
              SerialOutput ("\n\n");                                                  \
              UINTN buggy_shadow_address = MEM_TO_SHADOW(addr);                                  \
              UINTN ip = (UINTN)__builtin_return_address(0);                                     \
              asan_bug_report2(addr, size, buggy_shadow_address, 1, ip, __FILE__, __LINE__); \
        }                                                                             \
      }                                                                               \
    }                                                                                 \
  }                                                                                   \
}

DEFINE_ASAN_LOAD(1);
DEFINE_ASAN_LOAD(2);
DEFINE_ASAN_LOAD(4);
DEFINE_ASAN_LOAD(8);
DEFINE_ASAN_LOAD(16);
DEFINE_ASAN_STORE(1);
DEFINE_ASAN_STORE(2);
DEFINE_ASAN_STORE(4);
DEFINE_ASAN_STORE(8);
DEFINE_ASAN_STORE(16);
DEFINE_ASAN_LOAD_NOABORT(1);
DEFINE_ASAN_LOAD_NOABORT(2);
DEFINE_ASAN_LOAD_NOABORT(4);
DEFINE_ASAN_LOAD_NOABORT(8);
DEFINE_ASAN_LOAD_NOABORT(16);
DEFINE_ASAN_STORE_NOABORT(1);
DEFINE_ASAN_STORE_NOABORT(2);
DEFINE_ASAN_STORE_NOABORT(4);
DEFINE_ASAN_STORE_NOABORT(8);
DEFINE_ASAN_STORE_NOABORT(16);

static BOOLEAN AddressIsPoisoned(UINTN a) {
  if (asan_is_deactivated || !asan_inited){
    return FALSE;
  }

  UINT8 *shadow_address = (UINT8*)(UINTN)MEM_TO_SHADOW(a);
  if((UINT64)(UINTN)shadow_address < mAsanShadowMemoryStart || mAsanShadowMemoryEnd < (UINT64)(UINTN)shadow_address) {
    return FALSE;
  }
  INT8 shadow_value = *shadow_address;
  if (shadow_value) {
    UINT8 last_accessed_byte = (a & (SHADOW_GRANULARITY - 1));
    return (last_accessed_byte >= shadow_value);
  }
  return FALSE;
}

BOOLEAN mem_is_zero(const char *beg, UINTN size) {
  if (size > (1<< 30)){
    SerialOutput("mem_is_zero input size is too big\n");
  }
  const char *end = beg + size;
  UINTN *aligned_beg = (UINTN *)RoundUpTo((UINTN)beg, sizeof(UINTN));
  UINTN *aligned_end = (UINTN *)RoundDownTo((UINTN)end, sizeof(UINTN));
  UINTN all = 0;
  // Prologue.
  for (const char *mem = beg; mem < (char*)aligned_beg && mem < end; mem++)
    all |= *mem;
  // Aligned loop.
  for (; aligned_beg < aligned_end; aligned_beg++)
    all |= *aligned_beg;
  // Epilogue.
  if ((char*)aligned_end >= beg)
    for (const char *mem = (char*)aligned_end; mem < end; mem++)
      all |= *mem;
  return all == 0;
}


UINTN __asan_region_is_poisoned(UINTN beg, UINTN size) {
  if (asan_is_deactivated || !asan_inited){
    return 0;
  }

  if (!size) return 0;
  UINTN end = beg + size;
  if (beg > end){
    SerialOutput("__asan_region_is_poisoned inputs are wrong\n");
  }
  UINTN aligned_b = RoundUpTo(beg, SHADOW_GRANULARITY);
  UINTN aligned_e = RoundDownTo(end, SHADOW_GRANULARITY);
  UINTN shadow_beg = MEM_TO_SHADOW(aligned_b);
  UINTN shadow_end = MEM_TO_SHADOW(aligned_e);
  // First check the first and the last application bytes,
  // then check the SHADOW_GRANULARITY-aligned region by calling
  // mem_is_zero on the corresponding shadow.
  if (!AddressIsPoisoned(beg) &&
      !AddressIsPoisoned(end - 1) &&
      (shadow_end <= shadow_beg ||
       mem_is_zero((const char *)shadow_beg, shadow_end - shadow_beg))
      ){
      return 0;
      }

  // The fast check failed, so we have a poisoned byte somewhere.
  // Find it slowly.
  for (; beg < end; beg++)
    if (AddressIsPoisoned(beg))
      return beg;
  SerialOutput("mem_is_zero returned false, but poisoned byte was not found\n");
  return 0;
}


void __asan_loadN_noabort(UINTN addr, UINTN size)
{
  CHAR8 NumStr[19];

  if (asan_is_deactivated || !asan_inited){
    return;
  }

  if (__asan_region_is_poisoned(addr, size)) {
    SerialOutput2 ("__asan_loadN_noabort ASAN MEMORY ACCESS check fail! ");
    gSerialOutputSwitch = 1;
    UINTN sp = MEM_TO_SHADOW(addr);
    if(sp < mAsanShadowMemoryStart || mAsanShadowMemoryEnd < sp) {
      return;
    }
    UINTN s = size <= SHADOW_GRANULARITY ? *(UINT8 *)(sp): *(UINT16 *)(sp);
    Num2Str8bit ( size , NumStr);
    SerialOutput ("__asan_storeN_noabort");
    SerialOutput (NumStr);
    SerialOutput (" is called\n");
    SerialOutput ("Return IP address is ");
    Num2Str64bit ((UINTN)__builtin_return_address(0),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    Num2Str64bit ((UINTN)__builtin_return_address(1),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    Num2Str64bit ((UINTN)__builtin_return_address(2),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    Num2Str64bit ((UINTN)__builtin_return_address(3),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    Num2Str64bit ((UINTN)__builtin_return_address(4),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\nAccess Address= ");
    Num2Str64bit (addr, NumStr);
    SerialOutput (NumStr);
    SerialOutput (", Shadow Memory Address= ");
    Num2Str64bit ( sp , NumStr);
    SerialOutput (NumStr);
    SerialOutput (", Shadow Memory content= ");
    Num2Str64bit ( s , NumStr);
    SerialOutput (NumStr);
    SerialOutput (", (addr & (SHADOW_GRANULARITY - 1)) + size - 1)= ");
    Num2Str64bit (((addr & (SHADOW_GRANULARITY - 1)) + size - 1), NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n\n");
    UINTN buggy_shadow_address = MEM_TO_SHADOW(addr);                                  
    UINTN ip = (UINTN)__builtin_return_address(0);                                     
    asan_bug_report2(addr, size, buggy_shadow_address, 0, ip, __FILE__, __LINE__); 
  }
}

void __asan_storeN_noabort(UINTN addr, UINTN size)
{
  CHAR8 NumStr[19];
  if (asan_is_deactivated || !asan_inited){
    return ;
  }
  //SerialOutput ("__asan_storeN_noabort is called\n");
  if (__asan_region_is_poisoned(addr, size)) {
    SerialOutput2 ("__asan_storeN_noabort ASAN MEMORY ACCESS check fail! ");
    gSerialOutputSwitch = 1;
    UINTN sp = MEM_TO_SHADOW(addr);
    if(sp < mAsanShadowMemoryStart || mAsanShadowMemoryEnd < sp) {
      return;
    }
    UINTN s = size <= SHADOW_GRANULARITY ? *(UINT8 *)(sp): *(UINT16 *)(sp);
    Num2Str8bit ( size , NumStr);
    SerialOutput ("__asan_storeN_noabort");
    SerialOutput (NumStr);
    SerialOutput (" is called\n");
    SerialOutput ("Return IP address is ");
    Num2Str64bit ((UINTN)__builtin_return_address(0),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    Num2Str64bit ((UINTN)__builtin_return_address(1),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    Num2Str64bit ((UINTN)__builtin_return_address(2),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    Num2Str64bit ((UINTN)__builtin_return_address(3),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    Num2Str64bit ((UINTN)__builtin_return_address(4),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\nAccess Address= ");
    Num2Str64bit (addr, NumStr);
    SerialOutput (NumStr);
    SerialOutput (", Shadow Memory Address= ");
    Num2Str64bit ( sp , NumStr);
    SerialOutput (NumStr);
    SerialOutput (", Shadow Memory content= ");
    Num2Str64bit ( s , NumStr);
    SerialOutput (NumStr);
    SerialOutput (", (addr & (SHADOW_GRANULARITY - 1)) + size - 1)= ");
    Num2Str64bit (((addr & (SHADOW_GRANULARITY - 1)) + size - 1), NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n\n");
    UINTN buggy_shadow_address = MEM_TO_SHADOW(addr);                                  
    UINTN ip = (UINTN)__builtin_return_address(0);                                     
    asan_bug_report2(addr, size, buggy_shadow_address, 1, ip, __FILE__, __LINE__); 
  }
}

void __asan_loadN(UINTN addr, UINTN size)
{
  CHAR8 NumStr[19];
  if (asan_is_deactivated || !asan_inited){
    return ;
  }
  //SerialOutput ("__asan_loadN is called\n");
  if (__asan_region_is_poisoned(addr, size)) {
    SerialOutput2 ("__asan_loadN ASAN MEMORY ACCESS check fail! ");
    gSerialOutputSwitch = 1;
    UINTN sp = MEM_TO_SHADOW(addr);
    if(sp < mAsanShadowMemoryStart || mAsanShadowMemoryEnd < sp) {
      return;
    }
    UINTN s = size <= SHADOW_GRANULARITY ? *(UINT8 *)(sp): *(UINT16 *)(sp);
    Num2Str8bit ( size , NumStr);
    SerialOutput ("__asan_loadN");
    SerialOutput (NumStr);
    SerialOutput (" is called\n");
    SerialOutput ("Return IP address is ");
    Num2Str64bit ((UINTN)__builtin_return_address(0),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    Num2Str64bit ((UINTN)__builtin_return_address(1),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    Num2Str64bit ((UINTN)__builtin_return_address(2),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    Num2Str64bit ((UINTN)__builtin_return_address(3),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    Num2Str64bit ((UINTN)__builtin_return_address(4),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\nAccess Address= ");
    Num2Str64bit (addr, NumStr);
    SerialOutput (NumStr);
    SerialOutput (", Shadow Memory Address= ");
    Num2Str64bit ( sp , NumStr);
    SerialOutput (NumStr);
    SerialOutput (", Shadow Memory content= ");
    Num2Str64bit ( s , NumStr);
    SerialOutput (NumStr);
    SerialOutput (", (addr & (SHADOW_GRANULARITY - 1)) + size - 1)= ");
    Num2Str64bit (((addr & (SHADOW_GRANULARITY - 1)) + size - 1), NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n\n");
    UINTN buggy_shadow_address = MEM_TO_SHADOW(addr);                                  
    UINTN ip = (UINTN)__builtin_return_address(0);                                     
    asan_bug_report2(addr, size, buggy_shadow_address, 0, ip, __FILE__, __LINE__); 
  }
}

void __asan_storeN(UINTN addr, UINTN size)
{
  CHAR8 NumStr[19];
  if (asan_is_deactivated || !asan_inited){
    return ;
  }

  if (__asan_region_is_poisoned(addr, size)) {
    SerialOutput2 ("__asan_storeN ASAN MEMORY ACCESS check fail! ");
    gSerialOutputSwitch = 1;
    UINTN sp = MEM_TO_SHADOW(addr);
    if(sp < mAsanShadowMemoryStart || mAsanShadowMemoryEnd < sp) {
      return;
    }
    UINTN s = size <= SHADOW_GRANULARITY ? *(UINT8 *)(sp): *(UINT16 *)(sp);
    Num2Str8bit ( size , NumStr);
    SerialOutput ("__asan_storeN");
    SerialOutput (NumStr);
    SerialOutput (" is called\n");
    SerialOutput ("Return IP address is ");
    Num2Str64bit ((UINTN)__builtin_return_address(0),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    Num2Str64bit ((UINTN)__builtin_return_address(1),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    Num2Str64bit ((UINTN)__builtin_return_address(2),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    Num2Str64bit ((UINTN)__builtin_return_address(3),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    Num2Str64bit ((UINTN)__builtin_return_address(4),NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\nAccess Address= ");
    Num2Str64bit (addr, NumStr);
    SerialOutput (NumStr);
    SerialOutput (", Shadow Memory Address= ");
    Num2Str64bit ( sp , NumStr);
    SerialOutput (NumStr);
    SerialOutput (", Shadow Memory content= ");
    Num2Str64bit ( s , NumStr);
    SerialOutput (NumStr);
    SerialOutput (", (addr & (SHADOW_GRANULARITY - 1)) + size - 1)= ");
    Num2Str64bit (((addr & (SHADOW_GRANULARITY - 1)) + size - 1), NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n\n");
    UINTN buggy_shadow_address = MEM_TO_SHADOW(addr);                                  
    UINTN ip = (UINTN)__builtin_return_address(0);                                     
    asan_bug_report2(addr, size, buggy_shadow_address, 1, ip, __FILE__, __LINE__); 
  }
}

//\llvm\projects\compiler-rt\lib\asan\asan_fake_stack.cc
// ---------------------- Interface ---------------- {{{1
int __asan_option_detect_stack_use_after_return = 1;
UINTN __asan_shadow_memory_dynamic_address = 0x10000000;

UINTN 
EFIAPI
OnMalloc (
  IN UINTN  ID,
  IN UINTN  AllocationSize
  )
{
  // PoisonShadowMemory(ptr, size, /*poison=*/0);
//  DEBUG ((EFI_D_ERROR, "OnMalloc\n"));
  return 0;
}

void
EFIAPI
OnFree (
  IN UINTN  ptr,
  IN UINTN  ID,
  IN UINTN  AllocationSize
  )
{
  // PoisonShadowMemory(ptr, AllocationSize, /*poison=*/0xF1);
//  DEBUG ((EFI_D_ERROR, "OnFree\n"));
}

#define DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(class_id)                       \
  UINTN __asan_stack_malloc_##class_id(UINTN size) {                              \
    return OnMalloc(class_id, size);                                           \
  }                                                                            \
  void __asan_stack_free_##class_id(UINTN ptr, UINTN size) {                   \
    OnFree(ptr, class_id, size);                                               \
  }

DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(0)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(1)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(2)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(3)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(4)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(5)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(6)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(7)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(8)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(9)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(10)
void * Intrinsic_memset (void *dest, char ch, unsigned int count);



void __stack_chk_fail(void) {
  SerialOutput2 ("__stack_chk_fail ASAN MEMORY ACCESS check fail! ");
  gSerialOutputSwitch = 1;
  CHAR8 NumStr[19];
  Num2Str64bit ((UINTN)__builtin_return_address(0),NumStr);
  SerialOutput ("__stack_chk_fail is called, Return IP address is ");
  SerialOutput (NumStr);
  SerialOutput ("\n");
}

void __asan_set_shadow_00(UINTN addr, UINTN size) {
  Intrinsic_memset((void *)addr, 0, size);
}

void __asan_set_shadow_f1(UINTN addr, UINTN size) {
  Intrinsic_memset((void *)addr, 0xf1, size);
}

void __asan_set_shadow_f2(UINTN addr, UINTN size) {
  Intrinsic_memset((void *)addr, 0xf2, size);
}

void __asan_set_shadow_f3(UINTN addr, UINTN size) {
  Intrinsic_memset((void *)addr, 0xf3, size);
}

void __asan_set_shadow_f5(UINTN addr, UINTN size) {
  Intrinsic_memset((void *)addr, 0xf5, size);
}

void __asan_set_shadow_f8(UINTN addr, UINTN size) {
  Intrinsic_memset((void *)addr, 0xf8, size);
}

//
// This structure is used to describe the source location of a place where
// global was defined.
typedef struct{
  const char *filename;
  int line_no;
  int column_no;
}__asan_global_source_location;

//
// This structure describes an instrumented global variable.
//
typedef struct  {
  UINTN beg;                // The address of the global.
  UINTN size;               // The original size of the global.
  UINTN size_with_redzone;  // The size with the redzone.
  const char *name;        // Name as a C string.
  const char *module_name; // Module name as a C string. This pointer is a
                           // unique identifier of a module.
  UINTN has_dynamic_init;   // Non-zero if the global has dynamic initializer.
  __asan_global_source_location *location;  // Source location of a global,
                                            // or NULL if it is unknown.
  UINTN odr_indicator;      // The address of the ODR indicator symbol.
}__asan_global;

typedef __asan_global Global;

#define SHADOW_GRANULARITY (1ULL << SHADOW_SCALE)

#define EFI_DEADLOOP()    { volatile UINTN __iii; __iii = 1; while (__iii); }

BOOLEAN IsPowerOfTwo(UINTN x) {
  return (x & (x - 1)) == 0;
}

UINTN RoundUpTo(UINTN size, UINTN boundary) {
  if(!IsPowerOfTwo(boundary)){
    EFI_DEADLOOP();
  }
  return (size + boundary - 1) & ~(boundary - 1);
}

UINTN RoundDownTo(UINTN x, UINTN boundary) {
  return x & ~(boundary - 1);
}

static BOOLEAN AddrIsAlignedByGranularity(UINTN a) {
  return (a & (SHADOW_GRANULARITY - 1)) == 0;
}

//D:\Project\LLVM\llvm\projects\compiler-rt\lib\asan\asan_poisoning.h
// Fast versions of PoisonShadow and PoisonShadowPartialRightRedzone that
// assume that memory addresses are properly aligned. Use in
// performance-critical code with care.
void 
FastPoisonShadow(
  UINTN aligned_beg, 
  UINTN aligned_size,
  UINT8 value
  ) 
{
  //SerialOutput ("FastPoisonShadow begin\n");
  ASAN_ASSERT(AddrIsAlignedByGranularity(aligned_beg));
  ASAN_ASSERT(AddrIsAlignedByGranularity(aligned_size));

  UINTN shadow_beg = MEM_TO_SHADOW(aligned_beg);
  UINTN shadow_end = MEM_TO_SHADOW(
      aligned_beg + aligned_size - SHADOW_GRANULARITY) + 1;

  Intrinsic_memset((void*)shadow_beg, value, shadow_end - shadow_beg);

}

void
FastPoisonShadowPartialRightRedzone(
  UINTN aligned_addr,
  UINTN size,
  UINTN size_with_redzone,
  UINT8 value
  )
{
  //SerialOutput ("FastPoisonShadowPartialRightRedzone begin\n");
  ASAN_ASSERT(AddrIsAlignedByGranularity(aligned_addr));
  UINT8 *shadow = (UINT8*)(UINTN)MEM_TO_SHADOW(aligned_addr);
  for (UINTN i = 0; i < size_with_redzone; i += SHADOW_GRANULARITY, shadow++) {
    if (i + SHADOW_GRANULARITY <= size) {
      *shadow = 0;  // fully addressable
    } else if (i >= size) {
      *shadow = (SHADOW_GRANULARITY == 128) ? 0xff : value;  // unaddressable
    } else {
      // first size-i bytes are addressable
      *shadow = (UINT8)(size - i);
    }
  }
}

UINTN
ComputePoolRightRedzoneSize(
  IN UINTN user_requested_size
  )
{
  UINTN rz_size =
    user_requested_size <= 64        - 16   ? 16 :
    user_requested_size <= 128       - 32   ? 32 :
    user_requested_size <= 512       - 64   ? 64 :
    user_requested_size <= 4096      - 128  ? 128 :
    user_requested_size <= (1 << 14) - 256  ? 256 :
    user_requested_size <= (1 << 15) - 512  ? 512 :
    user_requested_size <= (1 << 16) - 1024 ? 1024 : 2048;
  return rz_size;
}

//D:\Project\LLVM\llvm\projects\compiler-rt\lib\asan\asan_globals.cc
// void PoisonShadowForGlobal(const Global *g, UINT8 value) {
  // FastPoisonShadow(g->beg, g->size_with_redzone, value);
// }
void
PoisonPool(
  IN const UINTN Addr,
  IN UINTN Size,
  IN const UINT8 value
  )
{
  UINTN aligned_addr;

  //SerialOutput ("PoisonPool begin, ");
  //CHAR8 NumStr[19];

  // SerialOutput ("Addr=");
  // Num2Str64bit ( Addr , NumStr);
  // SerialOutput (NumStr);
  // SerialOutput ("\n");
  if (asan_is_deactivated || !asan_inited){
    return ;
  }

  ASAN_ASSERT(Size != 0);

  aligned_addr = RoundUpTo(Addr, SHADOW_GRANULARITY);
  Size -= (aligned_addr - Addr);
  UINT8 *shadow = (UINT8*)(UINTN)MEM_TO_SHADOW(Addr);
  *shadow = (UINT8)(SHADOW_GRANULARITY - (aligned_addr - Addr));

  // SerialOutput ("aligned_addr=");
  // Num2Str64bit ( aligned_addr , NumStr);
  // SerialOutput (NumStr);
  // SerialOutput ("\n");
  // SerialOutput ("*shadow=");
  // Num2Str64bit ( *shadow , NumStr);
  // SerialOutput (NumStr);
  // SerialOutput ("\n");

  ASAN_ASSERT(AddrIsAlignedByGranularity(aligned_addr));

  UINTN aligned_End = RoundDownTo(aligned_addr + Size -1, SHADOW_GRANULARITY);
  ASAN_ASSERT (aligned_End <= (aligned_addr + Size -1));
  FastPoisonShadow(aligned_addr, aligned_End - aligned_addr, value);

  if (aligned_End < (aligned_addr + Size -1)) {
    ASAN_ASSERT ((aligned_addr + Size -1 - aligned_End) < SHADOW_GRANULARITY);
    UINT8 *shadow = (UINT8*)(UINTN)MEM_TO_SHADOW(aligned_addr + Size - 1);
    // first size-i bytes are addressable
    *shadow = (UINT8)(aligned_addr + Size -1 - aligned_End);
  }

}

void 
UnpoisonPool(
  IN const UINTN Addr,
  IN UINTN Size
  )
{
  UINTN aligned_addr;

  //SerialOutput ("UnpoisonPool begin\n");
  if (asan_is_deactivated || !asan_inited){
    return ;
  }

  ASAN_ASSERT(Size != 0);

  aligned_addr = RoundUpTo(Addr, SHADOW_GRANULARITY);
  Size -= (aligned_addr - Addr);
  UINT8 *shadow = (UINT8*)(UINTN)MEM_TO_SHADOW(Addr);
  *shadow = 0;

  ASAN_ASSERT(AddrIsAlignedByGranularity(aligned_addr));

  UINTN aligned_End = RoundDownTo(aligned_addr + Size - 1, SHADOW_GRANULARITY);
  ASAN_ASSERT (aligned_End <= (aligned_addr + Size -1));
  FastPoisonShadow(aligned_addr, aligned_End - aligned_addr, 0);

  if (aligned_End < (aligned_addr + Size -1)) {
    ASAN_ASSERT ((aligned_addr + Size -1 - aligned_End) < SHADOW_GRANULARITY);
    UINT8 *shadow = (UINT8*)(UINTN)MEM_TO_SHADOW(aligned_addr + Size -1);
    *shadow = 0;
  }
}


void PoisonPages (
  IN const UINT64 Start,
  IN const UINTN  PageNum,
  IN const UINT8  Value
  )
{
  //SerialOutput ("PoisonPages begin\n");
  if (asan_is_deactivated || !asan_inited){
    return ;
  }

  FastPoisonShadow(Start, EFI_PAGES_TO_SIZE(PageNum), kAsanInternalHeapMagic);
}

void UnpoisonPages (
  IN const UINT64 Start,
  IN const UINTN  PageNum
  )
{
  //SerialOutput ("UnpoisonPages begin\n");
  if (asan_is_deactivated || !asan_inited){
    return ;
  }

  FastPoisonShadow(Start, EFI_PAGES_TO_SIZE(PageNum), 0);
}


void PoisonGlobalRedZone(const __asan_global *g) {
  //SerialOutput ("PoisonGlobalRedZone begin\n");
  UINTN aligned_size = RoundUpTo(g->size, SHADOW_GRANULARITY);
  FastPoisonShadow(g->beg + aligned_size, g->size_with_redzone - aligned_size,
                   kAsanGlobalRedzoneMagic);

  if (g->size != aligned_size) {
    FastPoisonShadowPartialRightRedzone(
        g->beg + RoundDownTo(g->size, SHADOW_GRANULARITY),
        g->size % SHADOW_GRANULARITY,
        SHADOW_GRANULARITY,
        kAsanGlobalRedzoneMagic);
  }

  // UINTN shadow_beg = MEM_TO_SHADOW(g->beg);
  // UINTN shadow_end = MEM_TO_SHADOW(g->beg + g->size_with_redzone);
  // CHAR8 NumStr[19];

  // SerialOutput ("shadow_beg: ");
  // Num2Str64bit ( shadow_beg , NumStr);
  // SerialOutput (NumStr);
  // SerialOutput (", shadow_end: ");
  // Num2Str64bit ( shadow_end , NumStr);
  // SerialOutput (NumStr);
  // SerialOutput ("\n");
  // for (UINT8 *ptr = (UINT8 *)shadow_beg; (UINTN) ptr < shadow_end; ptr++){
    // Num2Str8bit ( *ptr , NumStr);
    // SerialOutput (NumStr);
    // SerialOutput (",");
  // }
  // SerialOutput ("\n");

}

static void UnpoisonGlobal(const __asan_global *g) {
  //SerialOutput ("UnpoisonGlobal begin\n");
  UnpoisonPool(g->beg, g->size);
}

static void register_global(const __asan_global *global)
{
  // SerialOutput ("register_global begin\n");
  // CHAR8 NumStr[19];
  // SerialOutput ("name: ");
  // SerialOutput (global->name);
  // SerialOutput (",module_name: ");
  // SerialOutput (global->module_name);
  // SerialOutput (",size: ");
  // Num2Str64bit ( global->size , NumStr);
  // SerialOutput (NumStr);
  // SerialOutput (",size_with_redzone: ");
  // Num2Str64bit ( global->size_with_redzone , NumStr);
  // SerialOutput (NumStr);
  // SerialOutput (",beg: ");
  // Num2Str64bit ( global->beg , NumStr);
  // SerialOutput (NumStr);
  // SerialOutput (",has_dynamic_init: ");
  // Num2Str64bit ( global->has_dynamic_init , NumStr);
  // SerialOutput (NumStr);
  // SerialOutput ("\n");
  // if (global->has_dynamic_init == 0){
    // SerialOutput ("line_no: ");
    // Num2Str64bit ( global->location->line_no , NumStr);
    // SerialOutput (NumStr);
    // SerialOutput (",column_no: ");
    // Num2Str64bit ( global->location->column_no , NumStr);
    // SerialOutput (NumStr);
    // SerialOutput ("\n");
  // }

  // if (global->location !=0){
    // DEBUG ((EFI_D_ERROR, "location= 0x%x,", global->location));
    // DEBUG ((EFI_D_ERROR, "location filename: %s,", global->location->filename));
    // DEBUG ((EFI_D_ERROR, "location line_no: 0x%x,", global->location->line_no));
    // DEBUG ((EFI_D_ERROR, "column_no: 0x%x\n", global->location->column_no));
  // }

  UnpoisonGlobal (global);
  PoisonGlobalRedZone (global);

}

// Register an array of globals.
void __asan_register_globals(__asan_global *globals, UINTN size) {
  //SerialOutput ("__asan_register_globals is called\n");

  UINTN Index;
  for (Index = 0; Index < size; Index++){
    register_global(&globals[Index]);
  }

}


// Unregister an array of globals.
// We must do this when a shared objects gets dlclosed.
void __asan_unregister_globals(__asan_global *globals, UINTN n) {
  SerialOutput ("__asan_unregister_globals is called\n");
}

void __asan_register_elf_globals(UINTN *flag, void *start, void *stop) {
  if (*flag) return;
  if (!start) return;
  __asan_global *globals_start = (__asan_global*)start;
  __asan_global *globals_stop = (__asan_global*)stop;
  __asan_register_globals(globals_start, globals_stop - globals_start);
  *flag = 1;
}

void __asan_unregister_elf_globals(UINTN *flag, void *start, void *stop) {
  if (!*flag) return;
  if (!start) return;
  __asan_global *globals_start = (__asan_global*)start;
  __asan_global *globals_stop = (__asan_global*)stop;
  __asan_unregister_globals(globals_start, globals_stop - globals_start);
  *flag = 0;
}

void __asan_init() {
  //SerialOutput ("__asan_init is called\n");
  //
  // asan_is_deactivated flag is initialized in AsanLibConstructor
  //
  if (!asan_is_deactivated) return; 


}

void __asan_version_mismatch_check_v8() {
  // SerialOutput ("__asan_version_mismatch_check_v8 is called\n");
}

void __asan_version_mismatch_check_v6() {
  // SerialOutput ("__asan_version_mismatch_check_v6 is called\n");
}

VOID *
EFIAPI
Intrinsic_CopyMem (
  OUT     VOID                      *DestinationBuffer,
  IN      CONST VOID                *SourceBuffer,
  IN      UINTN                     Length
  );

void * __asan_memcpy (void *dest, const void *src, unsigned int count)
{
  return Intrinsic_CopyMem (dest, src, (UINTN)count);
}

void * __asan_memset (void *dest, char ch, unsigned int count)
{
  return Intrinsic_memset (dest, ch, count);
}

void __asan_alloca_poison(UINTN addr, UINTN size) {
  SerialOutput ("__asan_alloca_poison is called ");
  PoisonPool(addr, size, kAsanStackMidRedzoneMagic);
}

void __asan_allocas_unpoison(UINTN top, UINTN bottom) {
  SerialOutput ("__asan_allocas_unpoison is called ");
  UnpoisonPool(top, (bottom - top));
}

void __asan_handle_no_return() {

}

void __asan_poison_stack_memory(UINTN addr, UINTN size) {
  SerialOutput ("__asan_poison_stack_memory is called ");
  PoisonPool(addr, size, kAsanStackMidRedzoneMagic);
}

void __asan_unpoison_stack_memory(UINTN addr, UINTN size) {
  SerialOutput ("__asan_unpoison_stack_memory is called ");
  UnpoisonPool(addr, size);
}

void __edk2_sanitizer_trap() {
  SANITIZER_CALLSTACK_DUMP("__edk2_sanitizer_trap");
}

struct TypeDescriptor {
  UINT16 TypeKind;
  UINT16 TypeInfo;
  char TypeName[1];
};

struct SourceLocation {
  const char *file_name;
  UINT32 line;
  UINT32 column;
};

struct OverflowDescData {
	struct SourceLocation Loc;
};

struct TypeMismatchData {
  struct SourceLocation Loc;
  struct TypeDescriptor *Type;
  unsigned char LogAlignment;
  unsigned char TypeCheckKind;
};

const char *TypeCheckKinds[] = {
    "load of", "store to", "reference binding to", "member access within",
    "member call on", "constructor call on", "downcast of", "downcast of",
    "upcast of", "cast to virtual base of", "_Nonnull binding to"
};

void __ubsan_handle_invalid_builtin(struct TypeMismatchData *Data, UINTN Pointer) {
  CHAR8 NumStr[19];
  SerialOutput (Data->Loc.file_name);
  SerialOutput (", line:");
  Num2Str16bit (Data->Loc.line, NumStr);
  SerialOutput (NumStr);
  SerialOutput (", column:");
  Num2Str16bit (Data->Loc.column, NumStr);
  SerialOutput (NumStr);
  SerialOutput (" ErrorType = ");
  SerialOutput ("InvalidBuiltin\n");
}

void __ubsan_handle_type_mismatch(struct TypeMismatchData *Data, UINTN Pointer) {
  CHAR8 NumStr[19];
  SerialOutput (Data->Loc.file_name);
  SerialOutput (", line:");
  Num2Str16bit (Data->Loc.line, NumStr);
  SerialOutput (NumStr);
  SerialOutput (", column:");
  Num2Str16bit (Data->Loc.column, NumStr);
  SerialOutput (NumStr);
  SerialOutput (" ErrorType = ");

  UINTN Alignment = (UINTN)1 << Data->LogAlignment;
  if (!Pointer){
    SerialOutput ("NullPointerUse: ");
    SerialOutput (TypeCheckKinds[Data->TypeCheckKind]);
    SerialOutput (" null pointer of type ");
    SerialOutput (Data->Type->TypeName);
    SerialOutput ("\n");
  } else if (Pointer & (Alignment - 1)){
    SerialOutput ("MisalignedPointerUse: ");
    SerialOutput (TypeCheckKinds[Data->TypeCheckKind]);
    SerialOutput (" misaligned address ");
    Num2Str64bit (Pointer, NumStr);
    SerialOutput (NumStr);
    SerialOutput (" for type ");
    SerialOutput (Data->Type->TypeName);
    SerialOutput (" which requires ");
    Num2Str16bit (Alignment, NumStr);
    SerialOutput (NumStr);
    SerialOutput (" byte alignment\n");
  } else {
    SerialOutput ("InsufficientObjectSize\n");
  }

  // UINTN buggy_shadow_address = MEM_TO_SHADOW(Pointer);                                  
  // UINTN ip = (UINTN)__builtin_return_address(0);                                     
  // asan_bug_report2(Pointer, size, buggy_shadow_address, TRUE, ip, Data->Loc.file_name, Data->Loc.line); 

  // SANITIZER_CALLSTACK_DUMP("__ubsan_handle_type_mismatch");
}

void __ubsan_handle_type_mismatch_v1(struct TypeMismatchData *Data, UINTN Pointer) {
  CHAR8 NumStr[19];
  SerialOutput (Data->Loc.file_name);
  SerialOutput (", line:");
  Num2Str16bit (Data->Loc.line, NumStr);
  SerialOutput (NumStr);
  SerialOutput (", column:");
  Num2Str16bit (Data->Loc.column, NumStr);
  SerialOutput (NumStr);
  SerialOutput (" ErrorType = ");

  UINTN Alignment = (UINTN)1 << Data->LogAlignment;
  if (!Pointer){
    SerialOutput ("NullPointerUse: ");
    SerialOutput (TypeCheckKinds[Data->TypeCheckKind]);
    SerialOutput (" null pointer of type ");
    SerialOutput (Data->Type->TypeName);
    SerialOutput ("\n");
  } else if (Pointer & (Alignment - 1)){
    SerialOutput ("MisalignedPointerUse: ");
    SerialOutput (TypeCheckKinds[Data->TypeCheckKind]);
    SerialOutput (" misaligned address ");
    Num2Str64bit (Pointer, NumStr);
    SerialOutput (NumStr);
    SerialOutput (" for type ");
    SerialOutput (Data->Type->TypeName);
    SerialOutput (" which requires ");
    Num2Str16bit (Alignment, NumStr);
    SerialOutput (NumStr);
    SerialOutput (" byte alignment\n");
  } else {
    SerialOutput ("InsufficientObjectSize\n");
  }

  // SANITIZER_CALLSTACK_DUMP("__ubsan_handle_type_mismatch_v1");
}

void __ubsan_handle_type_mismatch_v1_abort(UINTN *Data, UINTN Pointer) {
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_type_mismatch_v1_abort");
}

struct shift_out_of_bounds_data {
  struct SourceLocation location;
  struct TypeDescriptor *lhs_type;
  struct TypeDescriptor *rhs_type;
};


void __ubsan_handle_shift_out_of_bounds(struct shift_out_of_bounds_data *Data, UINTN LHS, UINTN RHS) {
  CHAR8 NumStr[19];
  SerialOutput (Data->location.file_name);
  SerialOutput (", line:");
  Num2Str16bit (Data->location.line, NumStr);
  SerialOutput (NumStr);
  SerialOutput (", column:");
  Num2Str16bit (Data->location.column, NumStr);
  SerialOutput (NumStr);
  SerialOutput ("\n");

  SerialOutput ("LHS:");
  Num2Str64bit (LHS, NumStr);
  SerialOutput (NumStr);
  SerialOutput (" RHS:");
  Num2Str64bit (RHS, NumStr);
  SerialOutput (NumStr);
  SerialOutput ("\n");

  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_shift_out_of_bounds");
}

void __ubsan_handle_shift_out_of_bounds_abort(UINTN *Data, UINTN LHS, UINTN RHS) {
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_shift_out_of_bounds_abort");
}

void __ubsan_handle_divrem_overflow(UINTN *Data, UINTN LHS, UINTN RHS) {
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_divrem_overflow");
}

void __ubsan_handle_divrem_overflow_abort(UINTN *Data, UINTN LHS, UINTN RHS) {
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_divrem_overflow_abort");
}

void __ubsan_handle_out_of_bounds(UINTN *Data, UINTN Index) {
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_out_of_bounds");
}

void __ubsan_handle_out_of_bounds_abort(UINTN *Data, UINTN Index) {
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_out_of_bounds_abort");
}

void __ubsan_handle_negate_overflow(UINTN *Data, UINTN OldVal) {
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_negate_overflow");
}

void __ubsan_handle_negate_overflow_abort(UINTN *Data, UINTN OldVal) {
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_negate_overflow_abort");
}

void __ubsan_handle_builtin_unreachable(UINTN *Data) {
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_builtin_unreachable");
}

void __ubsan_handle_add_overflow(UINTN *Data, UINTN LHS, UINTN RHS) {
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_add_overflow");
}

void __ubsan_handle_add_overflow_abort(UINTN *Data, UINTN LHS, UINTN RHS) {
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_add_overflow_abort");
}

void __ubsan_handle_sub_overflow(UINTN *Data, UINTN LHS, UINTN RHS) {
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_sub_overflow");
}

void __ubsan_handle_sub_overflow_abort(UINTN *Data, UINTN LHS, UINTN RHS) {
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_sub_overflow_abort");
}

void __ubsan_handle_mul_overflow(UINTN *Data, UINTN LHS, UINTN RHS) {
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_mul_overflow");
}

void __ubsan_handle_mul_overflow_abort(UINTN *Data, UINTN LHS, UINTN RHS) {
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_mul_overflow_abort");
}

void __ubsan_handle_pointer_overflow(struct OverflowDescData *Data, UINTN Base, UINTN Result) {
  CHAR8 NumStr[19];
  SerialOutput (Data->Loc.file_name);
  SerialOutput (", line:");
  Num2Str16bit (Data->Loc.line, NumStr);
  SerialOutput (NumStr);
  SerialOutput (", column:");
  Num2Str16bit (Data->Loc.column, NumStr);
  SerialOutput (NumStr);
  SerialOutput ("\n");
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_pointer_overflow");
}

void __ubsan_handle_pointer_overflow_abort(struct OverflowDescData *Data, UINTN Base, UINTN Result) {
  CHAR8 NumStr[19];
  SerialOutput (Data->Loc.file_name);
  SerialOutput (", line:");
  Num2Str16bit (Data->Loc.line, NumStr);
  SerialOutput (NumStr);
  SerialOutput (", column:");
  Num2Str16bit (Data->Loc.column, NumStr);
  SerialOutput (NumStr);
  SerialOutput ("\n");
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_pointer_overflow_abort");
}

void __ubsan_handle_float_cast_overflow(UINTN *Data, UINTN From) {
  SANITIZER_CALLSTACK_DUMP("__ubsan_handle_float_cast_overflow");
}

//define internal void @asan.module_ctor() {
//  call void @__asan_init()
//  call void @__asan_version_mismatch_check_v8()
//  call void @__asan_register_globals(i64 ptrtoint ([1 x { i64, i64, i64, i64, i64, i64, i64, i64 }]* @0 to i64), i64 1)
//  ret void
//}



// UINTN Asan_heap_size_rounded(UINTN size) {
  // if (asan_is_deactivated || !asan_inited){
    // return size;
  // }
  // UINTN rz_size = ComputeRZSize(size);
  // UINTN rounded_size = RoundUpTo(size, SHADOW_GRANULARITY);
  // UINTN needed_size = rounded_size + rz_size;
  // return needed_size;
// }

// Marked weak so OvmfPkg/Library/SyzCoverLib (which provides a real
// implementation that writes PCs into the syzkaller ivshmem region)
// can override us when SYZ_AGENT_ENABLE=TRUE.
__attribute__((weak))
void __sanitizer_cov_trace_pc(void)
{

}


//
// These symbols are provided in the GCC linker script.
//
extern void (*__preinit_array_start []) (int, char **, char **);
extern void (*__preinit_array_end []) (int, char **, char **);
extern void (*__init_array_start []) (int, char **, char **);
extern void (*__init_array_end []) (int, char **, char **);
extern void (*__fini_array_start []) (void);
extern void (*__fini_array_end []) (void);

RETURN_STATUS
EFIAPI
SetupAsanShadowMemory (
  VOID
  )
{
  EFI_HOB_GUID_TYPE     *GuidHob;
  ASAN_INFO             *AsanInfoPtr;

  GuidHob = GetFirstGuidHob (&gAsanInfoGuid);
  if (GuidHob == NULL) {
    asan_is_deactivated = TRUE;
    asan_inited = FALSE;
    mAsanShadowMemoryStart = 0;
    mAsanShadowMemorySize = 0;
    return RETURN_UNSUPPORTED;
  } 

  AsanInfoPtr = GET_GUID_HOB_DATA (GuidHob);
  asan_inited = (AsanInfoPtr->AsanInited == 0)? FALSE: TRUE;;
  asan_is_deactivated = (AsanInfoPtr->AsanActivated == 0)? TRUE: FALSE;
  mAsanShadowMemoryStart = AsanInfoPtr->AsanShadowMemoryStart;
  mAsanShadowMemorySize = AsanInfoPtr->AsanShadowMemorySize;
  mAsanShadowMemoryEnd = mAsanShadowMemoryStart + mAsanShadowMemorySize -1 ;

  mShadowOffset = mAsanShadowMemoryStart;
  __asan_shadow_memory_dynamic_address = mAsanShadowMemoryStart;


  // CHAR8 NumStr[19];
  // SerialOutput ("asan_inited = ");
  // Num2Str64bit ( asan_inited , NumStr); 
  // SerialOutput (NumStr);
  // SerialOutput ("\n");
  // SerialOutput ("asan_is_deactivated = ");
  // Num2Str64bit ( asan_is_deactivated , NumStr);
  // SerialOutput (NumStr);
  // SerialOutput ("\n");
  // SerialOutput ("mAsanShadowMemoryStart = ");
  // Num2Str64bit ( mAsanShadowMemoryStart , NumStr);
  // SerialOutput (NumStr);
  // SerialOutput ("\n");
  // SerialOutput ("mAsanShadowMemorySize = ");
  // Num2Str64bit ( mAsanShadowMemorySize , NumStr);
  // SerialOutput (NumStr);
  // SerialOutput ("\n");

  if (mAsanShadowMemorySize < 0x800000) { //8M shadow memory at least, map to 64M system memory
    asan_inited = FALSE;
    asan_is_deactivated = TRUE;
    SerialOutput ("mAsanShadowMemorySize is too small!\n");
    return RETURN_UNSUPPORTED;
  }

  return RETURN_SUCCESS;
}


RETURN_STATUS
EFIAPI
AsanLibConstructor (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                    Status;
  // CHAR8                         NumStr[19];
  int                           size;
  // SerialOutput ("AsanLibConstructor begin\n");
  // SerialOutput ("Get hob of gAsanInfoGuid\n");

  if (AsanCtorFlag) {
    return RETURN_SUCCESS;//Status;
  } else {
    AsanCtorFlag = TRUE;
  }

  Status = SetupAsanShadowMemory();
  if (EFI_ERROR(Status)){
    return RETURN_SUCCESS;//Status;
  }

  size = __preinit_array_end - __preinit_array_start;
  // SerialOutput ("AsanLibConstructor: preinit function pointers size = ");
  // Num2Str64bit ( size , NumStr);
  // SerialOutput (NumStr);
  // SerialOutput ("\n");

  for (int i = 0; i < size; i++){
    (*__preinit_array_start [i]) (0, 0, 0);
  }

  size = __init_array_end - __init_array_start;
  // SerialOutput ("AsanLibConstructor: init function pointers size = ");
  // Num2Str64bit ( size , NumStr);
  // SerialOutput (NumStr);
  // SerialOutput ("\n");

  for (int i = 0; i < size; i++){
    (*__init_array_start [i]) (0, 0, 0);
  }

  // SerialOutput ("AsanLibConstructor done\n");
  return RETURN_SUCCESS;
}
