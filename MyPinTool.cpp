#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <wchar.h>

#include <set>
#include <map>
#include <unordered_map>
#include <vector>
#include <string>
#include <sstream>

#define UNDANGLE
// #undef UNDANGLE

// 統計プロファイルの有無の制御はここで
#undef CALL_STAT
// #define CALL_STAT

#define OUT_FP stderr
// #define OUT_FP stdout

// アサートチェックの有無の制御はここで
// #undef NDEBUG
#define NDEBUG
#include <cassert>
#include "pin.H"

enum REG_INDEX {
    INDEX_RAX   = 0,  INDEX_RBX   = 1,  INDEX_RCX   = 2,  INDEX_RDX   = 3,
    INDEX_RDI   = 4,  INDEX_RSI   = 5,  INDEX_RBP   = 6,  INDEX_RSP   = 7,
    INDEX_R8    = 8,  INDEX_R9    = 9,  INDEX_R10   = 10, INDEX_R11   = 11,
    INDEX_R12   = 12, INDEX_R13   = 13, INDEX_R14   = 14, INDEX_R15   = 15,
    INDEX_MM0   = 16, INDEX_MM1   = 17, INDEX_MM2   = 18, INDEX_MM3   = 19,
    INDEX_MM4   = 20, INDEX_MM5   = 21, INDEX_MM6   = 22, INDEX_MM7   = 23,
    INDEX_XMM0  = 24, INDEX_XMM1  = 25, INDEX_XMM2  = 26, INDEX_XMM3  = 27,
    INDEX_XMM4  = 28, INDEX_XMM5  = 29, INDEX_XMM6  = 30, INDEX_XMM7  = 31,
    INDEX_XMM8  = 32, INDEX_XMM9  = 33, INDEX_XMM10 = 34, INDEX_XMM11 = 35,
    INDEX_XMM12 = 36, INDEX_XMM13 = 37, INDEX_XMM14 = 38, INDEX_XMM15 = 39,
    INDEX_NONE1 = 40, INDEX_NONE2 = 41, INDEX_NONE4 = 42,
};
#define NUM_INDEX_REG 43
#define NUM_TAG_PER_REG 4
#define TAG_REG_ARRAY(i, j) tag_reg_array[reg_index((REG)i)][j]
const char *INDEX_REG_STR [] = {
    "RAX",   "RBX",   "RCX",   "RDX",
    "RDI",   "RSI",   "RBP",   "RSP",
    "R8",    "R9",    "R10",   "R11",
    "R12",   "R13",   "R14",   "R15",
    "MM0",   "MM1",   "MM2",   "MM3",
    "MM4",   "MM5",   "MM6",   "MM7",
    "XMM0",  "XMM1",  "XMM2",  "XMM3",
    "XMM4",  "XMM5",  "XMM6",  "XMM7",
    "XMM8",  "XMM9",  "XMM10", "XMM11",
    "XMM12", "XMM13", "XMM14", "XMM15",
    "NONE1", "NONE2", "NONE4",
};

const REG INDEX_REG_REG [] = {
    REG_RAX,   REG_RBX,   REG_RCX,   REG_RDX,
    REG_RDI,   REG_RSI,   REG_RBP,   REG_RSP,
    REG_R8,    REG_R9,    REG_R10,   REG_R11,
    REG_R12,   REG_R13,   REG_R14,   REG_R15,
    REG_MM0,   REG_MM1,   REG_MM2,   REG_MM3,
    REG_MM4,   REG_MM5,   REG_MM6,   REG_MM7,
    // ymmレジスタを扱う際にはこの4行を XMM->YMM と変更する必要がある
    REG_XMM0,  REG_XMM1,  REG_XMM2,  REG_XMM3,
    REG_XMM4,  REG_XMM5,  REG_XMM6,  REG_XMM7,
    REG_XMM8,  REG_XMM9,  REG_XMM10, REG_XMM11,
    REG_XMM12, REG_XMM13, REG_XMM14, REG_XMM15,
    REG_NONE,  REG_NONE,  REG_NONE,
};

// TOS-index から，REG に変換する配列
const REG MM_REG [] = {
    REG_MM0, REG_MM1, REG_MM2, REG_MM3, REG_MM4, REG_MM5, REG_MM6, REG_MM7,
};

/* ログ関連 =================================================== */
// なぜか rindex を呼べないので，自前で
const char *
strip_dir (const char * path)
{
    int tail = strlen (path) - 1;
    int i;
    for (i = tail; i >= 0; i--) {
        if (path [i] == '/') {
            break;
        }
    }
    if (i == 0) {
        return path;
    } else {
        return path + i + 1;
    }
}

int
my_fprintf (FILE *stream, const char *format, ...)
{
    va_list va_args; int ret;
    static char buf [4096]; // to be malloc-free
    va_start (va_args, format);
    ret = vsnprintf (buf, 4096, format, va_args);
    fputs (buf, OUT_FP); 
    va_end (va_args);
    return ret;
}

// fprintf 内の malloc が問題になったら以下のコメントを外す
// #define fprintf my_fprintf

// 普通に fprintf を呼び出すと内部で malloc が呼ばれてまずいかもで防御的に．
#define DLOG_REAL(...) do { \
    my_fprintf (OUT_FP, "%4d: ", __LINE__); \
    my_fprintf (OUT_FP, __VA_ARGS__); } while (0)
#define DLOG_NOHEADER_REAL(...) do { \
    my_fprintf (OUT_FP, __VA_ARGS__); } while (0)
// DLOG2 は malloc-free にするのが難しそう．大丈夫かなあ．
#define DLOG2_REAL(addr, ...) do { \
    INT32 col, line; std::string path; \
    PIN_LockClient (); \
    PIN_GetSourceLocation (addr, &col, &line, &path); \
    PIN_UnlockClient (); \
    my_fprintf (OUT_FP, "%4d: %d %s@%lx: ", __LINE__, line, strip_dir (path.c_str ()), addr); \
    my_fprintf (OUT_FP, __VA_ARGS__); } while (0)

#define DLOG_NULL(...)
#define DLOG_NOHEADER_NULL(...)
#define DLOG2_NULL(addr, ...)

// ログ出力の有無はここで制御
// #define OUTPUT_LOG
#undef OUTPUT_LOG

#ifdef OUTPUT_LOG
#define DLOG DLOG_REAL
#define DLOG_NOHEADER DLOG_NOHEADER_REAL
#define DLOG2 DLOG2_REAL
#else
#define DLOG DLOG_NULL
#define DLOG_NOHEADER DLOG_NOHEADER_NULL
#define DLOG2 DLOG2_NULL
#endif

#define ROUND_DOWN_TO_8BYTE(addr) ((addr) & ~7)
#define ROUND_UP_TO_8BYTE(addr)   (((addr) + 7) & ~7)
#define IS_ALIGNED_TO_8BYTE(addr) (!((addr) & 7))
#define ENV_VAR_NAME "PINLEAKPOINT_EXEC_CALLED"

#ifdef UNUSED
#undef UNUSED
#define UNUSED __attribute__((unused))
#endif

const ADDRINT NULLIFY_PATTERN = 0xDEADBEEFCAFEBABE;

enum ALLOC_STATUS {
    DEALLOCATED,
    ALLOCATED,
};

// pin下で std::tuple 使うとビルドがこけるので，struct を使用
struct MALLOC_META {
    UINT32 RC;
    UINT32 size;
    enum ALLOC_STATUS stat;
    std::vector<ADDRINT> alloc_loc;
    std::vector<ADDRINT> free_loc;
    std::vector<ADDRINT> last_use_loc;
    std::set<ADDRINT> mem_set; // memory addresses that refer to this heap object
//    std::set<REG> reg_set; // registers that refer to this heap object
    std::set<std::pair<REG, UINT32>> reg_set;
    std::unordered_map<ADDRINT, std::vector<ADDRINT>> mem_loc;
    // ↓ unordered_map にすると，このままではペアをキーにできない
    std::map<std::pair<REG, UINT32>, std::vector<ADDRINT>> reg_loc;
    bool mark; // for mark_sweep
    bool visited; // for detect_unreachable_cycles
    int post_order; // for detect_unreachable_cycles
};

// 「アドレス → <参照数，サイズ，malloc状態など>」の辞書
std::unordered_map<ADDRINT, struct MALLOC_META> malloc_map;
// このオブジェクトのアドレスを保持してるメモリ（スタック上のアドレスも含む）
std::unordered_map<ADDRINT, std::set<ADDRINT>> tag_mem_map;
// このオブジェクトのアドレスを保持してるレジスタ
std::set<ADDRINT> tag_reg_array [NUM_INDEX_REG][NUM_TAG_PER_REG];
// このオブジェクトのアドレスを保持してるスタック
std::map<ADDRINT, std::set<ADDRINT>> tag_stack_map;

std::unordered_map<const char *, unsigned long> call_stat;

#ifdef UNDANGLE
// map of pointer -> {pointee, mem_loc}
std::unordered_map<ADDRINT, std::pair<ADDRINT, std::vector<ADDRINT>>> nullified_map_traceend;
std::unordered_map<ADDRINT, std::pair<ADDRINT, std::vector<ADDRINT>>> nullified_map_funcend;
#endif

ADDRINT saved_addr;
ADDRINT saved_arg1;
ADDRINT saved_arg2;
ADDRINT saved_arg3;
ADDRINT saved_arg4;
ADDRINT saved_arg5;
ADDRINT saved_arg6;

std::set<ADDRINT> saved_tag;
std::vector<ADDRINT> saved_backtrace;

ADDRINT saved_ret_ip;
ADDRINT saved_pre_rsp;
ADDRINT saved_stack_bottom, stack_limit;
ADDRINT data_start, data_end;
const char *aout_name;

const ADDRINT DF_MASK = 0x400;

int rewind_depth;
ADDRINT watched_addr;

std::vector<std::string> extra_images;

KNOB<bool> NullifyDanglingPointers (KNOB_MODE_WRITEONCE, "pintool", "n", "1", "Nullify dangling pointers");
KNOB<bool> UseGCCWrapper (KNOB_MODE_WRITEONCE, "pintool", "w", "1", "Use GCC wrapper");
KNOB<bool> BreakOnLeakDetected (KNOB_MODE_WRITEONCE, "pintool", "d", "0", "Break on leak detected");
KNOB<bool> MarkSweepOnMainExited (KNOB_MODE_WRITEONCE, "pintool", "m", "1", "Mark-sweep when main is exited");
KNOB<int> RewindDepth (KNOB_MODE_WRITEONCE, "pintool", "r", "20", "Rewind depth for malloc/free functions");
KNOB<bool> FreeLeakedMemory (KNOB_MODE_WRITEONCE, "pintool", "f", "0", "Free leaked memory");
KNOB<bool> StopOnLeakDetected (KNOB_MODE_WRITEONCE, "pintool", "s", "0", "Stop on leak detected");
KNOB<ADDRINT> TraceSpecificHeapObject (KNOB_MODE_WRITEONCE, "pintool", "t", "0", "Trace specific heap object");
KNOB<std::string> InstrumentExtraImages (KNOB_MODE_WRITEONCE, "pintool", "i", "", "Instrument Extra Images");

/* プロトタイプ宣言 =================================================== */
int get_fpsw_tos (const CONTEXT *ctxt);
inline int reg_index (REG reg);
const char * get_func_name (ADDRINT addr);
char *addr2loc (ADDRINT addr, int index);
std::vector<ADDRINT> get_caller_addrs (const CONTEXT *ctxt, int n);
void get_stack_limit (void);
void get_data_limit (void);
#ifdef UNDANGLE
void dump_nullified_map (void);
#endif
void dump_backtrace (const CONTEXT *ctxt);
void dump_malloc_map_entry (std::pair<ADDRINT, struct MALLOC_META> i);
void dump_malloc_map (void);
void dump_tag_mem_map (void);
void dump_tag_reg_array (void);
void dump_tag_stack_map (void);
void dump_all_map (void);
void dump_ins (INS ins);
void dump_call_stat (void);

void search_malloc_map (ADDRINT addr);

int  is_nullified (ADDRINT addr);
void nullify_pointer (ADDRINT pointer, ADDRINT pointee, const CONTEXT *ctxt, std::vector<ADDRINT>);
void register_malloc_map (ADDRINT addr, UINT32 size, ADDRINT alloc_loc, const CONTEXT *ctxt);
void unregister_malloc_map (ADDRINT addr, ADDRINT free_loc, const CONTEXT *ctxt);

bool is_onstack (ADDRINT addr);
bool is_ondata (ADDRINT addr);
bool reg_is_general_purpose (REG reg);

void clear_reg_malloc_map (REG reg, int nth, ADDRINT tag);
void clear_mem_malloc_map (ADDRINT addr, ADDRINT tag);
void set_reg_malloc_map (REG reg, int nth, ADDRINT tag, const CONTEXT *ctxt);
void set_mem_malloc_map (ADDRINT addr, ADDRINT tag, const CONTEXT *ctxt);

void check_map_consistency (void);
void check_RC (ADDRINT ip, ADDRINT addr, const CONTEXT *ctxt);
void update_last_use_loc (ADDRINT ip, ADDRINT addr, const CONTEXT *ctxt);
void tag_clear_unaligned_mem (ADDRINT ip, ADDRINT addr, bool do_check);
void tag_clear_mem (ADDRINT ip, ADDRINT addr, const CONTEXT *ctxt, bool do_check);
void tag_clear_mem_region (ADDRINT ip, ADDRINT dst_mem, UINT32 size, const CONTEXT *ctxt);
void tag_clear_reg (ADDRINT ip, REG reg, int nth, const CONTEXT *ctxt, bool do_check);
void tag_clear_mmreg (ADDRINT ip, int nth, const CONTEXT *ctxt, bool do_check);
void tag_clear_reg_width (ADDRINT ip, REG reg, const CONTEXT *ctxt, bool do_check);
void tag_clear_reg_full (ADDRINT ip, REG reg, const CONTEXT *ctxt, bool do_check);
void tag_clear_caller_save_regs (ADDRINT ip, const CONTEXT *ctxt);
void tag_copy_reg2reg_nth (ADDRINT ip, REG src_reg, int src_nth, REG dst_reg, int dst_nth, bool do_strong_update, const CONTEXT *ctxt);
#if 0
void tag_copy_reg2reg (ADDRINT ip, REG src_reg, REG dst_reg, bool do_strong_update, const CONTEXT *ctxt);
#endif
void tag_copy_mem2reg_nth (ADDRINT ip, ADDRINT src_mem, REG dst_reg, int dst_nth, bool do_strong_update, const CONTEXT *ctxt);
#if 0
void tag_copy_mem2reg (ADDRINT ip, ADDRINT src_mem, REG dst_reg, bool do_strong_update, const CONTEXT *ctxt);
#endif
void tag_copy_reg2mem_nth (ADDRINT ip, REG src_reg, int src_nth, ADDRINT dst_mem, bool do_strong_update, const CONTEXT *ctxt);
#if 0
void tag_copy_reg2mem (ADDRINT ip, REG src_reg, ADDRINT dst_mem, bool do_strong_update, const CONTEXT *ctxt);
#endif
void tag_copy_mem2mem (ADDRINT ip, ADDRINT src_mem, ADDRINT dst_mem, bool do_strong_update, const CONTEXT *ctxt);
void tag_copy_mem2mem_region (ADDRINT ip, ADDRINT src_mem, ADDRINT dst_mem, UINT32 size, const CONTEXT *ctxt);

#if 0
void tag_swap_mmreg (ADDRINT ip, int nth, const CONTEXT *ctxt);
#endif

void tag_cmpxchg_reg2reg_clear (ADDRINT ip, ADDRINT rax_value, REG dst_reg, ADDRINT dst_value, const CONTEXT *ctxt);
void tag_cmpxchg_reg2mem_clear (ADDRINT ip, ADDRINT rax_value, ADDRINT dst_mem, const CONTEXT *ctxt);
void tag_cmpxchg_reg2reg_copy (ADDRINT ip, ADDRINT rax_value, REG src_reg, REG dst_reg, ADDRINT dst_value, const CONTEXT *ctxt);
void tag_cmpxchg_reg2mem_copy (ADDRINT ip, ADDRINT rax_value, REG src_reg, ADDRINT dst_mem, const CONTEXT *ctxt);
void tag_cmpxchg8b (ADDRINT ip, ADDRINT eax_value, ADDRINT edx_value, ADDRINT dst_mem, const CONTEXT *ctxt);
void tag_cmpxchg16b (ADDRINT ip, ADDRINT rax_value, ADDRINT rbx_value, ADDRINT rcx_value, ADDRINT rdx_value, ADDRINT dst_mem, const CONTEXT *ctxt);
ADDRINT return_arg (BOOL arg);
void tag_copy_rep_movs (ADDRINT ip, UINT32 size, ADDRINT rflags_value, ADDRINT rcx_value, ADDRINT src_mem, ADDRINT dst_mem, const CONTEXT *ctxt);
void tag_copy_rep_lods (ADDRINT ip, UINT32 size, ADDRINT rflags_value, ADDRINT rcx_value, ADDRINT src_mem, const CONTEXT *ctxt);
void tag_copy_rep_stos (ADDRINT ip, UINT32 size, ADDRINT rflags_value, ADDRINT rcx_value, ADDRINT dst_mem, const CONTEXT *ctxt);

void ins_clear_reg (INS ins, REG dst_reg, int nth);
void ins_clear_mmreg (INS ins, int nth);
void ins_clear_reg_width (INS ins, REG dst_reg);
void ins_clear_reg_full (INS ins, REG dst_reg);
void ins_clear_mem (INS ins, UINT32 dst_memopIdx);
void ins_clear_mem_region (INS ins, UINT32 dst_memopIdx);
void ins_copy_reg2reg_nth (INS ins, REG src_reg, int src_nth, REG dst_reg, int dst_nth, bool do_strong_update);
void ins_copy_reg2reg (INS ins, REG src_reg, REG dst_reg, bool do_strong_update);
void ins_copy_mem2reg_nth (INS ins, UINT32 src_memopIdx, REG dst_reg, int dst_nth, bool do_strong_update);
void ins_copy_mem2reg (INS ins, UINT32 src_memopIdx, REG dst_reg, bool do_strong_update);
void ins_copy_reg2mem_nth (INS ins, REG src_reg, int src_nth, UINT32 dst_memopIdx, bool do_strong_update);
void ins_copy_reg2mem (INS ins, REG src_reg, UINT32 dst_memopIdx, bool do_strong_update);
void ins_copy_mem2mem (INS ins, UINT32 src_memopIdx, UINT32 dst_memopIdx, bool do_strong_update);

#if 0
void ins_swap_mmreg (INS ins);
#endif

void ins_cmpxchg_reg2reg_clear (INS ins, REG dst_reg);
void ins_cmpxchg_reg2mem_clear (INS ins, UINT32 dst_memopIdx);
void ins_cmpxchg_reg2reg_copy (INS ins, REG src_reg, REG dst_reg);
void ins_cmpxchg_reg2mem_copy (INS ins, REG src_reg, UINT32 dst_memopIdx);
void ins_cmpxchg8b (INS ins);
void ins_cmpxchg16b (INS ins);

bool ins_clear_if_possible (INS ins, UINT32 src_idx, UINT32 dst_idx, std::map<int, int> &memop_idx);
void ins_copy (INS ins, UINT32 src_idx, UINT32 dst_idx, std::map<int, int> &memop_idx, bool do_strong_update);
void ins_xchg (INS ins, UINT32 src_idx, UINT32 dst_idx, std::map<int, int> &memop_idx);

VOID Undangle_TraceEnd (ADDRINT ip, CONTEXT *ctxt);
VOID Undangle_FuncEnd (ADDRINT ip, CONTEXT *ctxt);

#if 0
void SysenterBefore (THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v);
#endif
BOOL FollowChild (CHILD_PROCESS cProcess, VOID* v);
bool IsMainCalled (int is_set);
bool IsMainExited (int is_set);
VOID MainBefore (CONTEXT* ctxt);
VOID MainAfter (CONTEXT* ctxt);
VOID RSPBefore (ADDRINT ip, ADDRINT rsp);
VOID RSPAfter (ADDRINT ip, ADDRINT rsp);
VOID BeforeFuncCall (ADDRINT ip, CONTEXT *ctxt, ADDRINT target_addr, ADDRINT pre_addr, ADDRINT next_addr);
VOID AfterFuncReturn (ADDRINT ip, CONTEXT *ctxt);
VOID MemoryAccessBefore (const CONTEXT *ctxt, ADDRINT ip, UINT32 nth, ADDRINT addr, UINT32 size, char *func_name, char *disasm, bool is_write);
VOID MemoryAccessAfter (const CONTEXT *ctxt, ADDRINT ip, UINT32 nth, UINT32 size, char *func_name, char *disasm);
VOID RegisterAccessBefore (const CONTEXT *ctxt, ADDRINT ip, UINT32 nth, ADDRINT reg_ref, UINT32 size, char *func_name, char *disasm, bool is_write);
VOID RegisterAccessAfter (const CONTEXT *ctxt, ADDRINT ip, UINT32 nth, ADDRINT reg_ref, UINT32 size, char *func_name, char *disasm);
VOID Instruction1 (INS ins, VOID *v);
VOID Instruction2 (INS ins, VOID *v);
VOID Instruction3 (INS ins, VOID *v);
VOID Instruction4 (INS ins, VOID *v);
VOID Instruction5 (INS ins, VOID *v);
VOID Image (IMG img, VOID *v);
VOID Trace (TRACE trace, VOID *v);
VOID UnloadImage (IMG img, VOID *v);
VOID Init (VOID *v);
VOID Fini (INT32 code, VOID *v);
VOID InitThread (THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v);

VOID malloc_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID malloc_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID free_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID free_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID calloc_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID calloc_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID posix_memalign_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID posix_memalign_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID realloc_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID realloc_post_hook (ADDRINT ip, CONTEXT *ctxt);
#if 0
VOID reallocarray_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID reallocarray_post_hook (ADDRINT ip, CONTEXT *ctxt);
#endif
VOID strdup_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID strdup_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID strndup_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID strndup_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID wcsdup_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID wcsdup_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID asprintf_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID asprintf_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID memcpy_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID memcpy_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID mempcpy_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID mempcpy_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID memmove_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID memmove_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID memset_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID memset_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID strcpy_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID strcpy_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID strncpy_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID strncpy_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _Znwm_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _Znwm_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _Znam_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _Znam_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZdlPv_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZdlPv_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZdaPv_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZdaPv_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZdaPvm_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZdaPvm_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZdlPvm_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZdlPvm_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZnamRKSt9nothrow_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZnamRKSt9nothrow_t_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZnwmRKSt9nothrow_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZnwmRKSt9nothrow_t_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZnwmSt11align_val_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZnwmSt11align_val_t_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZnwmSt11align_val_tRKSt9nothrow_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZnwmSt11align_val_tRKSt9nothrow_t_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZnamSt11align_val_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZnamSt11align_val_t_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZnamSt11align_val_tRKSt9nothrow_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZnamSt11align_val_tRKSt9nothrow_t_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZdlPvmSt11align_val_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZdlPvmSt11align_val_t_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZdlPvRKSt9nothrow_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZdlPvRKSt9nothrow_t_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZdlPvSt11align_val_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZdlPvSt11align_val_t_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZdlPvSt11align_val_tRKSt9nothrow_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZdlPvSt11align_val_tRKSt9nothrow_t_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZdaPvmSt11align_val_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZdaPvmSt11align_val_t_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZdaPvRKSt9nothrow_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZdaPvRKSt9nothrow_t_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZdaPvSt11align_val_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZdaPvSt11align_val_t_post_hook (ADDRINT ip, CONTEXT *ctxt);
VOID _ZdaPvSt11align_val_tRKSt9nothrow_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip);
VOID _ZdaPvSt11align_val_tRKSt9nothrow_t_post_hook (ADDRINT ip, CONTEXT *ctxt);

void mark_sweep (void);
void detect_unreachable_cycles ();

/* その他関数 =================================================== */
std::vector<std::string>
string_split (const std::string &str, char sep)
{
    std::vector<std::string> v;
    std::stringstream ss(str);
    std::string buff;
    while( std::getline(ss, buff, sep) ) {
        v.push_back(buff);
    }
    return v;
}

/* ダンプ関数 =================================================== */
char *
addr2loc (ADDRINT addr, int index)
{
    static char buf [3][1024];
    INT32 col, line; std::string path;
    PIN_LockClient ();
    PIN_GetSourceLocation (addr, &col, &line, &path);
    PIN_UnlockClient ();
    // ここで，asprintf は使わない．malloc呼んで無限再帰する可能性を避けるため．
    snprintf (buf [index], 1024, "%s::%d (0x%lx)", strip_dir (path.c_str ()), line, addr);
    return buf [index];
}

std::vector<ADDRINT>
get_caller_addrs (const CONTEXT *ctxt, int n)
{
    DLOG ("get_caller_addrs: %d\n", n);
#if 0
    // なぜかうまくいかないので，-fno-frame-pointer を仮定して %rbp を調べる
    // 注：この ctxt は returnする直前なので %rbp 1回分 rewind 済み
    std::vector<ADDRINT> ret_addrs;
    ADDRINT old_rbp, ret_addr;
    ADDRINT rsp = PIN_GetContextReg (ctxt, REG_RSP);
    ADDRINT rbp = PIN_GetContextReg (ctxt, REG_RBP);
    PIN_SafeCopy ((VOID *)&ret_addr, (VOID *)rsp, sizeof (ADDRINT));
    ret_addrs.push_back (ret_addr);
    fprintf (OUT_FP, "ret_addr [0] = %lx@%s\n", ret_addr, addr2loc (ret_addr, 0));
    for (int i = 0; i < n; i++) {
        fprintf (OUT_FP, "rbp=%lx\n", rbp);
        PIN_SafeCopy ((VOID *)&old_rbp, (VOID *)rbp, sizeof (ADDRINT));
        rbp = old_rbp;
        if (rbp == 0) break;
        PIN_SafeCopy ((VOID *)&ret_addr, (VOID *)(rbp+8), sizeof (ADDRINT));
        ret_addrs.push_back (ret_addr);
        fprintf (OUT_FP, "ret_addr [%d] = %lx@%s\n", i + 1, ret_addr, addr2loc (ret_addr, 0));
    }
    return ret_addrs;
#else
    std::vector<ADDRINT> ret_addrs;
    int ret;
    void * buf [n];

    PIN_LockClient ();
    ret = PIN_Backtrace (ctxt, buf, n);
    PIN_UnlockClient ();
    if (ret < n) { n = ret; }
    // fprintf (OUT_FP, "=======\n");
    for (int i = 0; i < n; i++) {
        // fprintf (OUT_FP, "%p\n", buf [i]);
        ret_addrs.push_back ((ADDRINT) buf [i]);
    }
    return ret_addrs;
#endif
    DLOG ("get_caller_addrs: done\n");
}

void
get_stack_limit (void)
{
    // マルチスレッドには非対応
    // 文字列stackを含む行の1つ前の行の2番目のアドレスを stack_limit にする
    // cat /proc/self/maps | sed -n $((`cat -n /proc/self/maps | egrep stack | colrm 7`-1))p | sed -r 's/^[^-]+-([^ ]+) .*$/\1/'
    char buf [1024];
    snprintf (buf, sizeof (buf), "cat /proc/%d/maps | sed -n $((`cat -n /proc/self/maps | egrep stack | colrm 7`-1))p | sed -r 's/^[^-]+-([^ ]+) .*$/\\1/'",
              getpid ());
    FILE *fp = popen (buf, "r");
    if (fp == NULL) {
        perror ("popen"); exit (1);
    }
    UNUSED char *ret = fgets (buf, sizeof (buf), fp);
    assert (ret != NULL);
    stack_limit = strtol (buf, NULL, 16);
    DLOG ("get_stack_limit: stack_limit=%lx\n", stack_limit);
    pclose (fp);
}

void
get_data_limit (void)
{

    // 55555557d000-555555581000 rw-p 00028000 08:05 789904 ./a.out
    // cat /proc/self/maps | egrep cat | egrep 'rw-p' | sed -r 's/^([^ ]+) .*$/\1/'
    char buf [1024];
    snprintf (buf, sizeof (buf), "cat /proc/%d/maps | egrep %s | egrep 'rw-p' | sed -r 's/^([^ ]+) .*$/\\1/'", getpid (), aout_name);
    // fprintf (OUT_FP, "buf=|%s|\n", buf);
    FILE *fp = popen (buf, "r");
    if (fp == NULL) {
        perror ("popen"); exit (1);
    }
    UNUSED char *ret2 = fgets (buf, sizeof (buf), fp);
    // fprintf (OUT_FP, "buf=|%s|\n", buf);
    assert (ret2 != NULL);
    UNUSED int ret = sscanf (buf, "%lx-%lx", &data_start, &data_end);
    assert (ret == 2);
    DLOG ("data_start=%lx, data_end=%lx\n", data_start, data_end);
    pclose (fp);
}

#ifdef UNDANGLE
void
dump_nullified_map (void)
{
    fprintf (OUT_FP, "======== nulified_map_traceend\n");
    for (auto i: nullified_map_traceend) {
        fprintf (OUT_FP, "%lx (-> %lx)\n", i.first, i.second.first);
        fprintf (OUT_FP, "mem_loc: ");
        for (auto j: i.second.second) {
            char *mem_loc = addr2loc (j, 0);
            fprintf (OUT_FP, "%lx@%s, ", j, mem_loc);
        }
        fprintf (OUT_FP, "\n");
    }

    fprintf (OUT_FP, "======== nulified_map_funcend\n");
    for (auto i: nullified_map_funcend) {
        fprintf (OUT_FP, "%lx (-> %lx)\n", i.first, i.second.first);
        fprintf (OUT_FP, "mem_loc: ");
        for (auto j: i.second.second) {
            char *mem_loc = addr2loc (j, 0);
            fprintf (OUT_FP, "%lx@%s, ", j, mem_loc);
        }
        fprintf (OUT_FP, "\n");
    }
    fprintf (OUT_FP, "========\n");
}
#endif

// なぜかバックトレースが不正確になることがあるので，
// register_malloc_map では，saved_ret_ip を使っている．
void
dump_backtrace (const CONTEXT *ctxt)
{
    int size = 10, n;
    void * buf [size];
    std::string func_name;
    char *loc;

    // main の終了後は PIN_Backtrace でクラッシュする．それを避けるため．
    if (!IsMainCalled (false)) return;
    if (IsMainExited (false)) return;

    ADDRINT rsp = PIN_GetContextReg (ctxt, REG_RSP);

    fprintf (OUT_FP, "===== backtrace =====\n");
    PIN_LockClient ();
    n = PIN_Backtrace (ctxt, buf, size);
    PIN_UnlockClient ();
    fprintf (OUT_FP, "\tn=%d\n", n);
    fprintf (OUT_FP, "rsp=%lx\n", rsp);
    for (int i = 0; i < n; i++) {
        ADDRINT addr = (ADDRINT) buf [i];
        func_name = RTN_FindNameByAddress (addr);
        loc = addr2loc (addr, 0);
        fprintf (OUT_FP, "%s: [%d] ip=%lx@%s\n",
                 loc, i, addr, func_name.c_str ());
    }
    fprintf (OUT_FP, "==================\n");
}

void
dump_malloc_map_entry (std::pair<ADDRINT, struct MALLOC_META> i)
{
    auto meta = i.second;

    fprintf (OUT_FP, "0x%lx, %d, %d, %s, alloc: ",
             i.first, meta.RC, meta.size,
             meta.stat == ALLOCATED ? "ALLOC" : "DEALLOC");
    
    for (auto i: meta.alloc_loc) {
        char *alloc_loc = addr2loc (i, 0);
        fprintf (OUT_FP, "%lx@%s, ", i, alloc_loc);
    }
    
    fprintf (OUT_FP, "free: ");
    for (auto i: meta.free_loc) {
        char *free_loc = addr2loc (i, 0);
        fprintf (OUT_FP, "%lx@%s, ", i, free_loc);
    }
    
    fprintf (OUT_FP, "last_use: ");
    for (auto i: meta.last_use_loc) {
        char *last_use_loc = addr2loc (i, 0);
        fprintf (OUT_FP, "%lx@%s, ", i, last_use_loc);
    }
    
    fprintf (OUT_FP, "mark=%d\n", meta.mark);
    
    fprintf (OUT_FP, "\tmem_set: ");
    for (auto j: i.second.mem_set) {
        fprintf (OUT_FP, "%lx, ", j);
    }
    fprintf (OUT_FP, "\n");

    fprintf (OUT_FP, "\tmem_loc:\n");
    for (auto j: i.second.mem_set) {
        fprintf (OUT_FP, "\t\t%lx: ", j);
        for (auto k: i.second.mem_loc [j]) {
            char *mem_loc = addr2loc (k, 0);
            fprintf (OUT_FP, "%lx@%s, ", k, mem_loc);
        }
        fprintf (OUT_FP, "\n");
    }
    
    fprintf (OUT_FP, "\treg_set: ");
    for (auto &j: i.second.reg_set) {
        fprintf (OUT_FP, "%s [%d], ",
                 REG_StringShort (j.first).c_str (), j.second);
    }
    fprintf (OUT_FP, "\n");

    fprintf (OUT_FP, "\treg_loc:\n");
    for (auto j: i.second.reg_set) {
        fprintf (OUT_FP, "\t\t%s[%d]: ", REG_StringShort (j.first).c_str (), j.second);
        for (auto k: i.second.reg_loc [j]) {
            char *reg_loc = addr2loc (k, 0);
            fprintf (OUT_FP, "%lx@%s, ", k, reg_loc);
        }
        fprintf (OUT_FP, "\n");
    }
}

void
dump_malloc_map (void)
{
    fprintf (OUT_FP, "=== malloc_map ===\n");
    for (auto i: malloc_map) {
        dump_malloc_map_entry (i);
    }
    fprintf (OUT_FP, "==================\n");
}

void
dump_tag_mem_map (void)
{
    fprintf (OUT_FP, "=== tag_mem_map ===\n");
    for (auto i: tag_mem_map) {
        fprintf (OUT_FP, "%lx -> ", i.first);
        for (auto j: i.second) {
            fprintf (OUT_FP, "%lx,", j);
        }
        fprintf (OUT_FP, "\n");
    }
    fprintf (OUT_FP, "==================\n");
}

void
dump_tag_reg_array (void)
{
    fprintf (OUT_FP, "=== tag_reg_array ===\n");
    for (int i = 0; i < NUM_INDEX_REG; i++) {
        for (int j = 0; j < NUM_TAG_PER_REG; j++) {
            if (!tag_reg_array [i][j].empty ()) {
                fprintf (OUT_FP, "%s [%d]: ", INDEX_REG_STR [i], j);
                for (auto &tag: tag_reg_array [i][j]) {
                    fprintf (OUT_FP, "%lx,", tag);
                }
                fprintf (OUT_FP, "\n");
            }
        }
    }
    fprintf (OUT_FP, "==================\n");
}

void
dump_tag_stack_map (void)
{
    fprintf (OUT_FP, "=== tag_stack_map ===\n");
    for (auto i: tag_stack_map) {
        fprintf (OUT_FP, "%lx -> ", i.first);
        for (auto j: i.second) {
            fprintf (OUT_FP, "%lx,", j);
        }
        fprintf (OUT_FP, "\n");
        assert (is_onstack (i.first));
    }
    fprintf (OUT_FP, "==================\n");
}

void
dump_all_map (void)
{
#if 1 // xxx
    dump_malloc_map ();
    dump_tag_reg_array ();
    dump_tag_mem_map ();
    dump_tag_stack_map ();
#endif
}

void
dump_ins (INS ins)
{
    fprintf (OUT_FP, "%lx: %s, %s\n\t",
             INS_Address (ins),
             INS_Mnemonic (ins).c_str (), INS_Disassemble (ins).c_str ());
    UINT32 op_count = INS_OperandCount (ins);
    for (UINT32 i = 0; i < op_count; i++) {
        if (INS_OperandIsReg (ins, i)) {
            REG reg = INS_OperandReg (ins, i);
            fprintf  (OUT_FP, "%d(w%d, gr%d): %s, ", i,
                      INS_OperandWritten (ins, i),
                      reg_is_general_purpose (INS_OperandReg (ins, i)),
                      REG_StringShort (reg).c_str ());
        } else if (INS_OperandIsMemory (ins, i)) {
            fprintf (OUT_FP, "%d(w%d): mem, ", i, INS_OperandWritten (ins, i));
        }
    }
    fprintf (OUT_FP, "\n");
}

void
dump_call_stat (void)
{
    fprintf (OUT_FP, "=== call_stat ===\n");

    for (auto i: call_stat) {
        fprintf (OUT_FP, "%s: %ld times\n", i.first, i.second);
    }
}

void
search_malloc_map (ADDRINT addr)
{
    for (auto i: malloc_map) {
        if (i.first <= addr && addr < i.first + i.second.size) {
            dump_malloc_map_entry (i);
            break;
        }
    }
}

/* 解析関数の補助関数 =================================================== */
int
get_fpsw_tos (const CONTEXT *ctxt)
{
    DLOG ("get_fpsw_tos\n");
    FPSTATE fpstate;
    PIN_GetContextFPState (ctxt, &fpstate);
    UINT32 fsw_fcw;
    PIN_SafeCopy (&fsw_fcw, &fpstate, 4);
    UINT32 top_of_stack = ((fsw_fcw & 0x038000000) >> 27);
    DLOG ("\tTOS=%x, %d\n", fsw_fcw, top_of_stack);
    return top_of_stack;
}

inline int
reg_index (REG reg)
{
    assert (reg != REG_INVALID ());
    switch (reg) {
    case REG_RAX: case REG_EAX: case REG_AX: case REG_AH: case REG_AL:
        return INDEX_RAX;
    case REG_RBX: case REG_EBX: case REG_BX: case REG_BH: case REG_BL:
        return INDEX_RBX;
    case REG_RCX: case REG_ECX: case REG_CX: case REG_CH: case REG_CL:
        return INDEX_RCX;
    case REG_RDX: case REG_EDX: case REG_DX: case REG_DH: case REG_DL:
        return INDEX_RDX;
    case REG_RDI: case REG_EDI: case REG_DI: case REG_DIL:
        return INDEX_RDI;
    case REG_RSI: case REG_ESI: case REG_SI: case REG_SIL:
        return INDEX_RSI;
    case REG_RBP: case REG_EBP: case REG_BP: case REG_BPL:
        return INDEX_RBP;
    case REG_RSP: case REG_ESP: case REG_SP: case REG_SPL:
        return INDEX_RSP;
    case REG_R8: case REG_R8D: case REG_R8W: case REG_R8B:
        return INDEX_R8;
    case REG_R9: case REG_R9D: case REG_R9W: case REG_R9B:
        return INDEX_R9;
    case REG_R10: case REG_R10D: case REG_R10W: case REG_R10B:
        return INDEX_R10;
    case REG_R11: case REG_R11D: case REG_R11W: case REG_R11B:
        return INDEX_R11;
    case REG_R12: case REG_R12D: case REG_R12W: case REG_R12B:
        return INDEX_R12;
    case REG_R13: case REG_R13D: case REG_R13W: case REG_R13B:
        return INDEX_R13;
    case REG_R14: case REG_R14D: case REG_R14W: case REG_R14B:
        return INDEX_R14;
    case REG_R15: case REG_R15D: case REG_R15W: case REG_R15B:
        return INDEX_R15;
    case REG_MM0: case REG_ST0:
        return INDEX_MM0;
    case REG_MM1: case REG_ST1:
        return INDEX_MM1;
    case REG_MM2: case REG_ST2:
        return INDEX_MM2;
    case REG_MM3: case REG_ST3:
        return INDEX_MM3;
    case REG_MM4: case REG_ST4:
        return INDEX_MM4;
    case REG_MM5: case REG_ST5:
        return INDEX_MM5;
    case REG_MM6: case REG_ST6:
        return INDEX_MM6;
    case REG_MM7: case REG_ST7:
        return INDEX_MM7;
    case REG_XMM0: case REG_YMM0:
        return INDEX_XMM0;
    case REG_XMM1: case REG_YMM1:
        return INDEX_XMM1;
    case REG_XMM2: case REG_YMM2:
        return INDEX_XMM2;
    case REG_XMM3: case REG_YMM3:
        return INDEX_XMM3;
    case REG_XMM4: case REG_YMM4:
        return INDEX_XMM4;
    case REG_XMM5: case REG_YMM5:
        return INDEX_XMM5;
    case REG_XMM6: case REG_YMM6:
        return INDEX_XMM6;
    case REG_XMM7: case REG_YMM7:
        return INDEX_XMM7;
    case REG_XMM8: case REG_YMM8:
        return INDEX_XMM8;
    case REG_XMM9: case REG_YMM9:
        return INDEX_XMM9;
    case REG_XMM10: case REG_YMM10:
        return INDEX_XMM10;
    case REG_XMM11: case REG_YMM11:
        return INDEX_XMM11;
    case REG_XMM12: case REG_YMM12:
        return INDEX_XMM12;
    case REG_XMM13: case REG_YMM13:
        return INDEX_XMM13;
    case REG_XMM14: case REG_YMM14:
        return INDEX_XMM14;
    case REG_XMM15: case REG_YMM15:
        return INDEX_XMM15;
    case REG_NONE:
        return INDEX_NONE1;
    default:
        assert (0);
        return NUM_INDEX_REG;
    }
}

inline int
reg_width (REG reg)
{
    assert (reg != REG_INVALID ());
    switch (reg) {
    case REG_RAX: case REG_EAX: case REG_AX: case REG_AH: case REG_AL:
    case REG_RBX: case REG_EBX: case REG_BX: case REG_BH: case REG_BL:
    case REG_RCX: case REG_ECX: case REG_CX: case REG_CH: case REG_CL:
    case REG_RDX: case REG_EDX: case REG_DX: case REG_DH: case REG_DL:
    case REG_RDI: case REG_EDI: case REG_DI: case REG_DIL:
    case REG_RSI: case REG_ESI: case REG_SI: case REG_SIL:
    case REG_RBP: case REG_EBP: case REG_BP: case REG_BPL:
    case REG_RSP: case REG_ESP: case REG_SP: case REG_SPL:
    case REG_R8: case REG_R8D: case REG_R8W: case REG_R8B:
    case REG_R9: case REG_R9D: case REG_R9W: case REG_R9B:
    case REG_R10: case REG_R10D: case REG_R10W: case REG_R10B:
    case REG_R11: case REG_R11D: case REG_R11W: case REG_R11B:
    case REG_R12: case REG_R12D: case REG_R12W: case REG_R12B:
    case REG_R13: case REG_R13D: case REG_R13W: case REG_R13B:
    case REG_R14: case REG_R14D: case REG_R14W: case REG_R14B:
    case REG_R15: case REG_R15D: case REG_R15W: case REG_R15B:
    case REG_MM0: case REG_ST0:
    case REG_MM1: case REG_ST1:
    case REG_MM2: case REG_ST2:
    case REG_MM3: case REG_ST3:
    case REG_MM4: case REG_ST4:
    case REG_MM5: case REG_ST5:
    case REG_MM6: case REG_ST6:
    case REG_MM7: case REG_ST7:
        return 1;
    case REG_XMM0: case REG_XMM1: case REG_XMM2: case REG_XMM3:
    case REG_XMM4: case REG_XMM5: case REG_XMM6: case REG_XMM7:
    case REG_XMM8: case REG_XMM9: case REG_XMM10: case REG_XMM11:
    case REG_XMM12: case REG_XMM13: case REG_XMM14: case REG_XMM15:
        return 2;
    case REG_YMM0: case REG_YMM1: case REG_YMM2: case REG_YMM3:
    case REG_YMM4: case REG_YMM5: case REG_YMM6: case REG_YMM7:
    case REG_YMM8: case REG_YMM9: case REG_YMM10: case REG_YMM11:
    case REG_YMM12: case REG_YMM13: case REG_YMM14: case REG_YMM15:
        return 4;
    case REG_NONE:
        return 1;
    default:
        assert (0);
        return 1;
    }
}

int
is_nullified (ADDRINT addr)
{
#ifdef UNDANGLE
    return (addr >> 62) & 0x3;
#else
    return addr == NULLIFY_PATTERN;
#endif
}

void
nullify_pointer (ADDRINT pointer, ADDRINT pointee, const CONTEXT *ctxt, std::vector<ADDRINT> mem_loc)
{
#ifdef UNDANGLE
    // トップ2ビットを1にする
    ADDRINT addr2 = pointee | (0x3LL << 62);
    PIN_SafeCopy ((VOID *)pointer, (VOID *)&addr2, sizeof (ADDRINT));
#else
    ADDRINT addr2 = NULLIFY_PATTERN;
    PIN_SafeCopy ((VOID *)pointer, (VOID *)&addr2, sizeof (ADDRINT));
#endif
    DLOG ("nullify pointer: %lx (-> %lx)\n", pointer, pointee);

#ifdef UNDANGLE
    // fprintf (OUT_FP, "nullify pointer: %lx (-> %lx)\n", pointer, pointee);
    UNUSED auto found = nullified_map_traceend.find (pointer);
    assert (found == nullified_map_traceend.end ());
    nullified_map_traceend [pointer] = {pointee, mem_loc};
    nullified_map_funcend [pointer]  = {pointee, mem_loc};
#if 0
    dump_nullified_map ();
#endif
#endif
}

void
register_malloc_map (ADDRINT addr, UINT32 size, ADDRINT alloc_loc, const CONTEXT *ctxt)
{
    DLOG ("register_malloc_map: %lx, %d, %lx\n", addr, size, alloc_loc);
    assert (IS_ALIGNED_TO_8BYTE (addr));
    if (addr == 0) return;
    
    ADDRINT rip = PIN_GetContextReg (ctxt, REG_RIP);
#ifdef OUTPUT_LOG
    dump_backtrace (ctxt);
    dump_all_map ();
    check_map_consistency ();
#endif

    auto found = malloc_map.find (addr);
    if (found == malloc_map.end () || found->second.stat != ALLOCATED) {
        DLOG ("alloc_loc=%lx\n", alloc_loc);
        std::vector<ADDRINT> caller_addrs = get_caller_addrs (ctxt, rewind_depth);
        caller_addrs [0] = alloc_loc;
        malloc_map [addr] = {0, size, ALLOCATED, caller_addrs, {}}; // overwrite
#if 0
        dump_backtrace (ctxt);
        dump_malloc_map ();
#endif
    } else {
        // ALLOCATEDなエントリがすでに存在
        // realloc か再割当てで後ろに伸びたか縮んだケース
        // 元から存在したら参照カウント値を再使用する
        assert (found->second.stat == ALLOCATED);
        malloc_map [addr].size = size;

        std::vector<ADDRINT> caller_addrs = get_caller_addrs (ctxt, rewind_depth);
        caller_addrs [0] = alloc_loc;
        malloc_map [addr].alloc_loc = caller_addrs;
    }

    // =======================================
    // 最初は %rax のみが addrカラーを持つ
    tag_clear_reg (rip, REG_RAX, 0, ctxt, false);
    TAG_REG_ARRAY (REG_RAX, 0) = {addr};
    set_reg_malloc_map (REG_RAX, 0, addr, ctxt);
    // =======================================
#if defined (OUTPUT_LOG) 
    dump_backtrace (ctxt);
    dump_all_map ();
    check_map_consistency ();
#endif
}

void
unregister_malloc_map (ADDRINT addr, ADDRINT free_loc, const CONTEXT *ctxt)
{
    DLOG ("unregister_malloc_map: %lx\n", addr);

#if defined (OUTPUT_LOG) 
    dump_backtrace (ctxt);
    dump_all_map ();
    check_map_consistency ();
#endif
    if (addr == 0) return;

    auto found = malloc_map.find (addr);
    if (found == malloc_map.end () && is_nullified (addr)) {
        fprintf (OUT_FP, "double free detected: heap object %lx\n", addr);
        fprintf (OUT_FP, "add the option '-n 0' for more info.\n");
        dump_backtrace (ctxt);
        dump_all_map ();
        return;
    } else if (found->second.stat == DEALLOCATED) {
        auto ip = PIN_GetContextReg (ctxt, REG_RIP);
        auto meta = found->second;
        fprintf (OUT_FP, "%s double free detected: heap object %lx, size = %d, alloc_loc=", addr2loc (ip, 0), addr, meta.size);
        for (auto i: meta.alloc_loc) {
            fprintf (OUT_FP, "%s, ", addr2loc (i, 0));
        }
        fprintf (OUT_FP, "last_use_loc=");
        for (auto i: meta.last_use_loc) {
            fprintf (OUT_FP, "%s, ", addr2loc (i, 0));
        }
        dump_backtrace (ctxt);
        dump_all_map ();
        return;
    }
    assert (found != malloc_map.end ());
    assert (IS_ALIGNED_TO_8BYTE (addr));

    ADDRINT rip = PIN_GetContextReg (ctxt, REG_RIP);

    auto &meta = found->second;
    meta.stat = DEALLOCATED;

    std::vector<ADDRINT> caller_addrs = get_caller_addrs (ctxt, rewind_depth);
    caller_addrs [0] = free_loc;
    meta.free_loc = caller_addrs;

    // addr が指しているヒープオブジェクトのメタデータを調整（減らす）
    for (ADDRINT p = addr; p <= addr + meta.size - 8; p += 8) {
        tag_clear_mem (rip, p, ctxt, true);
    }

    // =======================================
    // ここで，addrの色を持つアドレスをすべて消す
    for (auto i: meta.mem_set) {
        DLOG ("\t!!%lx->%lx\n", i, addr);
        auto found = tag_mem_map.find (i);
        assert (found != tag_mem_map.end ());
        found->second.erase (addr);
        if (found->second.empty ()) tag_mem_map.erase (i);

        if (is_onstack (i)) {
            auto found = tag_stack_map.find (i);
            assert (found != tag_stack_map.end ());
            if (found == tag_stack_map.end ()) {
                fprintf (OUT_FP, "tag_stack_map not found\n");
                dump_tag_stack_map ();
            }
            found->second.erase (addr);
            if (found->second.empty ()) tag_stack_map.erase (i);
        }

        if (NullifyDanglingPointers.Value ()) {
            // 今 free した領域をゼロクリアしないためのガード
            if (!(addr <= i && i < addr + malloc_map [addr].size)) {
                auto found = malloc_map [addr].mem_loc.find (i);
                assert (found != malloc_map [addr].mem_loc.end ());
#if 0
                fprintf (OUT_FP, "mem_loc: ");
                for (auto k: found->second) {
                    char *mem_loc = addr2loc (k, 0);
                    fprintf (OUT_FP, "%lx@%s, ", k, mem_loc);
                }
                fprintf (OUT_FP, "\n");
#endif
                nullify_pointer (i, addr, ctxt, found->second);
            }
        }
    }
    meta.mem_set.clear ();

    for (auto i: meta.reg_set) {
        TAG_REG_ARRAY (i.first, i.second).clear ();
    }
    meta.reg_set.clear ();
    meta.RC = 0;
    // =======================================

#ifdef OUTPUT_LOG
    dump_backtrace (ctxt);
    dump_all_map ();
    check_map_consistency ();
#endif
}

bool
is_onstack (ADDRINT addr)
{
    return (stack_limit <= addr) && (addr <= saved_stack_bottom);
}

bool
is_ondata (ADDRINT addr)
{
    return (data_start <= addr) && (addr <= data_end);
}

bool
reg_is_general_purpose (REG reg)
{
    // REG_is_gr_type () は 64ビット以外だと false を返す
    return REG_is_gr64 (reg) || REG_is_gr32 (reg)
        || REG_is_gr16 (reg) || REG_is_gr8 (reg);
}

void
clear_reg_malloc_map (REG reg, int nth, ADDRINT tag)
{
    DLOG ("clear_reg_malloc_map: %s[%d]=>%lx\n",
          REG_StringShort (reg).c_str (), nth, tag);
    auto found = malloc_map.find (tag);
    assert (found != malloc_map.end ());
    auto &meta = found->second;
    meta.reg_loc.erase ({reg, nth});
    auto ret = meta.reg_set.erase ({reg, nth});
    if (ret) { // 消したときだけカウントダウン
        meta.RC--;
    }
}

void
clear_mem_malloc_map (ADDRINT addr, ADDRINT tag)
{
    DLOG ("clear_mem_malloc_map: %lx=>%lx\n", addr, tag);
    auto found = malloc_map.find (tag);
    assert (found != malloc_map.end ());
    auto &meta = found->second;
    meta.mem_loc.erase (addr);
    auto ret = meta.mem_set.erase (addr);
    if (ret) {
        meta.RC--;
    }
}

void
set_reg_malloc_map (REG reg, int nth, ADDRINT tag, const CONTEXT *ctxt) // reg -> tag
{
    DLOG ("set_reg_malloc_map: %s[%d]=>%lx\n",
          REG_StringShort (reg).c_str (), nth, tag);
    auto found = malloc_map.find (tag);
    assert (found != malloc_map.end ());
    auto &meta = found->second;
    meta.reg_loc.insert ({{reg, nth}, get_caller_addrs (ctxt, rewind_depth)});
    auto ret = meta.reg_set.insert ({reg, nth});
    if (ret.second) { // 挿入されたときだけカウントアップ
        meta.RC++;
    }
}

void
set_mem_malloc_map (ADDRINT addr, ADDRINT tag, const CONTEXT *ctxt) // addr->tag
{
    DLOG ("set_mem_malloc_map: %lx=>%lx\n", addr, tag);
    auto found = malloc_map.find (tag);
    assert (found != malloc_map.end ());
    auto &meta = found->second;
    meta.mem_loc.insert ({addr, get_caller_addrs (ctxt, rewind_depth)});
    auto ret = meta.mem_set.insert (addr);
    if (ret.second) {
        meta.RC++;
    }
}

/* 解析関数 =================================================== */
VOID
MainBefore (CONTEXT* ctxt)
{
    if (IsMainCalled (false)) return; // 2回呼ばれる可能性があるのでガード
    DLOG ("main is called ====================\n");
    IsMainCalled (true);

//    PIN_ExitApplication (1);
#if 0
    printf ("%s\n", INDEX_REG_STR [10]);
    printf ("REG_XMM0=%d, REG_YMM0=%d\n", REG_XMM0, REG_YMM0);
#endif    
#if 0
    tag_reg_array [INDEX_RAX][0].insert (0xDEADBEEF);
    tag_reg_array [INDEX_XMM0][1].insert (0xCAFEBABE);
    tag_reg_array [INDEX_XMM0][1].insert (0xDEADBEEF);
    dump_tag_reg_array ();
    PIN_ExitApplication (0);
#endif
#if 0
    tag_copy_mem2mem_region (0, 0x1001, 0x2001, 24, ctxt);
#endif
#if 0
    register_malloc_map (0x700000, 8, 0, ctxt);
    tag_copy_reg2reg (0x401193, REG_RAX, REG_RCX, 1, ctxt);
    register_malloc_map (0x800000, 8, 0, ctxt);
    tag_copy_reg2reg (0x401193, REG_RAX, REG_RCX, 0, ctxt);
    register_malloc_map (0x900000, 8, 0, ctxt);
    tag_copy_reg2reg (0x401193, REG_RAX, REG_RDX, 1, ctxt);
    tag_copy_reg2reg (0x401193, REG_RCX, REG_RAX, 1, ctxt);
    tag_copy_reg2reg (0x401193, REG_RAX, REG_RDX, 1, ctxt);
    dump_all_map ();
    PIN_ExitApplication (0);
#endif
}

VOID
MainAfter (CONTEXT* ctxt)
{
    if (IsMainExited (false)) return; // 2回呼ばれる可能性があるのでガード
    DLOG ("return from main ====================\n");
    IsMainExited (true);
    ADDRINT rip = PIN_GetContextReg (ctxt, REG_RIP);

    // main を呼び出す __libc_start_main には AfterFuncReturn を計装していないため
    AfterFuncReturn (rip, ctxt);

    if (MarkSweepOnMainExited.Value ()) {
        mark_sweep ();
    }

#ifdef CALL_STAT
    dump_call_stat ();
    dump_malloc_map ();
#endif
    PIN_ExitApplication (0);
}

#if 0
VOID
RSPBefore (ADDRINT ip, ADDRINT rsp)
{
    saved_pre_rsp = rsp;
    DLOG2 (ip, "RSPBefore: saved_pre_rsp=%lx@%lx\n", saved_pre_rsp, ip);
}

VOID
RSPAfter (ADDRINT ip, ADDRINT rsp)
{
    if (!IsMainCalled (false)) return;

    DLOG2 (ip, "RSPAfter: saved_pre_rsp=%lx, rsp=%lx\n", saved_pre_rsp, rsp);
    // redzone を壊さないように，redzone を超えたエリアを増減分だけゼロクリア
#if 0
    if (rsp < saved_pre_rsp) {
        // スタック成長
        UINT32 size = saved_pre_rsp - rsp;
        nullify_stack_region (rsp - 128, size);
    } else {
        // スタック伸縮
        UINT32 size = rsp - saved_pre_rsp;
        nullify_stack_region (saved_pre_rsp - 128, size);
        if (UseZCT.Value ())  {
            check_ZCT (rsp, ctxt);
        } 
        if (RefCountOnStack.Value ()) {
            check_stack_map (rsp, ctxt);
        }
    }
#endif
}
#endif

VOID
BeforeFuncCall (ADDRINT ip, CONTEXT *ctxt, ADDRINT target_addr, ADDRINT pre_addr, ADDRINT next_addr)
{
    if (!IsMainCalled (false)) return;
    DLOG2 ((ADDRINT) ip, "BeforeFuncCall: %s@%lx->%s@%lx (pre=%lx, next=%lx)\n",
           RTN_FindNameByAddress (ip).c_str (), ip,
           RTN_FindNameByAddress (target_addr).c_str (), target_addr,
           pre_addr, next_addr);
    tag_clear_reg (ip, REG_RAX, 0, ctxt, true);
}

VOID
AfterFuncReturn (ADDRINT ip, CONTEXT *ctxt)
{
    if (!IsMainCalled (false)) return;
    DLOG2 (ip, "AfterFuncReturn: %s@%lx<-\n",
           RTN_FindNameByAddress (ip).c_str (), ip);
    ADDRINT rsp =  PIN_GetContextReg (ctxt, REG_RSP);
#if 0
    dump_all_map ();
#endif
    tag_clear_caller_save_regs (ip, ctxt);
    
    for (auto i = tag_stack_map.begin (); i != tag_stack_map.end (); ) {
#ifdef OUTPUT_LOG
        DLOG ("\tstack checking addr=%lx, rsp=%lx\n", i->first, rsp);
#endif
        if (i->first < rsp) {
#ifdef OUTPUT_LOG
            DLOG ("\tstack clearing addr=%lx, rsp=%lx\n", i->first, rsp);
#endif
            tag_clear_mem (ip, (i++)->first, ctxt, true);
        } else {
            break;
        }
    }
#ifdef OUTPUT_LOG
    dump_backtrace (ctxt);
    dump_all_map ();
    check_map_consistency ();
#endif
}

VOID
MemoryAccessBefore (const CONTEXT *ctxt, ADDRINT ip, UINT32 nth, ADDRINT addr, UINT32 size, char *func_name, char *disasm, bool is_write)
{
    saved_addr = (ADDRINT) addr;
 
    for (ADDRINT p = (ADDRINT) addr; p <= (ADDRINT) addr + size - 8; p += 8) {
        ADDRINT addr2;
        PIN_SafeCopy (&addr2, (VOID *)p, sizeof (ADDRINT));
        if (ROUND_DOWN_TO_8BYTE (addr2) == watched_addr) {
            // fprintf (OUT_FP, "*%lx=%lx ", addr, addr2);
            fprintf (OUT_FP, "%s %s, %s\n",
                     (is_write ? "O" : "R"), addr2loc (ip, 0), func_name);
//            fprintf (OUT_FP, "\t%s\n", PIN_UndecorateSymbolName (func_name, UNDECORATION_COMPLETE).c_str ());
            fprintf (OUT_FP, "\t%s (#%d-memop)\n", disasm, nth);
            saved_addr = 0;
            break;
        }
    }
}

VOID
MemoryAccessAfter (const CONTEXT *ctxt, ADDRINT ip, UINT32 nth, UINT32 size, char *func_name, char *disasm)
{
    ADDRINT addr = saved_addr;
    if (addr == 0) return;
    for (ADDRINT p = addr; p <= addr + size - 8; p += 8) {
        ADDRINT addr2;
        PIN_SafeCopy (&addr2, (VOID *)p, sizeof (ADDRINT));
        if (ROUND_DOWN_TO_8BYTE (addr2) == watched_addr) {
            // fprintf (OUT_FP, "*%lx=%lx ", addr, addr2);
            fprintf (OUT_FP, "W %s, %s\n", addr2loc (ip, 0), func_name);
//            fprintf (OUT_FP, "\t%s\n", PIN_UndecorateSymbolName (func_name, UNDECORATION_COMPLETE).c_str ());
            fprintf (OUT_FP, "\t%s (#%d-memop)\n", disasm, nth);
            break;
        }
    }
}

VOID
RegisterAccessBefore (const CONTEXT *ctxt, ADDRINT ip, UINT32 nth, ADDRINT reg_ref, UINT32 size, char *func_name, char *disasm, bool is_write)
{
    DLOG ("RegisterAccessBefore: ip=%lx, nth=%d, reg_ref=%lx, size=%d, func_name=%s, disasm=%s\n", ip, nth, reg_ref, size, func_name, disasm);
    if (size < 8) return;
    for (ADDRINT p = reg_ref; p <= reg_ref + size - 8; p += 8) {
        ADDRINT addr2;
        PIN_SafeCopy (&addr2, (VOID *)p, sizeof (ADDRINT));
        if (ROUND_DOWN_TO_8BYTE (addr2) == watched_addr) {
            fprintf (OUT_FP, "%s %s, %s\n",
                     (is_write ? "O" : "R"), addr2loc (ip, 0), func_name);
//            fprintf (OUT_FP, "\t%s\n", PIN_UndecorateSymbolName (func_name, UNDECORATION_COMPLETE).c_str ());
            fprintf (OUT_FP, "\t%s (#%d-regop)\n", disasm, nth);
            break;
        }
    }
}

VOID
RegisterAccessAfter (const CONTEXT *ctxt, ADDRINT ip, UINT32 nth, ADDRINT reg_ref, UINT32 size, char *func_name, char *disasm)
{
    DLOG ("RegisterAccessBefore: ip=%lx, nth=%d, reg_ref=%lx, size=%d, func_name=%s, disasm=%s\n", ip, nth, reg_ref, size, func_name, disasm);
    if (size < 8) return;
    for (ADDRINT p = reg_ref; p <= reg_ref + size - 8; p += 8) {
        ADDRINT addr2;
        PIN_SafeCopy (&addr2, (VOID *)p, sizeof (ADDRINT));
        if (ROUND_DOWN_TO_8BYTE (addr2) == watched_addr) {
            fprintf (OUT_FP, "W %s, %s\n", addr2loc (ip, 0), func_name);
//            fprintf (OUT_FP, "\t%s\n", PIN_UndecorateSymbolName (func_name, UNDECORATION_COMPLETE).c_str ());
            fprintf (OUT_FP, "\t%s (#%d-regop)\n", disasm, nth);
        }
    }
}

void
check_map_consistency (void)
{
    // malloc_map にあるタグは，tag_{reg,mem}_map と tag_stack_map にある
    for (auto i: malloc_map) {
        for (auto j: i.second.mem_set) {
            UNUSED auto found = tag_mem_map.find (j);
            assert (found != tag_mem_map.end ());
            assert (found->second.find (i.first) != found->second.end ());
            if (is_onstack (j)) {
                UNUSED auto found = tag_stack_map.find (j);
                assert (found != tag_stack_map.end ());
                assert (found->second.find (i.first) != found->second.end ());
            }
        }
        for (auto j: i.second.reg_set) {
            auto tag_set = TAG_REG_ARRAY (j.first, j.second);
            assert (!tag_set.empty ());
            assert (tag_set.find (i.first) != tag_set.end ());
        }
    }
    // 上の逆
    for (auto i: tag_mem_map) {
        assert (!i.second.empty ());
        for (auto j: i.second) {
            auto found = malloc_map.find (j);
            assert (found != malloc_map.end ());
            auto &mem_set = found->second.mem_set;
            if (mem_set.find (i.first) == mem_set.end ()) {
                DLOG ("%lx=>%lx\n", i.first, j);
            }
            assert (mem_set.find (i.first) != mem_set.end ());
        }
    }
    for (auto i: tag_stack_map) {
        assert (!i.second.empty ());
        for (auto j: i.second) {
            auto found = malloc_map.find (j);
            assert (found != malloc_map.end ());
            UNUSED auto &mem_set = found->second.mem_set;
            assert (mem_set.find (i.first) != mem_set.end ());
        }
    }
    for (int i = 0; i < NUM_INDEX_REG; i++) {
        for (int j = 0; j < NUM_TAG_PER_REG; j++) {
            auto tag_set = tag_reg_array [i][j];
            if (tag_set.empty ()) {
                continue;
            }
            for (auto tag: tag_set) {
                auto found = malloc_map.find (tag);
                assert (found != malloc_map.end ());
                UNUSED auto &reg_set = found->second.reg_set;
                assert (reg_set.find ({INDEX_REG_REG [i], j}) != reg_set.end ());
            }
        }
    }
    DLOG ("check_map_consistency: done\n");
}

void
check_RC (ADDRINT ip, ADDRINT addr, const CONTEXT *ctxt)
{
    DLOG2 (ip, "check_RC: tag=%lx\n", addr);

    auto found = malloc_map.find (addr);
    assert (found != malloc_map.end ());
    auto &meta = found->second;
            
#if defined (OUTPUT_LOG)
    dump_backtrace (ctxt);
    dump_all_map ();
    check_map_consistency ();
#endif

#if 0
    // 正確には last use ではなく，参照数が減った場所
    if (!IsMainExited (false)) {
        meta.last_use_loc = get_caller_addrs (ctxt, rewind_depth);
    }
#endif

    if (meta.RC <= 0 && meta.stat == ALLOCATED) {
        fprintf (OUT_FP, "%s memory leak detected: "
                 "heap object %lx, size = %d, RC = %d, alloc_loc=",
                 addr2loc (ip, 0), addr, meta.size, meta.RC);
        for (auto i: meta.alloc_loc) {
            fprintf (OUT_FP, "%s, ", addr2loc (i, 0));
        }
        fprintf (OUT_FP, "last_use_loc=");
        for (auto i: meta.last_use_loc) {
            fprintf (OUT_FP, "%s, ", addr2loc (i, 0));
        }
        fprintf (OUT_FP, "\n");
        dump_backtrace (ctxt);
        dump_all_map ();
        if (BreakOnLeakDetected.Value ()) {
            PIN_ApplicationBreakpoint (ctxt, PIN_ThreadId (), TRUE, "leak detected");
        }

        // メモリリークの連鎖検出のため，このメモリを free する
        if (FreeLeakedMemory.Value ()) {
            fprintf (OUT_FP, "freeing %lx to detect more leak\n", addr);
            unregister_malloc_map (addr, 0, ctxt);
        }
        if (StopOnLeakDetected.Value ()) {
            PIN_ExitApplication (0);
        }
    }

#if defined (OUTPUT_LOG) 
    dump_backtrace (ctxt);
    dump_all_map ();
    check_map_consistency ();
#endif
}

void
update_last_use_loc (ADDRINT ip, ADDRINT addr, const CONTEXT *ctxt)
{
    auto found = malloc_map.find (addr);
    assert (found != malloc_map.end ());
    auto &meta = found->second;

    if (!IsMainExited (false)) {
        meta.last_use_loc = get_caller_addrs (ctxt, rewind_depth);
    }
}

void
tag_clear_reg (ADDRINT ip, REG reg, int nth, const CONTEXT *ctxt, bool do_check)
{
    DLOG2 (ip, "@tag_clear_reg: %s[%d], do_check=%d\n",
           REG_StringShort (reg).c_str (), nth, do_check);
#ifdef CALL_STAT
    call_stat ["tag_clear_reg"]++;
#endif

    auto old_tag_set = TAG_REG_ARRAY (reg, nth);

    for (auto tag: old_tag_set) {
        clear_reg_malloc_map (reg, nth, tag);
    }
#if 0
    dump_all_map ();
#endif
    TAG_REG_ARRAY (reg, nth).clear ();
    
    for (auto tag: old_tag_set) {
        update_last_use_loc (ip, tag, ctxt);
        if (do_check) {
            DLOG ("\tchecking tag: %lx\n", tag);
            check_RC (ip, tag, ctxt);
        }
    }
#if defined (OUTPUT_LOG) 
    dump_backtrace (ctxt);
    dump_all_map ();
    check_map_consistency ();
#endif
}

void
tag_clear_mmreg (ADDRINT ip, int nth, const CONTEXT *ctxt, bool do_check)
{
    int top_of_stack = get_fpsw_tos (ctxt);
    DLOG2 (ip, "@tag_clear_mmreg: nth=%d, tos=%d, do_check=%d\n",
           nth, top_of_stack, do_check);
#ifdef CALL_STAT
    call_stat ["tag_clear_mmreg"]++;
#endif
    int mm_index = (top_of_stack + 7) % 8 + nth;
    assert (0 <= mm_index && mm_index <= 7);
    tag_clear_reg (ip, MM_REG [mm_index], 0, ctxt, do_check);
}

void
tag_clear_reg_width (ADDRINT ip, REG reg, const CONTEXT *ctxt, bool do_check)
{
    DLOG2 (ip, "@tag_clear_reg_width: %s, do_check=%d\n",
           REG_StringShort (reg).c_str (), do_check);
#ifdef CALL_STAT
    call_stat ["tag_clear_reg_width"]++;
#endif

    for (int i = 0; i < reg_width (reg); i++) {
        tag_clear_reg (ip, reg, i, ctxt, do_check);
    }
#if defined (OUTPUT_LOG) 
    dump_backtrace (ctxt);
    dump_all_map ();
    check_map_consistency ();
#endif
}

void
tag_clear_reg_full (ADDRINT ip, REG reg, const CONTEXT *ctxt, bool do_check)
{
    DLOG2 (ip, "@tag_clear_reg_full: %s, do_check=%d\n",
           REG_StringShort (reg).c_str (), do_check);
#ifdef CALL_STAT
    call_stat ["tag_clear_reg_full"]++;
#endif

    for (int i = 0; i < NUM_TAG_PER_REG; i++) {
        tag_clear_reg (ip, reg, i, ctxt, do_check);
    }
#if defined (OUTPUT_LOG) 
    dump_backtrace (ctxt);
    dump_all_map ();
    check_map_consistency ();
#endif
}

void
tag_clear_caller_save_regs (ADDRINT ip, const CONTEXT *ctxt)
{
    DLOG2 (ip, "tag_clear_caller_save_regs: %lx\n", ip);
#ifdef CALL_STAT
    call_stat ["tag_clear_caller_save_regs"]++;
#endif
    std::set<REG> caller_save_regs = { /* REG_RAX, */ // %rax以外
                                      REG_RCX, REG_RDX, REG_RDI, REG_RSI,
                                      REG_R8, REG_R9, REG_R10, REG_R11};
    for (auto reg: caller_save_regs) {
        tag_clear_reg (ip, reg, 0, ctxt, true);
    }
    DLOG2( ip, "\tend of tag_clear_caller_save_regs =======\n");
}

#if 0
void
tag_clear_unaligned_mem (ADDRINT ip, ADDRINT addr, const CONTEXT *ctxt, bool do_check)
{
    // 8バイト以上で8バイト境界では無いメモリのクリア
    assert (!IS_ALIGNED_TO_8BYTE (addr));
    ADDRINT addr_down = ROUND_DOWN_TO_8BYTE (addr);
    ADDRINT addr_up   = ROUND_UP_TO_8BYTE (addr);
    tag_clear_mem (ip, addr_down, ctxt, do_check);
    tag_clear_mem (ip, addr_up, ctxt, do_check);
    DLOG2 (ip, "tag_clear_unaligned_mem: %lx {%lx, %lx}, do_check=%d\n",
           addr, addr_down, addr_up, do_check);
}
#endif

void
tag_clear_mem (ADDRINT ip, ADDRINT addr, const CONTEXT *ctxt, bool do_check)
{
    // 8バイト以下のメモリのクリア
    ADDRINT addr_down = ROUND_DOWN_TO_8BYTE (addr);
    DLOG2 (ip, "@tag_clear_mem: %lx {%lx}, do_check=%d, is_onstack=%d\n",
           addr, addr_down, do_check, is_onstack (addr));
#ifdef CALL_STAT
    call_stat ["tag_clear_mem"]++;
#endif

    auto found = tag_mem_map.find (addr_down);
    if (found == tag_mem_map.end ()) return;

    for (auto tag: found->second) {
        clear_mem_malloc_map (addr_down, tag);
    }
    
    auto old_tag_set = found->second;
    tag_mem_map.erase (addr_down);
    if (is_onstack (addr_down)) {
        tag_stack_map.erase (addr_down);
    }
    
    for (auto tag: old_tag_set) {
        update_last_use_loc (ip, tag, ctxt);
        if (do_check) {
            DLOG ("\tchecking tag: %lx\n", tag);
            check_RC (ip, tag, ctxt);
        }
    }
#if defined (OUTPUT_LOG) 
    dump_backtrace (ctxt);
    dump_all_map ();
    check_map_consistency ();
#endif
}

void
tag_clear_mem_region (ADDRINT ip, ADDRINT dst_mem, UINT32 size, const CONTEXT *ctxt)
{
    DLOG2 (ip, "tag_clear_mem_region %lx: %lx (size %d)\n", ip,  dst_mem, size);
#ifdef CALL_STAT
    call_stat ["tag_clear_mem_region"]++;
#endif

    ADDRINT d = ROUND_DOWN_TO_8BYTE (dst_mem), limit = dst_mem + size - 8;

    for (; d <= limit; d += 8) {
        DLOG ("\t(clear) d=%lx, limit=%lx, size=%d\n", d, limit, size);
        tag_clear_mem (ip, d, ctxt, true);
    }
    if (!IS_ALIGNED_TO_8BYTE (limit)) {
        DLOG ("\t(clear) d=%lx, limit=%lx, size=%d\n", d, limit, size);
        tag_clear_mem (ip, d, ctxt, true);
    }
    DLOG ("end of tag_clear_mem_region ======\n");
}

void tag_copy_reg2reg_nth (ADDRINT ip, REG src_reg, int src_nth, REG dst_reg, int dst_nth, bool do_strong_update, const CONTEXT *ctxt)
{
    DLOG2 (ip, "@tag_copy_reg2reg (%d): %s[%d]=>%s[%d]\n",
           do_strong_update,
           REG_StringShort (src_reg).c_str (), src_nth,
           REG_StringShort (dst_reg).c_str (), dst_nth);
#ifdef CALL_STAT
    call_stat ["tag_copy_reg2reg_nth"]++;
#endif

    if (src_reg == dst_reg) return;

    auto old_dst_set = TAG_REG_ARRAY (dst_reg, dst_nth);

    if (do_strong_update) {
        tag_clear_reg (ip, dst_reg, dst_nth, ctxt, false);
    }

    auto &src_set = TAG_REG_ARRAY (src_reg, src_nth);
    if (!src_set.empty ()) {
        for (UNUSED auto tag: src_set) {
            DLOG2 (ip, "\ttag_copy_reg2reg_nth (%d): %s[%d]=>%s[%d] (%lx)\n",
                   do_strong_update,
                   REG_StringShort (src_reg).c_str (), src_nth,
                   REG_StringShort (dst_reg).c_str (), dst_nth, tag);
        }
        
        TAG_REG_ARRAY (dst_reg, dst_nth).insert (src_set.begin (), src_set.end ());

        for (auto tag: src_set) {
            set_reg_malloc_map (dst_reg, dst_nth, tag, ctxt);
        }
    }
    
    for (auto tag: old_dst_set) {
        update_last_use_loc (ip, tag, ctxt);
        if (do_strong_update) {
            DLOG ("\tchecking tag: %lx\n", tag);
            check_RC (ip, tag, ctxt);
        }
    }

#if defined (OUTPUT_LOG) 
    dump_backtrace (ctxt);
    dump_all_map ();
    check_map_consistency ();
#endif
}

void
tag_copy_mem2reg_nth (ADDRINT ip, ADDRINT src_mem, REG dst_reg, int dst_nth, bool do_strong_update, const CONTEXT *ctxt)
{
    DLOG2 (ip, "@tag_copy_mem2reg_nth (%d): %lx+%d=>%s[%d], is_onstack=%d\n",
           do_strong_update, src_mem, dst_nth * 8,
           REG_StringShort (dst_reg).c_str (), dst_nth, is_onstack (src_mem));
#ifdef CALL_STAT
    call_stat ["tag_copy_mem2reg_nth"]++;
#endif

    src_mem += dst_nth * 8;

    if (!IS_ALIGNED_TO_8BYTE (src_mem)) {
        DLOG ("tag_copy_mem2reg_nth: unaligned src_mem: %lx\n", src_mem);
        tag_clear_reg (ip, dst_reg, dst_nth, ctxt, false);
        return;
    }

    auto old_dst_set = TAG_REG_ARRAY (dst_reg, dst_nth);

    if (do_strong_update) {
        tag_clear_reg (ip, dst_reg, dst_nth, ctxt, false);
    }

    auto found_src = tag_mem_map.find (src_mem);
    if (found_src != tag_mem_map.end ()) {
        for (UNUSED auto tag: found_src->second) {
            DLOG2 (ip, "\ttag_copy_mem2reg_nth (%d): %lx=>%s[%d] (%lx), is_onstack=%d\n",
                   do_strong_update, src_mem,
                   REG_StringShort (dst_reg).c_str (), dst_nth, tag,
                   is_onstack (src_mem));
        }
        
        auto &src_set = found_src->second;
        TAG_REG_ARRAY (dst_reg, dst_nth).insert (src_set.begin (), src_set.end ());

        for (auto tag: found_src->second) {
            set_reg_malloc_map (dst_reg, dst_nth, tag, ctxt);
        }
    }

    for (auto tag: old_dst_set) {
        update_last_use_loc (ip, tag, ctxt);
        if (do_strong_update) {
            DLOG ("\tchecking tag: %lx\n", tag);
            check_RC (ip, tag, ctxt);
        }
    }

#if defined (OUTPUT_LOG) 
    dump_backtrace (ctxt);
    dump_all_map ();
    check_map_consistency ();
#endif
}

void
tag_copy_reg2mem_nth (ADDRINT ip, REG src_reg, int src_nth, ADDRINT dst_mem, bool do_strong_update, const CONTEXT *ctxt)
{
    DLOG2 (ip, "@tag_copy_reg2mem_nth (%d): %s[%d]=>%lx+%d, is_onstack=%d\n",
           do_strong_update,
           REG_StringShort (src_reg).c_str (), src_nth, dst_mem, 
           src_nth * 8, is_onstack (dst_mem));
#ifdef CALL_STAT
    call_stat ["tag_copy_reg2mem_nth"]++;
#endif

    dst_mem += src_nth * 8;

    if (!IS_ALIGNED_TO_8BYTE (dst_mem)) {
        DLOG ("tag_copy_reg2mem_nth: unaligned dst_mem: %lx\n", dst_mem);
        tag_clear_mem_region (ip, dst_mem, 8, ctxt);
        return;
    }

    std::set<ADDRINT> old_dst_set;
    auto found_dst = tag_mem_map.find (dst_mem);
    if (found_dst != tag_mem_map.end ()) {
        old_dst_set = found_dst->second;
    }

    if (do_strong_update) {
        tag_clear_mem (ip, dst_mem, ctxt, false);
    }

    auto &src_set = TAG_REG_ARRAY (src_reg, src_nth);
    if (!src_set.empty ()) {
        for (UNUSED auto tag: src_set) {
            DLOG2 (ip, "\ttag_copy_reg2mem_nth (%d): %s[%d]=>%lx (%lx), is_onstack=%d\n",
                   do_strong_update,
                   REG_StringShort (src_reg).c_str (), src_nth, dst_mem, tag,
                   is_onstack (dst_mem));
        }
        
        tag_mem_map [dst_mem].insert (src_set.begin (), src_set.end ());
        if (is_onstack (dst_mem)) {
            tag_stack_map [dst_mem].insert (src_set.begin (), src_set.end ());
        }
        
        for (auto tag: src_set) {
            set_mem_malloc_map (dst_mem, tag, ctxt);
        }
    }

    for (auto tag: old_dst_set) {
        update_last_use_loc (ip, tag, ctxt);
        if (do_strong_update) {
            DLOG ("\tchecking tag: %lx\n", tag);
            check_RC (ip, tag, ctxt);
        }
    }
#if defined (OUTPUT_LOG) 
    dump_backtrace (ctxt);
    dump_all_map ();
    check_map_consistency ();
#endif
}

void
tag_copy_mem2mem (ADDRINT ip, ADDRINT src_mem, ADDRINT dst_mem, bool do_strong_update, const CONTEXT *ctxt)
{
    DLOG2 (ip, "@tag_copy_mem2mem (%d): %lx => %lx, is_onstack=%d,%d\n",
           do_strong_update, src_mem, dst_mem,
           is_onstack (src_mem), is_onstack (dst_mem));
#ifdef CALL_STAT
    call_stat ["tag_copy_mem2mem"]++;
#endif

    if (src_mem == dst_mem) return;

    assert (IS_ALIGNED_TO_8BYTE (dst_mem));
    if (!IS_ALIGNED_TO_8BYTE (dst_mem) || !IS_ALIGNED_TO_8BYTE (dst_mem)) {
        DLOG ("tag_copy_mem2mem: unaligned src_mem: %lx\n", src_mem);
        DLOG ("tag_copy_mem2mem: unaligned dst_mem: %lx\n", dst_mem);
        tag_clear_mem_region (ip, dst_mem, 8, ctxt);
        return;
    }

    std::set<ADDRINT> old_dst_set;
    auto found_dst = tag_mem_map.find (dst_mem);
    if (found_dst != tag_mem_map.end ()) {
        old_dst_set = found_dst->second;
    }

    if (do_strong_update) {
        tag_clear_mem (ip, dst_mem, ctxt, false);
    }

    auto found_src = tag_mem_map.find (src_mem);
    if (found_src != tag_mem_map.end ()) {
        for (UNUSED auto tag: found_src->second) {
            DLOG2 (ip, "@tag_copy_mem2mem (%d): %lx => %lx (%lx), is_onstack=%d,%d\n",
                   do_strong_update, src_mem, dst_mem, tag,
                   is_onstack (src_mem), is_onstack (dst_mem));
        }
        
        auto &src_set = found_src->second;
        tag_mem_map [dst_mem].insert (src_set.begin (), src_set.end ());
        if (is_onstack (dst_mem)) {
            tag_stack_map [dst_mem].insert (src_set.begin (), src_set.end ());
        }

        for (auto tag: src_set) {
            set_mem_malloc_map (dst_mem, tag, ctxt);
        }
    }

    for (auto tag: old_dst_set) {
        update_last_use_loc (ip, tag, ctxt);
        if (do_strong_update) {
            DLOG ("\tchecking tag: %lx\n", tag);
            check_RC (ip, tag, ctxt);
        }
    }
#if defined (OUTPUT_LOG) 
    dump_backtrace (ctxt);
    dump_all_map ();
    check_map_consistency ();
#endif
}

void
tag_copy_mem2mem_region (ADDRINT ip, ADDRINT src_mem, ADDRINT dst_mem, UINT32 size, const CONTEXT *ctxt)
{
    // overlap に対応するため，まずい場合は逆順にコピーする
    
    DLOG2 (ip, "tag_copy_mem2mem_region %lx: %lx->%lx (size %d)\n",
           ip, src_mem, dst_mem, size);
#ifdef CALL_STAT
    call_stat ["tag_copy_mem2mem_region"]++;
#endif

    if (dst_mem < src_mem) {
        ADDRINT d = dst_mem, s = src_mem, limit = dst_mem + size - 8;
        DLOG ("\ts=%lx, d=%lx, limit=%lx, size=%d\n", s, d, limit, size);
        if (!IS_ALIGNED_TO_8BYTE (d)) {
            tag_clear_mem (ip, d, ctxt, true);
            s += ROUND_UP_TO_8BYTE (d) - d;
            d = ROUND_UP_TO_8BYTE (d);
        }
        assert (IS_ALIGNED_TO_8BYTE (d));
        if (IS_ALIGNED_TO_8BYTE (s)) {
            for (; d <= limit; d += 8, s += 8) {
                DLOG ("\t(copy) s=%lx, d=%lx, limit=%lx, size=%d\n", s, d, limit, size);
                tag_copy_mem2mem (ip, s, d, true, ctxt);
            }
        } else {
            for (; d <= limit; d += 8, s += 8) {
                DLOG ("\t(clear)s=%lx, d=%lx, limit=%lx, size=%d\n", s, d, limit, size);
                tag_clear_mem (ip, d, ctxt, true);
            }
        }
        if (!IS_ALIGNED_TO_8BYTE (limit)) {
            tag_clear_mem (ip, d, ctxt, true);
        }
    } else if (src_mem < dst_mem) {
        ADDRINT d = dst_mem + size - 8, s = src_mem + size - 8;
        ADDRINT limit = dst_mem;
        DLOG ("\ts=%lx, d=%lx, limit=%lx, size=%d\n", s, d, limit, size);
        if (!IS_ALIGNED_TO_8BYTE (d)) {
            tag_clear_mem (ip, d, ctxt, true);
            s += ROUND_DOWN_TO_8BYTE (d) - d;
            d = ROUND_DOWN_TO_8BYTE (d);
        }
        assert (IS_ALIGNED_TO_8BYTE (d));
        if (IS_ALIGNED_TO_8BYTE (s)) {
            for (; limit <= d; d -= 8, s -= 8) {
                DLOG ("\t(copy) s=%lx, d=%lx, limit=%lx, size=%d\n", s, d, limit, size);
                tag_copy_mem2mem (ip, s, d, true, ctxt);
            }
        } else {
            for (; limit <= d; d -= 8, s -= 8) {
                DLOG ("\t(clear)s=%lx, d=%lx, limit=%lx, size=%d\n", s, d, limit, size);
                tag_clear_mem (ip, d, ctxt, true);
            }
        }
        if (!IS_ALIGNED_TO_8BYTE (limit)) {
            tag_clear_mem (ip, d, ctxt, true);
        }
    }
    DLOG ("end of tag_copy_mem2mem_region======\n");
}

#if 0
void
tag_swap_mmreg (ADDRINT ip, int nth, const CONTEXT *ctxt)
{
    int top_of_stack = get_fpsw_tos (ctxt);
    DLOG2 (ip, "tag_swap_mmreg: st0 <-> st%d (tos=%d)\n", nth, top_of_stack);
    DLOG2 (ip, "\ttag_swap_mmreg: mm%d <-> mm%d\n", 
           top_of_stack, top_of_stack + nth);
    REG src_reg = (REG) (REG_MM0 + top_of_stack);
    REG dst_reg = (REG) (src_reg + nth);
    tag_copy_reg2reg_nth (ip, src_reg,  0, REG_NONE, 0, true, ctxt);
    tag_copy_reg2reg_nth (ip, dst_reg,  0, src_reg,  0, true, ctxt);
    tag_copy_reg2reg_nth (ip, REG_NONE, 0, dst_reg,  0, true, ctxt);
}
#endif

void
tag_cmpxchg_reg2reg_clear (ADDRINT ip, ADDRINT rax_value, REG dst_reg, ADDRINT dst_value, const CONTEXT *ctxt)
{
    if (rax_value == dst_value) {
        DLOG2 (ip, "@tag_cmpxchg_reg2reg_clear (==): %s\n",
               REG_StringShort (dst_reg).c_str ());
        tag_clear_reg (ip, dst_reg, 0, ctxt, true);
    } else {
        DLOG2 (ip, "@tag_cmpxchg_reg2reg_clear (!=): RAX\n");
        tag_clear_reg (ip, REG_RAX, 0, ctxt, true);
    }
}

void
tag_cmpxchg_reg2mem_clear (ADDRINT ip, ADDRINT rax_value, ADDRINT dst_mem, const CONTEXT *ctxt)
{
    ADDRINT dst_value;
    PIN_SafeCopy ((VOID *)&dst_value, (VOID *)dst_mem, sizeof (ADDRINT));

    if (rax_value == dst_value) {
        DLOG2 (ip, "@tag_cmpxchg_reg2mem_clear (==): %lx\n", dst_mem);
        tag_clear_mem (ip, dst_mem, ctxt, true);
    } else {
        DLOG2 (ip, "@tag_cmpxchg_reg2reg_clear (!=): RAX\n");
        tag_clear_reg (ip, REG_RAX, 0, ctxt, true);
    }
}

void
tag_cmpxchg_reg2reg_copy (ADDRINT ip, ADDRINT rax_value, REG src_reg, REG dst_reg, ADDRINT dst_value, const CONTEXT *ctxt)
{
    if (rax_value == dst_value) {
        DLOG2 (ip, "@tag_cmpxchg_reg2reg_copy (==): %s -> %s\n",
               REG_StringShort (src_reg).c_str (),
               REG_StringShort (dst_reg).c_str ());
        tag_copy_reg2reg_nth (ip, src_reg, 0, dst_reg, 0, true, ctxt);
    } else {
        DLOG2 (ip, "@tag_cmpxchg_reg2reg_copy (!=): %s -> RAX\n",
               REG_StringShort (dst_reg).c_str ());
        tag_copy_reg2reg_nth (ip, dst_reg, 0, REG_RAX, 0, true, ctxt);
    }
}

void
tag_cmpxchg_reg2mem_copy (ADDRINT ip, ADDRINT rax_value, REG src_reg, ADDRINT dst_mem, const CONTEXT *ctxt)
{
    ADDRINT dst_value;
    PIN_SafeCopy ((VOID *)&dst_value, (VOID *)dst_mem, sizeof (ADDRINT));

    if (rax_value == dst_value) {
        DLOG2 (ip, "@tag_cmpxchg_reg2mem_copy (==): %s -> %lx\n",
               REG_StringShort (src_reg).c_str (), dst_mem);
        tag_copy_reg2mem_nth (ip, src_reg, 0, dst_mem, true, ctxt);
    } else {
        DLOG2 (ip, "@tag_cmpxchg_reg2mem_copy (!=): %lx -> RAX\n", dst_mem);
        tag_copy_mem2reg_nth (ip, dst_mem, REG_RAX, 0, true, ctxt);
    }
}

void
tag_cmpxchg8b (ADDRINT ip, ADDRINT eax_value, ADDRINT edx_value, ADDRINT dst_mem, const CONTEXT *ctxt)
{
    DLOG2 (ip, "@tag_cmpxchg8b\n");

    ADDRINT dst_value_high, dst_value_low;
    PIN_SafeCopy ((VOID *)&dst_value_low, (VOID *)dst_mem, 4);
    PIN_SafeCopy ((VOID *)&dst_value_high, (VOID *)(((char *)dst_mem)+4), 4);

    // ヒープオブジェクトの，別々に格納されている病的なケースは無視
    if ((dst_value_high == edx_value) && (dst_value_low == eax_value)) {
        tag_clear_mem (ip, dst_mem, ctxt, true);
    } else {
        tag_clear_reg (ip, REG_RDX, 0, ctxt, true);
        tag_clear_reg (ip, REG_RAX, 0, ctxt, true);
    }
}

void
tag_cmpxchg16b (ADDRINT ip, ADDRINT rax_value, ADDRINT rbx_value, ADDRINT rcx_value, ADDRINT rdx_value, ADDRINT dst_mem, const CONTEXT *ctxt)
{
    DLOG2 (ip, "@tag_cmpxchg16b\n");

    ADDRINT dst_value_high, dst_value_low;
    PIN_SafeCopy ((VOID *)&dst_value_low, (VOID *)dst_mem, 8);
    PIN_SafeCopy ((VOID *)&dst_value_high, (VOID *)(((char *)dst_mem)+8), 8);

    // ヒープオブジェクトの，別々に格納されている病的なケースは無視
    if ((dst_value_high == rdx_value) && (dst_value_low == rax_value)) {
        tag_copy_reg2mem_nth (ip, REG_RBX, 0, dst_mem, true, ctxt);
        tag_copy_reg2mem_nth (ip, REG_RCX, 0, dst_mem + 8, true, ctxt);
    } else {
        tag_copy_mem2reg_nth (ip, dst_mem, REG_RAX, 0, true, ctxt);
        tag_copy_mem2reg_nth (ip, dst_mem + 8, REG_RDX, 0, true, ctxt);
    }
}

ADDRINT
return_arg (BOOL arg)
{
    return arg;
}

void
tag_copy_rep_movs (ADDRINT ip, UINT32 size, ADDRINT rflags_value, ADDRINT rcx_value, ADDRINT src_mem, ADDRINT dst_mem, const CONTEXT *ctxt)
{
    bool df_flag = (rflags_value & DF_MASK)!=0;
    DLOG2 (ip, "@tag_copy_rep_movs: DF=%d, size=%d, rcx=%ld, %lx->%lx\n",
           df_flag, size, rcx_value, src_mem, dst_mem);

    ADDRINT d, s, limit;
    if (df_flag) {
        s = src_mem - size * rcx_value;
        d = dst_mem - size * rcx_value;
        limit = dst_mem - 8;
    } else {
        s = src_mem;
        d = dst_mem;
        limit = dst_mem + size * rcx_value - 8;
    }

    if (!IS_ALIGNED_TO_8BYTE (d)) {
        tag_clear_mem (ip, d, ctxt, true);
        s += ROUND_UP_TO_8BYTE (d) - d;
        d = ROUND_UP_TO_8BYTE (d);
    }
    assert (IS_ALIGNED_TO_8BYTE (d));
    if (IS_ALIGNED_TO_8BYTE (s)) {
        for (; d <= limit; d += 8, s += 8) {
            tag_copy_mem2mem (ip, s, d, true, ctxt);
        }
    } else {
        for (; d <= limit; d += 8, s += 8) {
            tag_clear_mem (ip, d, ctxt, true); // src_memとdst_memで境界がずれてたらクリアする
        }
    }

    if (!IS_ALIGNED_TO_8BYTE (limit)) {
        tag_clear_mem (ip, d, ctxt, true);
    }
}

void
tag_copy_rep_lods (ADDRINT ip, UINT32 size, ADDRINT rflags_value, ADDRINT rcx_value, ADDRINT src_mem, const CONTEXT *ctxt)
{
    bool df_flag = (rflags_value & DF_MASK)!=0;
    DLOG2 (ip, "@tag_copy_rep_lods: DF=%d, size=%d, rcx=%ld, %lx->RAX\n",
           df_flag, size, rcx_value, src_mem);

    ADDRINT s, limit;
    if (df_flag) {
        s = src_mem - size * rcx_value;
        if (!IS_ALIGNED_TO_8BYTE (s)) {
            tag_clear_reg (ip, REG_RAX, 0, ctxt, true);
        } else {
            assert (IS_ALIGNED_TO_8BYTE (s));
            // 最初だけコピー
            tag_copy_mem2reg_nth (ip, s, REG_RAX, 0, true, ctxt);
        }
    } else {
        limit = src_mem + size * rcx_value - 8;
        if (!IS_ALIGNED_TO_8BYTE (limit)) {
            tag_clear_reg (ip, REG_RAX, 0, ctxt, true);
        } else {
            assert (IS_ALIGNED_TO_8BYTE (limit));
            // 最後だけコピー
            tag_copy_mem2reg_nth (ip, limit, REG_RAX, 0, true, ctxt);
        }
    }
}

void
tag_copy_rep_stos (ADDRINT ip, UINT32 size, ADDRINT rflags_value, ADDRINT rcx_value, ADDRINT dst_mem, const CONTEXT *ctxt)
{
    bool df_flag = (rflags_value & DF_MASK)!=0;
    DLOG2 (ip, "@tag_copy_rep_stos: DF=%d, size=%d, rcx=%lx, RAX->%lx\n",
           df_flag, size, rcx_value, dst_mem);

    ADDRINT d, limit;
    if (df_flag) {
        d = dst_mem - size * rcx_value;
        limit = dst_mem - 8;
        if (IS_ALIGNED_TO_8BYTE (d)) {
            for (; d <= limit ; d += 8) {
                tag_copy_reg2mem_nth (ip, REG_RAX, 0, d, true, ctxt);
            }
        } else {
            // 最初がずれてたら，すべてテイントを消す
            for (; d <= limit ; d += 8) {
                tag_clear_mem (ip, d, ctxt, true);
            }
        }
    } else {
        d = dst_mem;
        limit = dst_mem + size * rcx_value - 8;
        if (IS_ALIGNED_TO_8BYTE (d)) {
            for (; d <= limit; d += 8) {
                tag_copy_reg2mem_nth (ip, REG_RAX, 0, d, true, ctxt);
            }
        } else {
            for (; d <= limit; d += 8) {
                tag_clear_mem (ip, d, ctxt, true);
            }
        }
    }

    if (!IS_ALIGNED_TO_8BYTE (limit)) {
        tag_clear_mem (ip, d, ctxt, true);
    }
}

/* 計装関数　=================================================== */

void
ins_clear_reg (INS ins, REG dst_reg, int nth)
{
    DLOG2 (INS_Address (ins), "\tins_clear_reg: %s[%d]\n",
           REG_StringShort (dst_reg).c_str (), nth);
    if (reg_is_general_purpose (dst_reg)) {
        dst_reg = REG_FullRegName (dst_reg);
    }

    INS_InsertPredicatedCall (ins, IPOINT_BEFORE,
                              (AFUNPTR) tag_clear_reg,
                              IARG_INST_PTR,
                              IARG_UINT32, dst_reg,
                              IARG_UINT32, nth,
                              IARG_CONST_CONTEXT,
                              IARG_BOOL, true,
                              IARG_END);
}

void
ins_clear_mmreg (INS ins, int nth)
{
    DLOG2 (INS_Address (ins), "\tins_clear_mmreg: nth=%d\n", nth);
    INS_InsertPredicatedCall (ins, IPOINT_BEFORE,
                              (AFUNPTR) tag_clear_mmreg,
                              IARG_INST_PTR,
                              IARG_UINT32, nth,
                              IARG_CONST_CONTEXT,
                              IARG_BOOL, true,
                              IARG_END);
}

void
ins_clear_reg_width (INS ins, REG dst_reg)
{
    DLOG2 (INS_Address (ins),
           "\tins_clear_reg_width: %s\n", REG_StringShort (dst_reg).c_str ());
    if (reg_is_general_purpose (dst_reg)) {
        dst_reg = REG_FullRegName (dst_reg);
    }

    INS_InsertPredicatedCall (ins, IPOINT_BEFORE,
                              (AFUNPTR) tag_clear_reg_width,
                              IARG_INST_PTR,
                              IARG_UINT32, dst_reg,
                              IARG_CONST_CONTEXT,
                              IARG_BOOL, true,
                              IARG_END);
}

void
ins_clear_reg_full (INS ins, REG dst_reg)
{
    DLOG2 (INS_Address (ins),
           "\tins_clear_reg_full: %s\n", REG_StringShort (dst_reg).c_str ());
    if (reg_is_general_purpose (dst_reg)) {
        dst_reg = REG_FullRegName (dst_reg);
    }

    INS_InsertPredicatedCall (ins, IPOINT_BEFORE,
                              (AFUNPTR) tag_clear_reg_full,
                              IARG_INST_PTR,
                              IARG_UINT32, dst_reg,
                              IARG_CONST_CONTEXT,
                              IARG_BOOL, true,
                              IARG_END);
}

void
ins_clear_mem (INS ins, UINT32 dst_memopIdx)
{
    DLOG2 (INS_Address (ins), "\tins_clear_mem: #%d-memop\n", dst_memopIdx);

    INS_InsertPredicatedCall (ins, IPOINT_BEFORE,
                              (AFUNPTR) tag_clear_mem,
                              IARG_INST_PTR,
                              IARG_MEMORYOP_EA, dst_memopIdx,
                              IARG_CONST_CONTEXT,
                              IARG_BOOL, true,
                              IARG_END);
}

void
ins_clear_mem_region (INS ins, UINT32 dst_memopIdx)
{
    DLOG2 (INS_Address (ins), "\tins_clear_mem_region: #%d-memop, %d bytes\n",
           dst_memopIdx, INS_MemoryOperandSize (ins, dst_memopIdx));

    INS_InsertPredicatedCall (ins, IPOINT_BEFORE,
                              (AFUNPTR) tag_clear_mem_region,
                              IARG_INST_PTR,
                              IARG_MEMORYOP_EA, dst_memopIdx,
                              IARG_UINT32, INS_MemoryOperandSize (ins, dst_memopIdx),
                              IARG_CONST_CONTEXT,
                              IARG_BOOL, true,
                              IARG_END);
}

void
ins_copy_reg2reg_nth (INS ins, REG src_reg, int src_nth, REG dst_reg, int dst_nth, bool do_strong_update)
{
    DLOG2 (INS_Address (ins), "\tins_copy_reg2reg_nth (%d): %s[%d]->%s[%d]\n",
           do_strong_update,
           REG_StringShort (src_reg).c_str (), src_nth,
           REG_StringShort (dst_reg).c_str (), dst_nth);

    INS_InsertPredicatedCall (ins, IPOINT_BEFORE,
                              (AFUNPTR) tag_copy_reg2reg_nth,
                              IARG_INST_PTR,
                              IARG_UINT32, src_reg,
                              IARG_UINT32, src_nth,
                              IARG_UINT32, dst_reg,
                              IARG_UINT32, dst_nth,
                              IARG_BOOL, do_strong_update,
                              IARG_CONST_CONTEXT,
                              IARG_END);
}
void
ins_copy_reg2reg (INS ins, REG src_reg, REG dst_reg, bool do_strong_update)
{
    DLOG2 (INS_Address (ins), "\tins_copy_reg2reg (%d): %s[0]->%s[0]\n",
           do_strong_update,
           REG_StringShort (src_reg).c_str (),
           REG_StringShort (dst_reg).c_str ());

    ins_copy_reg2reg_nth (ins, src_reg, 0, dst_reg, 0, do_strong_update);
}

void
ins_copy_mem2reg_nth (INS ins, UINT32 src_memopIdx, REG dst_reg, int dst_nth, bool do_strong_update)
{
    DLOG2 (INS_Address (ins), "\tins_copy_mem2reg_nth (%d): #%d-memop->%s[%d]\n",
           do_strong_update, src_memopIdx,
           REG_StringShort (dst_reg).c_str (), dst_nth);

    INS_InsertPredicatedCall (ins, IPOINT_BEFORE,
                              (AFUNPTR) tag_copy_mem2reg_nth,
                              IARG_INST_PTR,
                              IARG_MEMORYOP_EA, src_memopIdx,
                              IARG_UINT32, dst_reg,
                              IARG_UINT32, dst_nth,
                              IARG_BOOL, do_strong_update,
                              IARG_CONST_CONTEXT,
                              IARG_END);
}

void
ins_copy_mem2reg (INS ins, UINT32 src_memopIdx, REG dst_reg, bool do_strong_update)
{
    DLOG2 (INS_Address (ins), "\tins_copy_mem2reg (%d): #%d-memop->%s[0]\n",
           do_strong_update, src_memopIdx, REG_StringShort (dst_reg).c_str ());

    ins_copy_mem2reg_nth (ins, src_memopIdx, dst_reg, 0, do_strong_update);
}

void
ins_copy_reg2mem_nth (INS ins, REG src_reg, int src_nth, UINT32 dst_memopIdx, bool do_strong_update)
{
    DLOG2 (INS_Address (ins), "\tins_copy_reg2mem_nth (%d): %s[%d]->#%d-memop\n",
           do_strong_update, REG_StringShort (src_reg).c_str (), src_nth, dst_memopIdx);

    INS_InsertPredicatedCall (ins, IPOINT_BEFORE,
                              (AFUNPTR) tag_copy_reg2mem_nth,
                              IARG_INST_PTR,
                              IARG_UINT32, src_reg,
                              IARG_UINT32, src_nth,
                              IARG_MEMORYOP_EA, dst_memopIdx,
                              IARG_BOOL, do_strong_update,
                              IARG_CONST_CONTEXT,
                              IARG_END);
}

void
ins_copy_reg2mem (INS ins, REG src_reg, UINT32 dst_memopIdx, bool do_strong_update)
{
    DLOG2 (INS_Address (ins), "\tins_copy_reg2mem (%d): %s[0]->#%d-memop\n",
           do_strong_update, REG_StringShort (src_reg).c_str (), dst_memopIdx);

    ins_copy_reg2mem_nth (ins, src_reg, 0, dst_memopIdx, do_strong_update);

}

void
ins_copy_mem2mem (INS ins, UINT32 src_memopIdx, UINT32 dst_memopIdx, bool do_strong_update)
{
    DLOG2 (INS_Address (ins),
           "\tins_copy_mem2mem (%d): #%d-memop -> #%d-memop\n",
           do_strong_update, src_memopIdx, dst_memopIdx);

    INS_InsertPredicatedCall (ins, IPOINT_BEFORE,
                              (AFUNPTR) tag_copy_mem2mem, 
                              IARG_INST_PTR,
                              IARG_MEMORYOP_EA, src_memopIdx,
                              IARG_MEMORYOP_EA, dst_memopIdx,
                              IARG_BOOL, do_strong_update,
                              IARG_CONST_CONTEXT,
                              IARG_END);
}

#if 0
void
ins_swap_mmreg (INS ins)
{
    REG mmreg = INS_OperandReg (ins, 1);
    assert (REG_is_st (mmreg));
    DLOG2 (INS_Address (ins), "\tins_swap_mmreg: st0 <-> st%d\n", mmreg - REG_ST0);
    INS_InsertPredicatedCall (ins, IPOINT_BEFORE,
                              (AFUNPTR) tag_swap_mmreg, 
                              IARG_INST_PTR,
                              IARG_UINT32, mmreg - REG_ST0,
                              IARG_CONST_CONTEXT,
                              IARG_END);
}
#endif

void
ins_cmpxchg_reg2reg_clear (INS ins, REG dst_reg)
{
    DLOG2 (INS_Address (ins), "\tins_cmpxchg_reg2reg_clear: %s\n",
           REG_StringShort (dst_reg).c_str ());

    INS_InsertCall (ins, IPOINT_BEFORE,
                    (AFUNPTR) tag_cmpxchg_reg2reg_clear,
                    IARG_INST_PTR,
                    IARG_REG_VALUE, REG_RAX,
                    IARG_UINT32, REG_FullRegName (dst_reg),
                    IARG_REG_VALUE, dst_reg,
                    IARG_CONST_CONTEXT,
                    IARG_END);
}

void
ins_cmpxchg_reg2mem_clear (INS ins, UINT32 dst_memopIdx)
{
    DLOG2 (INS_Address (ins),
           "\tins_cmpxchg_reg2mem_clear: #%d-memop\n", dst_memopIdx);

    INS_InsertCall (ins, IPOINT_BEFORE,
                    (AFUNPTR) tag_cmpxchg_reg2mem_clear,
                    IARG_INST_PTR,
                    IARG_REG_VALUE, REG_RAX,
                    IARG_MEMORYOP_EA, dst_memopIdx,
                    IARG_CONST_CONTEXT,
                    IARG_END);
}

void
ins_cmpxchg_reg2reg_copy (INS ins, REG src_reg, REG dst_reg)
{
    DLOG2 (INS_Address (ins), "\tins_cmpxchg_reg2reg_copy: %s -> %s\n",
           REG_StringShort (src_reg).c_str (),
           REG_StringShort (dst_reg).c_str ());

    INS_InsertCall (ins, IPOINT_BEFORE,
                    (AFUNPTR) tag_cmpxchg_reg2reg_copy,
                    IARG_INST_PTR,
                    IARG_REG_VALUE, REG_RAX,
                    IARG_UINT32, REG_FullRegName (src_reg),
                    IARG_UINT32, REG_FullRegName (dst_reg),
                    IARG_REG_VALUE, dst_reg,
                    IARG_CONST_CONTEXT,
                    IARG_END);
}

void
ins_cmpxchg_reg2mem_copy (INS ins, REG src_reg, UINT32 dst_memopIdx)
{
    DLOG2 (INS_Address (ins), "\tins_cmpxchg_reg2reg_copy: %s -> #%d-memop\n",
           REG_StringShort (src_reg).c_str (), dst_memopIdx);
    INS_InsertCall (ins, IPOINT_BEFORE,
                    (AFUNPTR) tag_cmpxchg_reg2mem_copy,
                    IARG_INST_PTR,
                    IARG_REG_VALUE, REG_RAX,
                    IARG_UINT32, REG_FullRegName (src_reg),
                    IARG_MEMORYOP_EA, dst_memopIdx,
                    IARG_CONST_CONTEXT,
                    IARG_END);
}

void
ins_cmpxchg8b (INS ins)
{
    DLOG2 (INS_Address (ins), "\tins_cmpxchg8b\n");
    INS_InsertCall (ins, IPOINT_BEFORE,
                    (AFUNPTR) tag_cmpxchg8b,
                    IARG_INST_PTR,
                    IARG_REG_VALUE, REG_EAX,
                    IARG_REG_VALUE, REG_EDX,
                    IARG_MEMORYOP_EA, 0,
                    IARG_CONST_CONTEXT,
                    IARG_END);
}

void
ins_cmpxchg16b (INS ins)
{
    DLOG2 (INS_Address (ins), "\tins_cmpxchg16b\n");
    INS_InsertCall (ins, IPOINT_BEFORE,
                    (AFUNPTR) tag_cmpxchg16b,
                    IARG_INST_PTR,
                    IARG_REG_VALUE, REG_RAX,
                    IARG_REG_VALUE, REG_RBX,
                    IARG_REG_VALUE, REG_RCX,
                    IARG_REG_VALUE, REG_RDX,
                    IARG_MEMORYOP_EA, 0,
                    IARG_CONST_CONTEXT,
                    IARG_END);
}

bool
ins_clear_if_possible (INS ins, UINT32 src_idx, UINT32 dst_idx, std::map<int, int> &memop_idx)
{
    DLOG2 (INS_Address (ins),
           "\tins_clear_if_possible: %d -> %d\n", src_idx, dst_idx);
    if (INS_OperandIsImmediate (ins, src_idx) // src が定数
        || (INS_OperandIsReg (ins, src_idx) // src がセグメントレジスタ
            && REG_is_seg(INS_OperandReg(ins, src_idx)))
        || (INS_OperandSize (ins, dst_idx) < 8) // dst サイズが 8バイト未満
        || (INS_OperandSize (ins, src_idx) < 8) // src サイズが 8バイト未満
        ) {
        if (INS_OperandIsReg (ins, dst_idx)) {
            ins_clear_reg_width (ins, INS_OperandReg (ins, dst_idx));
        } else if (INS_OperandIsMemory (ins, dst_idx)) {
            ins_clear_mem_region (ins, memop_idx [dst_idx]);
        } else {
            assert (0);
        }
        DLOG ("\tins_clear_if_possible: true\n");
        return true; // 消去した
    }
    DLOG ("\tins_clear_if_possible: false\n");
    return false;
}

// オペランドがメモリかレジスタかをここで抽象化．ただし，1to1のみ
void
ins_copy (INS ins, UINT32 src_idx, UINT32 dst_idx, std::map<int, int> &memop_idx, bool do_strong_update)
{
    DLOG2 (INS_Address (ins), "\tins_copy: %d -> %d\n", src_idx, dst_idx);
    assert (INS_OperandSize (ins, src_idx) >= 8);
    assert (INS_OperandSize (ins, dst_idx) >= 8);

    if (INS_OperandIsReg (ins, src_idx)) {
        if (INS_OperandIsReg (ins, dst_idx)) {  // reg->reg
            ins_copy_reg2reg (ins,
                              INS_OperandReg (ins, src_idx),
                              INS_OperandReg (ins, dst_idx),
                              do_strong_update);
        } else if (INS_OperandIsMemory (ins, dst_idx)) { // reg->mem
            ins_copy_reg2mem (ins,
                              INS_OperandReg (ins, src_idx),
                              memop_idx [dst_idx],
                              do_strong_update);
        } else {
            assert (0);
        }
    } else if (INS_OperandIsMemory (ins, src_idx)) {
        if (INS_OperandIsReg (ins, dst_idx)) {  // mem->reg
            ins_copy_mem2reg (ins,
                              memop_idx [src_idx],
                              INS_OperandReg (ins, dst_idx),
                              do_strong_update);
        } else if (INS_OperandIsMemory (ins, dst_idx)) { // mem->mem
            ins_copy_mem2mem (ins,
                              memop_idx [src_idx],
                              memop_idx [dst_idx],
                              do_strong_update);
        } else {
            assert (0);
        }
    } else { 
        assert (0);
    }
}

void
ins_xchg (INS ins, UINT32 src_idx, UINT32 dst_idx, std::map<int, int> &memop_idx)
{
    DLOG2 (INS_Address (ins), "\tins_xchg: %d -> %d\n", src_idx, dst_idx);

    if (INS_OperandIsReg (ins, src_idx)) {
        if (INS_OperandIsReg (ins, dst_idx)) {  // reg->reg
            ins_copy_reg2reg (ins, INS_OperandReg (ins, src_idx), REG_NONE, true);
            ins_copy_reg2reg (ins, INS_OperandReg (ins, dst_idx), INS_OperandReg (ins, src_idx), true);
            ins_copy_reg2reg (ins, REG_NONE, INS_OperandReg (ins, dst_idx), true);
            ins_clear_reg (ins, REG_NONE, 0);
        } else if (INS_OperandIsMemory (ins, dst_idx)) { // reg->mem
            ins_copy_reg2reg (ins, INS_OperandReg (ins, src_idx), REG_NONE, true);
            ins_copy_mem2reg (ins, memop_idx [dst_idx], INS_OperandReg (ins, src_idx), true);
            ins_copy_reg2mem (ins, REG_NONE, memop_idx [dst_idx], true);
            ins_clear_reg (ins, REG_NONE, 0);
        } else {
            assert (0);
        }
    } else if (INS_OperandIsMemory (ins, src_idx)) {
        if (INS_OperandIsReg (ins, dst_idx)) {  // mem->reg
            ins_copy_mem2reg (ins, memop_idx [src_idx], REG_NONE, true);
            ins_copy_reg2mem (ins, INS_OperandReg (ins, dst_idx), memop_idx [src_idx], true);
            ins_copy_reg2reg (ins, REG_NONE, INS_OperandReg (ins, dst_idx), true);
            ins_clear_reg (ins, REG_NONE, 0);
        } else if (INS_OperandIsMemory (ins, dst_idx)) { // mem->mem
            assert (0);
        } else {
            assert (0);
        }
    } else { 
        assert (0);
    }
}

// _start など，main関数前に実行される関数を無視するため
bool
IsMainCalled (int do_set)
{
    static bool is_main_called = false;

    if (do_set) {
        is_main_called = true;
    }
    return is_main_called;
}

bool
IsMainExited (int do_set)
{
    static bool is_main_exited = false;

    if (do_set) {
        is_main_exited = true;
    }
    return is_main_exited;
}

#if 0
void
SysenterBefore (THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    size_t syscall_num = PIN_GetSyscallNumber (ctxt, std);
#if 0
    DLOG ("[syscall before] %ld\n", syscall_num);
#endif

    switch (syscall_num) {
    case 59: // execve
    case 322: // execveat
        DLOG ("execve called\n");
        // Pinツール内の変数をフラグにすると，execve後に値が戻ってしまう
        // このため環境変数を使う
        setenv (ENV_VAR_NAME, "1", 1);
        break;
    default:
        break;
    }
}
#endif

#ifdef UNDANGLE
VOID
Undangle_TraceEnd (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG ("Undangle_TraceEnd: %s\n", addr2loc (ip, 0));
    // dump_nullified_map ();
    for (auto p: nullified_map_traceend) {
        ADDRINT addr;
//        nullified_map_funcend.insert (p);
        PIN_SafeCopy ((VOID *)&addr, (VOID *)p.first, sizeof (ADDRINT));
        // fprintf (OUT_FP, "@pointer=%lx, addr=%lx\n", p.first, addr);
        if (is_nullified (addr)) {
            fprintf (OUT_FP, "TraceEnd: dangling pointer detected: %lx (-> %lx) @%s\n",
                     p.first, p.second.first, addr2loc (ip, 0));
            fprintf (OUT_FP, "pointee:\n");
            search_malloc_map (p.second.first);
            fprintf (OUT_FP, "mem_loc:\n");
            for (auto j: p.second.second) {
                char *mem_loc = addr2loc (j, rewind_depth);
                fprintf (OUT_FP, "%lx@%s, ", j, mem_loc);
            }
            fprintf (OUT_FP, "\n");

            if (BreakOnLeakDetected.Value ()) {
                PIN_ApplicationBreakpoint (ctxt, PIN_ThreadId (), TRUE, "dangling pointer detected");
            }
        }
    }
    nullified_map_traceend.clear ();
#if 0
    dump_malloc_map ();
#endif
}

VOID
Undangle_FuncEnd (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG ("Undangle_FuncEnd\n", addr2loc (ip, 0));
    // dump_nullified_map ();
    for (auto p: nullified_map_funcend) {
        ADDRINT addr;
        PIN_SafeCopy ((VOID *)&addr, (VOID *)p.first, sizeof (ADDRINT));
        // fprintf (OUT_FP, "@addr=%lx\n", addr);
        if (is_nullified (addr)) {
            fprintf (OUT_FP, "FuncEnd: dangling pointer detected: %lx (-> %lx) @%s\n",
                     p.first, p.second.first, addr2loc (ip, 0));
            fprintf (OUT_FP, "pointee:\n");
            search_malloc_map (p.second.first);
            fprintf (OUT_FP, "mem_loc:\n");
            for (auto j: p.second.second) {
                char *mem_loc = addr2loc (j, rewind_depth);
                fprintf (OUT_FP, "%lx@%s, ", j, mem_loc);
            }
            fprintf (OUT_FP, "\n");

            if (BreakOnLeakDetected.Value ()) {
                PIN_ApplicationBreakpoint (ctxt, PIN_ThreadId (), TRUE, "dangling pointer detected");
            }
        }
    }
    nullified_map_funcend.clear ();
#if 0
    dump_malloc_map ();
#endif
}
#endif

BOOL
FollowChild (CHILD_PROCESS cProcess, VOID* v)
{
    DLOG ("FollowChild called\n");
    setenv (ENV_VAR_NAME, "1", 1);
    return TRUE;
}

// いちいち命令の種類ごとにテイントポリシーを書くのではなく，
// 「メモリ読み書き」「レジスタ読み書き」などで一般化したい（できるのか）
VOID
Instruction1 (INS ins, VOID *v)
{
    auto ins_opcode = (xed_iclass_enum_t) INS_Opcode (ins);
    auto ins_category = INS_Category (ins);
    assert (XED_ICLASS_INVALID < ins_opcode && ins_opcode < XED_ICLASS_LAST);

#if defined (OUTPUT_LOG) && 0 // xxx
    DLOG2 ((ADDRINT) INS_Address (ins),
           "%s, %s: %s (mov %d, sub %d, nop %d, movsame %d, rep %d)\n",
           CATEGORY_StringShort (INS_Category (ins)).c_str (),
           INS_Mnemonic (ins).c_str (),
           INS_Disassemble (ins).c_str (),
           INS_IsMov (ins),
           INS_IsSub (ins),
           INS_IsNop (ins),
           INS_IsMovFullRegRegSame (ins),
           INS_HasRealRep (ins)
        );
#endif

    UINT32 memop_count = INS_MemoryOperandCount (ins);
    // operand-index から memory-operand-index へのマップ
    std::map<int, int> memop_idx;
    for (UINT32 i = 0; i < memop_count; i++) {
        int idx = INS_MemoryOperandIndexToOperandIndex (ins, i);
        DLOG ("\t#%d mem-operand: w=%d r=%d opidx=%d \n",
              i,
              INS_MemoryOperandIsWritten (ins, i),
              INS_MemoryOperandIsRead (ins, i),
              idx
            );
        memop_idx [idx] = i;
    }

#if defined (OUTPUT_LOG) && 0 // xxx
    for (UNUSED auto i: memop_idx) {
        DLOG ("\tidx=%d -> memop-idx=%d\n", i.first, i.second);
    }

    for (UINT i = 0; i < INS_OperandCount (ins); i++) {
        DLOG ("\t#%d operand size is %d\n", i, INS_OperandSize (ins, i));
        if (INS_OperandIsReg (ins, i)) {
            UNUSED REG reg = INS_OperandReg (ins, i);
            DLOG ("\t#%d operand is register (%s)\n",
                  i, REG_StringShort (reg).c_str ());
        }
        if (INS_OperandIsImmediate (ins, i)) {
            DLOG ("\t#%d operand is imm\n", i);
        }
        if (INS_OperandIsMemory (ins, i)) {
            DLOG ("\t#%d operand is memory\n", i);
        }
        if (INS_OperandIsAddressGenerator(ins, i)) {
            DLOG ("\t#%d operand is address generator\n", i);
        }
        if (INS_OperandIsSegmentReg (ins, i)) {
            DLOG ("\t#%d operand is segment reg\n", i);
        }
        if (INS_OperandIsBranchDisplacement(ins, i)) {
            DLOG ("\t#%d operand is branch displacement\n", i);
        }
        if (INS_OperandIsFixedMemop (ins, i)) {
            DLOG ("\t#%d operand is fixed-memop\n", i);
        }
        if (INS_OperandIsImplicit (ins, i)) {
            REG reg = INS_OperandReg (ins, i);
            std::string reg_name;
            if (reg != REG_INVALID ()) {
                reg_name = REG_StringShort (reg);
            }
            DLOG ("\t#%d operand is implicit (%s)\n", i, reg_name.c_str ());
        }
        {
            REG reg = INS_OperandMemoryIndexReg(ins, i);
            if (reg != REG_INVALID ()) {
                DLOG ("\t#%d oprand is index reg (%s)\n",
                      i, REG_StringShort (reg).c_str ());
            }
            reg = INS_OperandMemoryBaseReg(ins, i);
            if (reg != REG_INVALID ()) {
                DLOG ("\t#%d oprand is base reg (%s)\n",
                      i, REG_StringShort (reg).c_str ());
            }
        }
        DLOG ("\tr=%d, rw=%d, ro=%d, w=%d, wo=%d\n",
              INS_OperandRead (ins, i),
              INS_OperandReadAndWritten (ins, i),
              INS_OperandReadOnly (ins, i),
              INS_OperandWritten (ins, i),
              INS_OperandWrittenOnly (ins, i));

    }

    DLOG ("\tregw: ");
    for (UINT32 i = 0; i < INS_MaxNumWRegs (ins); i++) {
        DLOG_NOHEADER ("%s, ", REG_StringShort (INS_RegW (ins, i)).c_str ());
    }
    DLOG_NOHEADER ("\n");

    DLOG ("\tregr: ");
    for (UINT32 i = 0; i < INS_MaxNumRRegs (ins); i++) {
        DLOG_NOHEADER ("%s, ", REG_StringShort (INS_RegR (ins, i)).c_str ());
    }
    DLOG_NOHEADER ("\n");
#endif

    // ==========================================
    if (INS_IsNop (ins) || INS_IsMovFullRegRegSame (ins)) {
        return;
    }

    switch (ins_opcode) {
    case XED_ICLASS_MOV:
        if (ins_clear_if_possible (ins, 1, 0, memop_idx)) {
        } else {
            ins_copy (ins, 1, 0, memop_idx, true);
        }
        break;
    case XED_ICLASS_PUSH:
        if (ins_clear_if_possible (ins, 0, 2, memop_idx)) {
        } else {
            ins_copy (ins, 0, 2, memop_idx, true);
        }
        break;
    case XED_ICLASS_POP:
        if (ins_clear_if_possible (ins, 2, 0, memop_idx)) {
        } else {
            ins_copy (ins, 2, 0, memop_idx, true);
        }
        break;
    case XED_ICLASS_LEAVE:
        ins_copy (ins, 2, 3, memop_idx, true); // %rsp=%rbp
        ins_copy (ins, 0, 2, memop_idx, true); // pop %rbp
        break;
    case XED_ICLASS_XCHG:
    case XED_ICLASS_XADD_LOCK:
    case XED_ICLASS_XADD:
        if (ins_clear_if_possible (ins, 0, 1, memop_idx)) {
            ins_clear_if_possible (ins, 1, 0, memop_idx);
        } else {
            ins_xchg (ins, 0, 1, memop_idx);
        }
        break;
    case XED_ICLASS_CMPXCHG:
    case XED_ICLASS_CMPXCHG_LOCK:
        if (INS_OperandSize (ins, 1) < 8) {
            assert (INS_OperandSize (ins, 0) < 8);
            if (INS_OperandIsReg (ins, 0)) {
                ins_cmpxchg_reg2reg_clear (ins, INS_OperandReg (ins, 0));
            } else if (INS_OperandIsMemory (ins, 0)) {
                ins_cmpxchg_reg2mem_clear (ins, 0);
            } else {
                assert (0);
            }
        } else if (INS_OperandSize (ins, 1) == 8) {
            if (INS_OperandIsReg (ins, 0)) {
                ins_cmpxchg_reg2reg_copy (ins, INS_OperandReg (ins, 1),
                                          INS_OperandReg (ins, 0));
            } else if (INS_OperandIsMemory (ins, 0)) {
                ins_cmpxchg_reg2mem_copy (ins, INS_OperandReg (ins, 1), 0);
            } else {
                assert (0);
            }
        } else {
            assert (0);
        }
        break;
    case XED_ICLASS_CMPXCHG8B:
    case XED_ICLASS_CMPXCHG8B_LOCK:
        ins_cmpxchg8b (ins);
        break;
    case XED_ICLASS_CMPXCHG16B:
    case XED_ICLASS_CMPXCHG16B_LOCK:
        ins_cmpxchg16b (ins);
        break;

        // Conditional Move
//    case XED_ICLASS_CMOVA:
//    case XED_ICLASS_CMOVAE:
    case XED_ICLASS_CMOVB:
    case XED_ICLASS_CMOVBE:
//    case XED_ICLASS_CMOVC:
//    case XED_ICLASS_CMOVE:
//    case XED_ICLASS_CMOVGE:
    case XED_ICLASS_CMOVL:
    case XED_ICLASS_CMOVLE:
//    case XED_ICLASS_CMOVNA:
//    case XED_ICLASS_CMOVNAE:
    case XED_ICLASS_CMOVNB:
    case XED_ICLASS_CMOVNBE:
//    case XED_ICLASS_CMOVNC:
//    case XED_ICLASS_CMOVNE:
//    case XED_ICLASS_CMOVNG:
//    case XED_ICLASS_CMOVNGE:
    case XED_ICLASS_CMOVNL:
    case XED_ICLASS_CMOVNLE:
    case XED_ICLASS_CMOVNO:
    case XED_ICLASS_CMOVNP:
    case XED_ICLASS_CMOVNS:
    case XED_ICLASS_CMOVNZ:
    case XED_ICLASS_CMOVO:
    case XED_ICLASS_CMOVP:
//    case XED_ICLASS_CMOVPE:
//    case XED_ICLASS_CMOVPO:
    case XED_ICLASS_CMOVS:
    case XED_ICLASS_CMOVZ:
        if (ins_clear_if_possible (ins, 1, 0, memop_idx)) {
        } else {
            ins_copy (ins, 1, 0, memop_idx, true);
        }
        break;

        // String命令
//    case XED_ICLASS_REP_MOVSB: // これは使えない
    case XED_ICLASS_MOVSB:
    case XED_ICLASS_MOVSW:
    case XED_ICLASS_MOVSD:
    case XED_ICLASS_MOVSQ:
        if (INS_HasRealRep (ins)) {
            assert (INS_RepPrefix (ins));
            DLOG ("\trep_movs\n");
            INS_InsertIfCall (ins, IPOINT_BEFORE,
                              (AFUNPTR) return_arg, 
                              IARG_FIRST_REP_ITERATION,
                              IARG_END);
            INS_InsertThenCall (ins, IPOINT_BEFORE,
                                (AFUNPTR) tag_copy_rep_movs, 
                                IARG_INST_PTR,
                                IARG_UINT32, INS_OperandSize (ins, 0),
                                IARG_REG_VALUE, REG_RFLAGS,
                                IARG_REG_VALUE, REG_RCX,
                                IARG_MEMORYOP_EA, 1,
                                IARG_MEMORYOP_EA, 0,
                                IARG_CONST_CONTEXT,
                                IARG_END);
        } else {
            if (ins_clear_if_possible (ins, 2, 0, memop_idx)) {
            } else {
                ins_copy (ins, 2, 0, memop_idx, true);
            }
        }
        break;

    case XED_ICLASS_LODSB:
    case XED_ICLASS_LODSW:
    case XED_ICLASS_LODSD:
    case XED_ICLASS_LODSQ:
        if (INS_HasRealRep (ins)) {
            assert (INS_RepPrefix (ins));
            DLOG ("\trep_lods\n");
            INS_InsertIfCall (ins, IPOINT_BEFORE,
                              (AFUNPTR) return_arg, 
                              IARG_FIRST_REP_ITERATION,
                              IARG_END);
            INS_InsertThenCall (ins, IPOINT_BEFORE,
                                (AFUNPTR) tag_copy_rep_lods, 
                                IARG_UINT32, INS_OperandSize (ins, 0),
                                IARG_INST_PTR,
                                IARG_REG_VALUE, REG_RFLAGS,
                                IARG_REG_VALUE, REG_RCX,
                                IARG_MEMORYOP_EA, 0,
                                IARG_CONST_CONTEXT,
                                IARG_END);
        } else {
            if (ins_clear_if_possible (ins, 1, 0, memop_idx)) {
            } else {
                ins_copy (ins, 1, 0, memop_idx, true);
            }
        }
        break;
        
    case XED_ICLASS_STOSB:
    case XED_ICLASS_STOSW:
    case XED_ICLASS_STOSD:
    case XED_ICLASS_STOSQ:
        if (INS_HasRealRep (ins)) {
            assert (INS_RepPrefix (ins));
            DLOG ("\trep_stos: %d\n", INS_OperandSize (ins, 0));
            INS_InsertIfCall (ins, IPOINT_BEFORE,
                              (AFUNPTR) return_arg, 
                              IARG_FIRST_REP_ITERATION,
                              IARG_END);
            INS_InsertThenCall (ins, IPOINT_BEFORE,
                                (AFUNPTR) tag_copy_rep_stos, 
                                IARG_INST_PTR,
                                IARG_UINT32, INS_OperandSize (ins, 0),
                                IARG_REG_VALUE, REG_RFLAGS,
                                IARG_REG_VALUE, REG_RCX,
                                IARG_MEMORYOP_EA, 0,
                                IARG_CONST_CONTEXT,
                                IARG_END);
        } else {
            if (ins_clear_if_possible (ins, 2, 0, memop_idx)) {
            } else {
                ins_copy (ins, 2, 0, memop_idx, true);
            }
        }
        break;
        
    case XED_ICLASS_LEA:
        if (ins_clear_if_possible (ins, 1, 0, memop_idx)) {
        } else {
            REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
            if (base_reg != REG_RIP && base_reg != REG_INVALID ()) {
                ins_copy_reg2reg (ins, base_reg, INS_OperandReg (ins, 0), true);
            }
            REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
            if (index_reg != REG_INVALID ()) {
                ins_copy_reg2reg (ins, index_reg, INS_OperandReg (ins, 0), true);
            }
            // lea 8, %rax で，8は immediate にならないので必要
            if (base_reg == REG_INVALID () && index_reg == REG_INVALID ()) {
                ins_clear_reg (ins, INS_OperandReg (ins, 0), 0);
            }
        }
        break;

    case XED_ICLASS_ADD:
    case XED_ICLASS_ADD_LOCK:
    case XED_ICLASS_ADC:
    case XED_ICLASS_ADC_LOCK:
    case XED_ICLASS_ADCX:
//    case XED_ICLASS_ADCX_LOCK:
    case XED_ICLASS_AND:
    case XED_ICLASS_AND_LOCK:
    case XED_ICLASS_XOR:
    case XED_ICLASS_XOR_LOCK:
    case XED_ICLASS_OR:
    case XED_ICLASS_OR_LOCK:
        // op0 が8バイト長の場合，op0のテイントを消去してはいけない
        if ((INS_OperandSize (ins, 0) < 8)
            && ins_clear_if_possible (ins, 1, 0, memop_idx)) {
        } else if (!INS_OperandIsImmediate (ins, 1)) {
            ins_copy (ins, 1, 0, memop_idx, false);
        }
        break;

    case XED_ICLASS_SUB:
    case XED_ICLASS_SUB_LOCK:
    case XED_ICLASS_SBB:
    case XED_ICLASS_SBB_LOCK:
        // op0 が8バイト長の場合，op0のテイントを消去してはいけない
        if ((INS_OperandSize (ins, 0) < 8)
            && ins_clear_if_possible (ins, 1, 0, memop_idx)) {
        } else {
            // p = p - offset で，offset => p というテイント伝播は無い
            // ins_copy (ins, 1, 0, memop_idx, false);
        }
        break;

    case XED_ICLASS_BSWAP:
        if ((INS_OperandSize (ins, 0) < 8)
            && ins_clear_if_possible (ins, 0, 0, memop_idx)) {
        }
        // BSWAP r64 を2回やると元に戻るのでテイントを残す．
        break;

// MMX, SSE, AVX2 (but not AVX512)
// メモリアクセスは 8バイト境界とは限らない
    case XED_ICLASS_MOVQ:
    case XED_ICLASS_VMOVQ:
        if (INS_OperandIsReg (ins, 0)) {
            REG reg0 = INS_OperandReg (ins, 0);
            // destオペランドがxmmのとき，上位8バイトはクリアされる
            ins_clear_reg (ins, reg0, 1);
            if (ins_opcode == XED_ICLASS_VMOVQ || REG_is_xmm (reg0)) {
                // VMOVQ だと，ymm の上半分もクリア
                ins_clear_reg (ins, reg0, 2);
                ins_clear_reg (ins, reg0, 3);
            }
        }
        ins_copy (ins, 1, 0, memop_idx, true);
        break;

    case XED_ICLASS_MOVSS:
    case XED_ICLASS_VMOVSS:
        if (INS_OperandIsReg (ins, 0)) {
            REG reg0 = INS_OperandReg (ins, 0);
            assert (REG_is_xmm (reg0));
            if (INS_OperandIsReg (ins, 1)) { // reg -> reg
                REG reg1 = INS_OperandReg (ins, 1);
                assert (REG_is_xmm (reg1));
                ins_clear_reg (ins, reg0, 0);
                if (ins_opcode == XED_ICLASS_VMOVSS) {
                    ins_copy_reg2reg_nth (ins, reg1, 1, reg0, 1, true);
                    ins_clear_reg (ins, reg0, 2);
                    ins_clear_reg (ins, reg0, 3);
                } 
            } else {
                assert (INS_OperandIsMemory (ins, 1)); // mem -> reg
                if (ins_opcode == XED_ICLASS_VMOVSS) {
                    ins_clear_reg_full (ins, reg0);
                } else {
                    ins_clear_reg_width (ins, reg0);
                }
            }
        } else {
            assert (INS_OperandIsMemory (ins, 0)) ; // reg -> mem
            ins_clear_mem_region (ins, 0);
        } 
        break;

    case XED_ICLASS_MOVSD_XMM:
    case XED_ICLASS_VMOVSD:
        if (INS_OperandIsReg (ins, 0)) {
            REG reg0 = INS_OperandReg (ins, 0);
            assert (REG_is_xmm (reg0));
            if (INS_OperandIsReg (ins, 1)) { // reg -> reg
                REG reg1 = INS_OperandReg (ins, 1);
                assert (REG_is_xmm (reg1));
                if (ins_opcode == XED_ICLASS_VMOVSD) {
                    assert (INS_OperandIsReg (ins, 2));
                    REG reg2 = INS_OperandReg (ins, 2);
                    ins_copy_reg2reg_nth (ins, reg2, 0, reg0, 0, true);
                    ins_copy_reg2reg_nth (ins, reg1, 1, reg0, 1, true);
                } else {
                    assert (ins_opcode == XED_ICLASS_MOVSD_XMM);
                    ins_copy_reg2reg_nth (ins, reg1, 0, reg0, 0, true);
                }
            } else { // mem -> reg
                assert (INS_OperandIsMemory (ins, 1));
                ins_clear_reg (ins, reg0, 1);
                ins_copy (ins, 1, 0, memop_idx, true);
                if (ins_opcode == XED_ICLASS_VMOVSD) {
                    ins_clear_reg (ins, reg0, 2);
                    ins_clear_reg (ins, reg0, 3);
                }
            }
        } else { // reg -> mem
            assert (INS_OperandIsMemory (ins, 0)) ;
            ins_copy (ins, 1, 0, memop_idx, true);
        }
        break;
        
    case XED_ICLASS_MOVAPS:
    case XED_ICLASS_MOVUPS:
    case XED_ICLASS_MOVAPD:
    case XED_ICLASS_MOVUPD:
    case XED_ICLASS_MOVDQA:
    case XED_ICLASS_MOVDQU:
        if (INS_OperandIsReg (ins, 1)) {
            REG reg1 = INS_OperandReg (ins, 1);
            assert (REG_is_xmm (reg1) || REG_is_ymm (reg1));
            if (INS_OperandIsReg (ins, 0)) {  // reg->reg
                REG reg0 = INS_OperandReg (ins, 0);
                assert (REG_is_xmm (reg0) || REG_is_ymm (reg0));
                assert ((REG_is_xmm (reg0) && REG_is_xmm (reg1))
                         || (REG_is_ymm (reg0) && REG_is_ymm (reg1)));
                for (int i = 0; i < reg_width (reg0); i++) {
                    ins_copy_reg2reg_nth (ins, reg1, i, reg0, i, true);
                }
            } else if (INS_OperandIsMemory (ins, 0)) { // reg->mem
                for (int i = 0; i < reg_width (reg1); i++) {
                    ins_copy_reg2mem_nth (ins, reg1, i, 0, true);
                }
            } else {
                assert (0);
            }
        } else if (INS_OperandIsMemory (ins, 1)) {
            if (INS_OperandIsReg (ins, 0)) {  // mem->reg
                REG reg0 = INS_OperandReg (ins, 0);
                for (int i = 0; i < reg_width (reg0); i++) {
                    ins_copy_mem2reg_nth (ins, 0, reg0, i, true);
                }
            } else {
                assert (0);
            }
        } else { 
            assert (0);
        }
        break;

    case XED_ICLASS_VMOVAPS:
    case XED_ICLASS_VMOVUPS:
    case XED_ICLASS_VMOVAPD:
    case XED_ICLASS_VMOVUPD:
    case XED_ICLASS_VMOVDQA:
    case XED_ICLASS_VMOVDQU:
        if (INS_OperandIsReg (ins, 1)) {
            REG reg1 = INS_OperandReg (ins, 1);
            assert (REG_is_xmm (reg1) || REG_is_ymm (reg1));
            if (INS_OperandIsReg (ins, 0)) {  // reg->reg
                REG reg0 = INS_OperandReg (ins, 0);
                assert (REG_is_xmm (reg0) || REG_is_ymm (reg0));
                assert ((REG_is_xmm (reg0) && REG_is_xmm (reg1))
                         || (REG_is_ymm (reg0) && REG_is_ymm (reg1)));
                for (int i = 0; i < reg_width (reg0); i++) {
                    ins_copy_reg2reg_nth (ins, reg1, i, reg0, i, true);
                }
                if (REG_is_xmm (reg0)) {
                    ins_clear_reg (ins, reg0, 2);
                    ins_clear_reg (ins, reg0, 3);
                }
            } else if (INS_OperandIsMemory (ins, 0)) { // reg->mem
                for (int i = 0; i < reg_width (reg1); i++) {
                    ins_copy_reg2mem_nth (ins, reg1, i, 0, true);
                }
            } else {
                assert (0);
            }
        } else if (INS_OperandIsMemory (ins, 1)) {
            if (INS_OperandIsReg (ins, 0)) {  // mem->reg
                REG reg0 = INS_OperandReg (ins, 0);
                for (int i = 0; i < reg_width (reg0); i++) {
                    ins_copy_mem2reg_nth (ins, 0, reg0, i, true);
                }
                if (REG_is_xmm (reg0)) {
                    ins_clear_reg (ins, reg0, 2);
                    ins_clear_reg (ins, reg0, 3);
                }
            } else {
                assert (0);
            }
        } else { 
            assert (0);
        }
        break;

    case XED_ICLASS_ADDSS:
    case XED_ICLASS_VADDSS:
    case XED_ICLASS_SUBSS:
    case XED_ICLASS_VSUBSS:
    case XED_ICLASS_MULSS:
    case XED_ICLASS_VMULSS:
    case XED_ICLASS_DIVSS:
    case XED_ICLASS_VDIVSS:
        if (INS_OperandIsReg (ins, 0)) {
            REG reg0 = INS_OperandReg (ins, 0);
            assert (REG_is_xmm (reg0));
            if (INS_OperandIsReg (ins, 1)) { // reg -> reg
                REG reg1 = INS_OperandReg (ins, 1);
                assert (REG_is_xmm (reg1));
                ins_clear_reg (ins, reg0, 0);
                if (ins_category == XED_CATEGORY_AVX
                    || ins_category == XED_CATEGORY_AVX2) {
                    assert (ins_opcode == XED_ICLASS_VADDSS
                            || ins_opcode == XED_ICLASS_VSUBSS
                            || ins_opcode == XED_ICLASS_VMULSS
                            || ins_opcode == XED_ICLASS_VDIVSS);
                    ins_copy_reg2reg_nth (ins, reg1, 1, reg0, 1, true);
                    ins_clear_reg (ins, reg0, 2);
                    ins_clear_reg (ins, reg0, 3);
                } 
            } else {
                assert (INS_OperandIsMemory (ins, 1)); // mem -> reg
                ins_clear_reg (ins, reg0, 0);
            }
        } else {
            assert (0);
        } 
        break;

    case XED_ICLASS_ADDSD:
        ins_copy (ins, 1, 0, memop_idx, false);
        break;

    case XED_ICLASS_SUBSD:
        break;

    case XED_ICLASS_MULSD:
    case XED_ICLASS_DIVSD:
        ins_clear_reg (ins, INS_OperandReg (ins, 0), 0);
        break;

    case XED_ICLASS_VADDSD:
    case XED_ICLASS_VSUBSD:
    {
        assert (INS_OperandIsReg (ins, 0));
        assert (INS_OperandIsReg (ins, 1));
        REG reg0 = INS_OperandReg (ins, 0);
        REG reg1 = INS_OperandReg (ins, 1);
        assert (REG_is_xmm (reg0));
        assert (REG_is_xmm (reg1));
        ins_copy (ins, 1, 0, memop_idx, false);
        if (ins_opcode == XED_ICLASS_VADDSD) {
            ins_copy (ins, 2, 0, memop_idx, false);
        }
        ins_copy_reg2reg_nth (ins, reg1, 1, reg0, 1, true);
        ins_clear_reg (ins, reg0, 2);
        ins_clear_reg (ins, reg0, 3);
        break;
    }

    case XED_ICLASS_VMULSD:
    case XED_ICLASS_VDIVSD:
    {
        assert (INS_OperandIsReg (ins, 0));
        assert (INS_OperandIsReg (ins, 1));
        REG reg0 = INS_OperandReg (ins, 0);
        REG reg1 = INS_OperandReg (ins, 1);
        assert (REG_is_xmm (reg0));
        assert (REG_is_xmm (reg1));
        ins_clear_reg (ins, reg0, 0);
        ins_copy_reg2reg_nth (ins, reg1, 1, reg0, 1, true);
        ins_clear_reg (ins, reg0, 2);
        ins_clear_reg (ins, reg0, 3);
        break;
    }

#if 0
    case XED_ICLASS_MULSD:
    case XED_ICLASS_DIVSD:
        break;
#endif


    case XED_ICLASS_CVTSI2SS:
    case XED_ICLASS_CVTSS2SI:
    case XED_ICLASS_CVTSI2SD:
    case XED_ICLASS_CVTSD2SI:
    case XED_ICLASS_CVTSS2SD:
    case XED_ICLASS_CVTSD2SS:
    case XED_ICLASS_CVTTSS2SI:
    case XED_ICLASS_CVTTSD2SI:
    case XED_ICLASS_VCVTSS2SI:
    case XED_ICLASS_VCVTSD2SI:
    case XED_ICLASS_VCVTTSS2SI:
    case XED_ICLASS_VCVTTSD2SI:

    case XED_ICLASS_CVTPD2PS:
    case XED_ICLASS_CVTPS2DQ:
    case XED_ICLASS_CVTTPS2DQ:
    case XED_ICLASS_CVTPS2PI:
    case XED_ICLASS_CVTTPS2PI:
    case XED_ICLASS_CVTPD2PI:
    case XED_ICLASS_CVTTPD2PI:
        ins_clear_reg (ins, INS_OperandReg (ins, 0), 0);
        break;

    case XED_ICLASS_CVTPS2PD:
    case XED_ICLASS_CVTPD2DQ:
    case XED_ICLASS_CVTTPD2DQ:
    case XED_ICLASS_CVTPI2PD:
    case XED_ICLASS_CVTPI2PS:
    case XED_ICLASS_CVTDQ2PD:
        ins_clear_reg (ins, INS_OperandReg (ins, 0), 0);
        ins_clear_reg (ins, INS_OperandReg (ins, 0), 1);
        break;

    case XED_ICLASS_VCVTPS2DQ:
    case XED_ICLASS_VCVTTPS2DQ:
    case XED_ICLASS_VCVTDQ2PD:
    case XED_ICLASS_VCVTPD2DQ:
    case XED_ICLASS_VCVTTPD2DQ:
        ins_clear_reg (ins, INS_OperandReg (ins, 0), 0);
        ins_clear_reg (ins, INS_OperandReg (ins, 0), 1);
        ins_clear_reg (ins, INS_OperandReg (ins, 0), 2);
        ins_clear_reg (ins, INS_OperandReg (ins, 0), 3);
        break;

    case XED_ICLASS_VCVTSI2SS:
    case XED_ICLASS_VCVTSI2SD:
    case XED_ICLASS_VCVTSS2SD:
    case XED_ICLASS_VCVTSD2SS:
    {
        assert (INS_OperandIsReg (ins, 0));
        assert (INS_OperandIsReg (ins, 1));
        REG reg0 = INS_OperandReg (ins, 0);
        REG reg1 = INS_OperandReg (ins, 1);
        assert (REG_is_xmm (reg0));
        assert (REG_is_xmm (reg1));
        ins_clear_reg (ins, reg0, 0);
        ins_copy_reg2reg_nth (ins, reg1, 1, reg0, 1, true);
        ins_clear_reg (ins, reg0, 2);
        ins_clear_reg (ins, reg0, 3);
        break;
    } 
 
        
    // ===========================================================
    default:
    {
        char *loc = addr2loc (INS_Address (ins), 0);
        fprintf (OUT_FP, "default instrumentation performed: %s: %s @ %s\n",
                 INS_Mnemonic (ins).c_str (), INS_Disassemble (ins).c_str (),
                 loc);
    }

        // fall through

// MMX, SSE, AVX2 (but not AVX512)
    case XED_ICLASS_VMOVD:
    case XED_ICLASS_VPXOR:
    case XED_ICLASS_VXORPD:
    case XED_ICLASS_VXORPS:

        // AVX命令で，destレジスタがxmmの場合のymm上半分クリアへの対応
        for (UINT32 i = 0; i < INS_MaxNumWRegs (ins); i++) {
            REG reg = INS_RegW (ins, i);
            if (REG_is_xmm (reg)) {
                ins_clear_reg (ins, reg, 2);
                ins_clear_reg (ins, reg, 3);
            }
        }

    case XED_ICLASS_VCOMISS:
    case XED_ICLASS_COMISS:
    case XED_ICLASS_VUCOMISS:
    case XED_ICLASS_UCOMISS:
    case XED_ICLASS_VCOMISD:
    case XED_ICLASS_COMISD:
    case XED_ICLASS_VUCOMISD:
    case XED_ICLASS_UCOMISD:

    case XED_ICLASS_MOVD:
    case XED_ICLASS_PXOR:
    case XED_ICLASS_XORPD:
    case XED_ICLASS_XORPS:

    case XED_ICLASS_FILD:
    case XED_ICLASS_FLD:
    case XED_ICLASS_FIST:
    case XED_ICLASS_FISTP:
    case XED_ICLASS_FISTTP:
    case XED_ICLASS_FST:
    case XED_ICLASS_FSTP:
    case XED_ICLASS_FXCH:

#if 1
    case XED_ICLASS_FCOM:
    case XED_ICLASS_FCOMP:
    case XED_ICLASS_FCOMPP:
    case XED_ICLASS_FCOMI:
    case XED_ICLASS_FCOMIP:
    case XED_ICLASS_FUCOMI:
    case XED_ICLASS_FUCOMIP:
    case XED_ICLASS_FADD:
    case XED_ICLASS_FADDP:
    case XED_ICLASS_FIADD:
    case XED_ICLASS_FSUB:
    case XED_ICLASS_FSUBP:
    case XED_ICLASS_FISUB:
    case XED_ICLASS_FSUBR:
    case XED_ICLASS_FSUBRP:
    case XED_ICLASS_FISUBR:
    case XED_ICLASS_FMUL:
    case XED_ICLASS_FMULP:
    case XED_ICLASS_FIMUL:
    case XED_ICLASS_FDIV:
    case XED_ICLASS_FDIVP:
    case XED_ICLASS_FIDIV:
    case XED_ICLASS_FDIVR:
    case XED_ICLASS_FDIVRP:
    case XED_ICLASS_FIDIVR:
#endif

        // fall through
    case XED_ICLASS_JMP:
    case XED_ICLASS_JZ:
    case XED_ICLASS_JNZ:
    case XED_ICLASS_JB:
    case XED_ICLASS_JNB:
    case XED_ICLASS_JBE:
    case XED_ICLASS_JNBE:
    case XED_ICLASS_JL:
    case XED_ICLASS_JNL:
    case XED_ICLASS_JLE:
    case XED_ICLASS_JNLE:
    case XED_ICLASS_JS:
    case XED_ICLASS_JNS:
    case XED_ICLASS_JP:
    case XED_ICLASS_JNP:
    case XED_ICLASS_JO:
    case XED_ICLASS_JNO:
    case XED_ICLASS_RET_FAR:
    case XED_ICLASS_RET_NEAR:
    case XED_ICLASS_CALL_FAR:
    case XED_ICLASS_CALL_NEAR:
    case XED_ICLASS_RCL:
    case XED_ICLASS_RCR:
    case XED_ICLASS_ROL:
    case XED_ICLASS_ROR:
    case XED_ICLASS_SHL:
    case XED_ICLASS_SAR:
    case XED_ICLASS_SHR:
    case XED_ICLASS_SHLD:
    case XED_ICLASS_SHRD:
    case XED_ICLASS_NEG:
    case XED_ICLASS_NOT:
    case XED_ICLASS_HLT:
    case XED_ICLASS_CMP:
    case XED_ICLASS_TEST:
    case XED_ICLASS_SETB:
    case XED_ICLASS_SETBE:
    case XED_ICLASS_SETL:
    case XED_ICLASS_SETLE:
    case XED_ICLASS_SETNB:
    case XED_ICLASS_SETNBE:
    case XED_ICLASS_SETNL:
    case XED_ICLASS_SETNLE:
    case XED_ICLASS_SETNO:
    case XED_ICLASS_SETNP:
    case XED_ICLASS_SETNS:
    case XED_ICLASS_SETNZ:
    case XED_ICLASS_SETO:
    case XED_ICLASS_SETP:
    case XED_ICLASS_SETS:
    case XED_ICLASS_SETZ:
    case XED_ICLASS_MUL:
    case XED_ICLASS_IMUL:
    case XED_ICLASS_DIV:
    case XED_ICLASS_IDIV:

    case XED_ICLASS_MOVZX:
    case XED_ICLASS_MOVSX:
    case XED_ICLASS_MOVSXD:

    case XED_ICLASS_CMPSB:
    case XED_ICLASS_CMPSW:
    case XED_ICLASS_CMPSD:
    case XED_ICLASS_CMPSQ:
    case XED_ICLASS_RDTSC:
    case XED_ICLASS_RDTSCP:
    case XED_ICLASS_SYSCALL:

    case XED_ICLASS_BT:
    case XED_ICLASS_BSF:
    case XED_ICLASS_BSR:
    case XED_ICLASS_BTC:
    case XED_ICLASS_BTC_LOCK:
    case XED_ICLASS_BTS:
    case XED_ICLASS_BTS_LOCK:
    case XED_ICLASS_BTR:
    case XED_ICLASS_BTR_LOCK:

    case XED_ICLASS_POPCNT:
    case XED_ICLASS_TZCNT:
    case XED_ICLASS_LZCNT:

    case XED_ICLASS_SCASB:
    case XED_ICLASS_SCASW:
    case XED_ICLASS_SCASD:
    case XED_ICLASS_SCASQ:

    case XED_ICLASS_CBW:
    case XED_ICLASS_CWDE:
    case XED_ICLASS_CDQE:
    case XED_ICLASS_CWD:
    case XED_ICLASS_CDQ:
    case XED_ICLASS_CQO:
    case XED_ICLASS_DEC:
    case XED_ICLASS_DEC_LOCK:
    case XED_ICLASS_INC:
    case XED_ICLASS_INC_LOCK:

    case XED_ICLASS_SFENCE:
    case XED_ICLASS_LFENCE:
    case XED_ICLASS_MFENCE:

    case XED_ICLASS_UD2:
    case XED_ICLASS_XBEGIN:
    case XED_ICLASS_XEND:
    case XED_ICLASS_XABORT:
    case XED_ICLASS_CLD:
    case XED_ICLASS_FWAIT:
    case XED_ICLASS_LSL:
    case XED_ICLASS_RDPID:
    case XED_ICLASS_RDPKRU:
    case XED_ICLASS_WRPKRU:
    case XED_ICLASS_CPUID:
    case XED_ICLASS_FCHS:
    case XED_ICLASS_FLD1:
    case XED_ICLASS_FLDZ:
    case XED_ICLASS_FRNDINT:

    case XED_ICLASS_FLDCW:
//    case XED_ICLASS_FSTCW:
    case XED_ICLASS_FNSTCW:
    
#if 0
ADDSS
ADDSD
ADDPS
ADDPD
SUBSS
SUBSD
SUBPS
SUBPD
#endif

        // ここで，書き込まれるレジスタとメモリは単にテイントを消去する
        for (UINT32 i = 0; i < memop_count; i++) {
            if (INS_MemoryOperandIsWritten (ins, i)) {
                DLOG ("\t#%d-memop will be cleared\n", i);
                ins_clear_mem_region (ins, i);
            }
        }
      
        for (UINT32 i = 0; i < INS_MaxNumWRegs (ins); i++) {
            REG reg = INS_RegW (ins, i);
            if (reg_is_general_purpose (reg)) {
                reg = REG_FullRegName (reg);
                // xmm0 はフルにすると ymm0 になっちゃう．xmm0のままで
            }
            if (reg == REG_RFLAGS || reg == REG_RIP || reg == REG_RSP) {
                // %rflags, %rip, %rsp はテイントクリアしない．テイントがついているはずがないから
                continue;
            }
            DLOG_NOHEADER ("\t%s will be cleared\n", REG_StringShort (INS_RegW (ins, i)).c_str ());
            if (REG_is_st (reg)) {
                ins_clear_mmreg (ins, reg - REG_ST0);
            } else {
                ins_clear_reg_width (ins, reg);
            }
        }
        break;
    }
}

// call命令に対する計装 (BeforeFuncCall, AfterFuncReturn)
VOID
Instruction2 (INS ins, VOID *v)
{
    if (!INS_IsCall (ins)) return;

#ifdef OUTPUT_LOG
    DLOG2 ((ADDRINT) INS_Address (ins),
           "%s, %s: %s\n", CATEGORY_StringShort (INS_Category (ins)).c_str (),
           INS_Mnemonic (ins).c_str (), INS_Disassemble (ins).c_str ());
#endif
    INS ins_next = INS_Next (ins);
    ADDRINT next_addr = INS_NextAddress (ins);
    if (ins_next == INS_Invalid ()) {
        // callq  4740 <abort@plt> のみのエントリとかでこのパターンになる
        DLOG ("invalid next instruction: %s, %lx, %lx\n",
              INS_Mnemonic (ins).c_str (), INS_Address (ins), next_addr);
    } else if (next_addr != INS_Address (ins_next)) {
        DLOG ("next address mismatch: %s, %lx, %lx\n",
              INS_Mnemonic (ins_next).c_str (),
              INS_Address (ins_next), next_addr);
    } else {
        DLOG ("BeforeFuncCall instrumented %s@%lx\n",
              INS_Mnemonic (ins).c_str (), INS_Address (ins));
        INS_InsertCall (ins,
                        IPOINT_BEFORE,
                        (AFUNPTR) BeforeFuncCall,
                        IARG_INST_PTR,
                        IARG_CONTEXT,
                        IARG_BRANCH_TARGET_ADDR,
                        IARG_ADDRINT, INS_Address (ins),
                        IARG_ADDRINT, next_addr,
                        IARG_CALL_ORDER, CALL_ORDER_LAST - 10,
                        IARG_END);
        if (next_addr != 0 && INS_Valid (ins_next)) {
#ifdef OUTPUT_LOG
            DLOG ("AfterFuncReturn instrumented %s@%lx, %d\n",
                  INS_Mnemonic (ins).c_str (), next_addr,
                  INS_Valid (ins_next));
#endif
                INS_InsertCall (ins_next,
                                IPOINT_BEFORE,
                                (AFUNPTR) AfterFuncReturn,
                                IARG_INST_PTR,
                                IARG_CONTEXT,
                                IARG_CALL_ORDER, CALL_ORDER_FIRST + 10,
                                IARG_END);
        }
    }
}

// メモリとレジスタの読み書きをフックする計装
// TraceSpecificHeapObjectモードのみ
VOID
Instruction3 (INS ins, VOID *v)
{
    // メモリアクセス (read/write両方)がある命令を全て計装
    UINT32 memop_count = INS_MemoryOperandCount (ins);
    const char *func_name = strdup (RTN_Name (INS_Rtn (ins)).c_str ());
    const char *disasm = strdup (INS_Disassemble (ins).c_str ());

    // メモリアクセスを監視
    for (UINT32 i = 0; i < memop_count; i++) {
        INS_InsertPredicatedCall (ins,
                                  IPOINT_BEFORE,
                                  (AFUNPTR) MemoryAccessBefore,
                                  IARG_CONST_CONTEXT,
                                  IARG_INST_PTR,
                                  IARG_UINT32, i,
                                  IARG_MEMORYOP_EA, i,
                                  IARG_MEMORYOP_SIZE, i,
                                  IARG_PTR, func_name,
                                  IARG_PTR, disasm,
                                  IARG_BOOL, INS_MemoryOperandIsWritten (ins, i),
                                  IARG_END);

        if (INS_MemoryOperandIsWritten (ins, i)
            && INS_IsValidForIpointAfter (ins)) {
            INS_InsertPredicatedCall (ins,
                                      IPOINT_AFTER,
                                      (AFUNPTR) MemoryAccessAfter,
                                      IARG_CONST_CONTEXT,
                                      IARG_INST_PTR,
                                      IARG_UINT32, i,
                                      IARG_MEMORYOP_SIZE, i,
                                      IARG_PTR, func_name,
                                      IARG_PTR, disasm,
                                      IARG_END);
        }
    }

    // レジスタ読み込みを監視
    for (UINT32 i = 0; i < INS_MaxNumRRegs (ins); i++) {
        REG reg = INS_RegR (ins, i);
        UINT32 size = REG_Size (reg);

        INS_InsertPredicatedCall (ins,
                                  IPOINT_BEFORE,
                                  (AFUNPTR) RegisterAccessBefore,
                                  IARG_CONST_CONTEXT,
                                  IARG_INST_PTR,
                                  IARG_UINT32, i,
                                  IARG_REG_CONST_REFERENCE, reg,
                                  IARG_UINT32, size,
                                  IARG_PTR, func_name,
                                  IARG_PTR, disasm,
                                  IARG_BOOL, false,
                                  IARG_END);
    }

    // レジスタ書き込みを監視
    for (UINT32 i = 0; i < INS_MaxNumWRegs (ins); i++) {
        REG reg = INS_RegW (ins, i);
        UINT32 size = REG_Size (reg);

        INS_InsertPredicatedCall (ins,
                                  IPOINT_BEFORE,
                                  (AFUNPTR) RegisterAccessBefore,
                                  IARG_CONST_CONTEXT,
                                  IARG_INST_PTR,
                                  IARG_UINT32, i,
                                  IARG_REG_CONST_REFERENCE, reg,
                                  IARG_UINT32, size,
                                  IARG_PTR, func_name,
                                  IARG_PTR, disasm,
                                  IARG_BOOL, true,
                                  IARG_END);

        if (INS_IsValidForIpointAfter (ins)) {
            INS_InsertPredicatedCall (ins,
                                      IPOINT_AFTER,
                                      (AFUNPTR) RegisterAccessAfter,
                                      IARG_CONST_CONTEXT,
                                      IARG_INST_PTR,
                                      IARG_UINT32, i,
                                      IARG_REG_CONST_REFERENCE, reg,
                                      IARG_UINT32, size,
                                      IARG_PTR, func_name,
                                      IARG_PTR, disasm,
                                      IARG_END);
        }
    }
}

#if 0
VOID
Instruction4 (INS ins, VOID *v)
{
    assert (INS_IsValidForIpointAfter (ins));

    INS_InsertCall (ins,
                    IPOINT_BEFORE,
                    (AFUNPTR) RSPBefore,
                    IARG_INST_PTR,
                    IARG_REG_VALUE, REG_RSP,
                    IARG_END);

    INS_InsertCall (ins,
                    IPOINT_AFTER,
                    (AFUNPTR) RSPAfter,
                    IARG_INST_PTR,
                    IARG_REG_VALUE, REG_RSP,
                    IARG_END);
}
#endif

VOID
Image (IMG img, VOID *v)
{
    if (!IMG_Valid (img)) return;
    auto &img_name = IMG_Name (img);
    const char *img_cname = strip_dir (img_name.c_str ());
#ifdef OUTPUT_LOG
    DLOG ("image name: %s, %d\n", img_cname, IMG_IsMainExecutable (img));
#endif

    // 計装は a.out と libhook.so のみにする．
    // extra_images にも計装するように変更
    if (!strcmp (img_cname, "hook.so")
        || !strcmp (img_cname, "libhook.so")
        || IMG_IsMainExecutable (img)) {
        goto Image_OK;
    }
    for (auto &i: extra_images) {
//        fprintf (OUT_FP, "@@ i=%s, img_name=%s\n", i.c_str (), img_cname);
        if (!strcmp (i.c_str (), img_cname)) {
            goto Image_OK;
        }
    }

    fprintf (OUT_FP, "\timage %s inst. skipped\n", img_cname);
    return;

Image_OK:
    // env から execve が呼ばれるまでは計装をスキップする
    char *env_val = getenv (ENV_VAR_NAME);
    DLOG ("env_val = %s\n", env_val);
    if (!UseGCCWrapper.Value () && env_val == NULL) {
        DLOG ("\timage inst. skipped\n");
        return;
    }


// ========= libhook.so は wrap関数を計装するが，中身は計装しない
// CONTEXT ではなく，特定のレジスタ値だけを渡した方が早い？
#define INSTRUMENT_HELPER1(name) \
        RTN name##Rtn = RTN_FindByName (img, "__wrap_" #name); \
        if (RTN_Valid (name##Rtn)) {  \
            DLOG ("__wrap_" #name " found in %s\n", img_cname); \
            RTN_Open (name##Rtn); \
            RTN_InsertCall (name##Rtn, IPOINT_BEFORE, \
                            (AFUNPTR) name##_pre_hook, \
                            IARG_INST_PTR, IARG_CONST_CONTEXT, \
                            IARG_RETURN_IP, \
                            IARG_CALL_ORDER, CALL_ORDER_LAST, \
                            IARG_END); \
            RTN_InsertCall (name##Rtn, IPOINT_AFTER, \
                            (AFUNPTR) name##_post_hook, \
                            IARG_INST_PTR, IARG_CONST_CONTEXT, \
                            IARG_CALL_ORDER, CALL_ORDER_FIRST, \
                            IARG_END); \
            RTN_Close (name##Rtn); \
        }

#define INSTRUMENT_HELPER2(name) \
        RTN name##Rtn = RTN_FindByName (img, #name); \
        if (RTN_Valid (name##Rtn)) {  \
            DLOG (#name " found in %s\n", img_cname); \
            RTN_Open (name##Rtn); \
            RTN_InsertCall (name##Rtn, IPOINT_BEFORE, \
                            (AFUNPTR) name##_pre_hook, \
                            IARG_INST_PTR, IARG_CONST_CONTEXT, \
                            IARG_RETURN_IP, IARG_END); \
            RTN_InsertCall (name##Rtn, IPOINT_AFTER, \
                            (AFUNPTR) name##_post_hook, \
                            IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_END); \
            RTN_Close (name##Rtn); \
        }
    
    // libc.so.6 とかの malloc はフックしたくない．libhook.so中のものだけフック．
    if (UseGCCWrapper.Value () && !strcmp (img_cname, "libhook.so")) {
        INSTRUMENT_HELPER1 (malloc);
        INSTRUMENT_HELPER1 (free);
        INSTRUMENT_HELPER1 (calloc);
        INSTRUMENT_HELPER1 (posix_memalign);
        INSTRUMENT_HELPER1 (realloc);
#if 0
        INSTRUMENT_HELPER (reallocarray);
#endif
        INSTRUMENT_HELPER1 (strdup);
        INSTRUMENT_HELPER1 (strndup);
        INSTRUMENT_HELPER1 (wcsdup);
        INSTRUMENT_HELPER1 (asprintf);
        INSTRUMENT_HELPER1 (memcpy);
        INSTRUMENT_HELPER1 (mempcpy);
        INSTRUMENT_HELPER1 (memmove);
        INSTRUMENT_HELPER1 (memset);
        INSTRUMENT_HELPER1 (strcpy);
        INSTRUMENT_HELPER1 (strncpy);
        INSTRUMENT_HELPER1 (_Znwm);
        INSTRUMENT_HELPER1 (_Znam);
        INSTRUMENT_HELPER1 (_ZdlPv);
        INSTRUMENT_HELPER1 (_ZdaPv);
        INSTRUMENT_HELPER1 (_ZdaPvm);
        INSTRUMENT_HELPER1 (_ZdlPvm);
        INSTRUMENT_HELPER1 (_ZnamRKSt9nothrow_t);
        INSTRUMENT_HELPER1 (_ZnwmRKSt9nothrow_t);
        INSTRUMENT_HELPER1 (_ZnwmSt11align_val_t);
        INSTRUMENT_HELPER1 (_ZnwmSt11align_val_tRKSt9nothrow_t);
        INSTRUMENT_HELPER1 (_ZnamSt11align_val_t);
        INSTRUMENT_HELPER1 (_ZnamSt11align_val_tRKSt9nothrow_t);
        INSTRUMENT_HELPER1 (_ZdlPvmSt11align_val_t);
        INSTRUMENT_HELPER1 (_ZdlPvRKSt9nothrow_t);
        INSTRUMENT_HELPER1 (_ZdlPvSt11align_val_t);
        INSTRUMENT_HELPER1 (_ZdlPvSt11align_val_tRKSt9nothrow_t);
        INSTRUMENT_HELPER1 (_ZdaPvmSt11align_val_t);
        INSTRUMENT_HELPER1 (_ZdaPvRKSt9nothrow_t);
        INSTRUMENT_HELPER1 (_ZdaPvSt11align_val_t);
        INSTRUMENT_HELPER1 (_ZdaPvSt11align_val_tRKSt9nothrow_t);
        return;
    } else if (!strcmp (img_cname, "hook.so")) {
        INSTRUMENT_HELPER2 (malloc);
        INSTRUMENT_HELPER2 (free);
        INSTRUMENT_HELPER2 (calloc);
        INSTRUMENT_HELPER2 (realloc);
#if 0
        INSTRUMENT_HELPER2 (reallocarray);
#endif
        // 追加不要
        return;
    }
// =========

    // libhook.so 以外に命令レベルの計装
    if (IMG_IsMainExecutable (img)) {
        aout_name = strdup (img_cname);
        DLOG ("aout_name = %s\n", aout_name);
    }

    if (TraceSpecificHeapObject.Value ()) {
        for (SEC sec = IMG_SecHead (img); SEC_Valid (sec); sec = SEC_Next (sec)) {
            for (RTN rtn = SEC_RtnHead (sec); RTN_Valid (rtn); rtn = RTN_Next (rtn)) {
                RTN_Open (rtn);
                for (INS ins = RTN_InsHead (rtn); INS_Valid (ins); ins = INS_Next (ins)) {
                    Instruction3 (ins, 0);
                }
                RTN_Close (rtn);
            }
        }
        return;
    }

    for (SEC sec = IMG_SecHead (img); SEC_Valid (sec); sec = SEC_Next (sec)) {
        for (RTN rtn = SEC_RtnHead (sec); RTN_Valid (rtn); rtn = RTN_Next (rtn)) {
            RTN_Open (rtn);
            DLOG ("func_name: %s\n", RTN_Name (rtn).c_str ());

#ifdef UNDANGLE 
            assert (strcmp (img_cname, "libhook.so"));
            RTN_InsertCall (rtn,
                            IPOINT_AFTER,
                            (AFUNPTR) Undangle_FuncEnd,
                            IARG_INST_PTR,
                            IARG_CONST_CONTEXT,
                            IARG_END);
#endif

            for (INS ins = RTN_InsHead (rtn); INS_Valid (ins); ins = INS_Next (ins)) {
                Instruction1 (ins, 0);
                Instruction2 (ins, 0);
#if 0
                if (INS_RegWContain (ins, REG_RSP)) {
                    // Instruction4 (ins, 0);
                }
#endif
            }
            RTN_Close (rtn);
        }
    }
    fprintf (OUT_FP, "\timage %s inst. done\n", img_cname);


    // main関数開始前後のフック
    if (IMG_IsMainExecutable (img)) {
        RTN mainRtn = RTN_FindByName (img, "main");
        if (RTN_Valid (mainRtn)) {
            RTN_Open (mainRtn);
            RTN_InsertCall (mainRtn,
                            IPOINT_BEFORE,
                            (AFUNPTR) MainBefore,
                            IARG_CONST_CONTEXT,
                            IARG_END);
            RTN_InsertCall (mainRtn,
                            IPOINT_AFTER,
                            (AFUNPTR) MainAfter,
                            IARG_CONST_CONTEXT,
                            IARG_END);
            RTN_Close (mainRtn);
        }
    }
}

VOID
UnloadImage (IMG img, VOID *v)
{
    DLOG ("Image unloaded: %s\n", IMG_Name (img).c_str ());
}

#ifdef UNDANGLE
VOID
Trace (TRACE trace, VOID *v)
{
    IMG img = IMG_FindByAddress (TRACE_Address (trace));
    if (!IMG_Valid (img)) {
        return;
    }
    auto &img_name = IMG_Name (img);
    const char *img_cname = strip_dir (img_name.c_str ());

    if (!strcmp (img_cname, "libhook.so")) { // libhook.so には計装しない
        DLOG ("libhook.so excluded\n");
        return;
    }

    if (IMG_IsMainExecutable (img)) {
            goto Image_OK;
    }

    for (auto &i: extra_images) {
//        fprintf (OUT_FP, "@@ i=%s, img_name=%s\n", i.c_str (), img_cname);
        if (!strcmp (i.c_str (), img_cname)) {
            goto Image_OK;
        }
    }

    DLOG ("\tTrace: image %s inst. skipped\n", img_cname);
    return;

Image_OK:
    
    TRACE_InsertCall (trace, IPOINT_TAKEN_BRANCH,
                      (AFUNPTR) Undangle_TraceEnd,
                      IARG_INST_PTR,
                      IARG_CONST_CONTEXT,
                      IARG_END);

    if (TRACE_HasFallThrough (trace)) {
        TRACE_InsertCall (trace, IPOINT_AFTER,
                          (AFUNPTR) Undangle_TraceEnd,
                          IARG_INST_PTR,
                          IARG_CONST_CONTEXT,
                          IARG_END);
    }
}
#endif

/* 初期化・終了化関数　=================================================== */
VOID
Init (VOID *v)
{
    DLOG ("Init ==============\n");
    rewind_depth = RewindDepth.Value ();
    DLOG ("rewind_depth = %d\n", rewind_depth);
}

VOID
Fini (INT32 code, VOID *v)
{
    DLOG ("Fini ====================\n");

    if (!IsMainExited (false)) {
    if (MarkSweepOnMainExited.Value ()) {
        mark_sweep ();
    }

#ifdef CALL_STAT
    dump_call_stat ();
    dump_malloc_map ();
#endif
    }
}

VOID
InitThread (THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    DLOG ("InitThread: tid=%d\n", tid);
    assert (tid == 0); // multi-thread apps are not supported

    saved_stack_bottom = PIN_GetContextReg (ctxt, REG_RSP);
    get_stack_limit ();
    DLOG ("saved_stack_bottom=%lx, stack_limit=%lx\n",
          saved_stack_bottom, stack_limit);
    get_data_limit ();
    DLOG ("data_start=%lx, data_end=%lx\n", data_start, data_end);
}
/* ライブラリ関数 caller側の処理　========================================== */
VOID
malloc_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    saved_arg1 =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG2 ((ADDRINT) ip, "malloc_pre_hook@%lx: size=%ld, ret_ip=%lx\n",
           ip, saved_arg1, ret_ip);
}

VOID
malloc_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    ADDRINT addr = PIN_GetContextReg (ctxt, REG_RAX);
    UINT32 size = (UINT32) saved_arg1;
    DLOG ("malloc_post_hook: addr=%lx, size=%d\n", addr, size);
    register_malloc_map (addr, size, saved_ret_ip, ctxt);
}

VOID
free_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT addr =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG ("free_pre_hook: ptr = %lx\n", addr);
    unregister_malloc_map (addr, ret_ip, ctxt);
}

VOID
free_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG ("free_post_hook:\n");
    tag_clear_caller_save_regs (ip, ctxt);
}

VOID
calloc_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    saved_arg1 =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_arg2 =  PIN_GetContextReg (ctxt, REG_RSI);
    saved_ret_ip = ret_ip;
    DLOG ("calloc_pre_hook: nmemb = %ld, size = %ld\n",
          saved_arg1, saved_arg2);
}
VOID
calloc_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    ADDRINT addr = PIN_GetContextReg (ctxt, REG_RAX);
    UINT32 nmemb = (UINT32) saved_arg1;
    UINT32 size = (UINT32) saved_arg2;
    DLOG ("calloc_post_hook: addr=%lx, nmemb=%d, size=%d\n",
          addr, nmemb, size);
    register_malloc_map (addr, nmemb * size, saved_ret_ip, ctxt);
}

VOID
posix_memalign_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    saved_arg1 =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_arg2 =  PIN_GetContextReg (ctxt, REG_RSI);
    saved_arg3 =  PIN_GetContextReg (ctxt, REG_RDX);
    saved_ret_ip = ret_ip;
    DLOG2 ((ADDRINT) ip, "posix_memalign_pre_hook@%lx: memptr=%lx, align=%ld, size=%ld, ret_ip=%lx\n",
           ip, saved_arg1, saved_arg2, saved_arg3, ret_ip);
    fprintf (OUT_FP, "posix_memalign_pre_hook@%lx: memptr=%lx, align=%ld, size=%ld, ret_ip=%lx\n",
             ip, saved_arg1, saved_arg2, saved_arg3, ret_ip);
}

VOID
posix_memalign_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    UNUSED UINT32 ret = PIN_GetContextReg (ctxt, REG_RAX);
    void **memptr = (void **) saved_arg1;
    UNUSED UINT32 align = (UINT32) saved_arg2;
    UINT32 size = (UINT32) saved_arg3;
    ADDRINT addr = (ADDRINT) *memptr;
    DLOG ("posix_memalign_post_hook: memaddr=%p, *memaddr=%lx, align=%d, size=%d, ret=%d\n", memptr, addr, align, size, ret);
    fprintf (OUT_FP, "posix_memalign_post_hook: memaddr=%p, *memaddr=%lx, align=%d, size=%d, ret=%d\n", memptr, addr, align, size, ret);
    register_malloc_map (addr, size, saved_ret_ip, ctxt);

    // register_malloc_map の作用で，rax -> addr となっている．
    // これを dest_mem -> addr に変更する
    ADDRINT dst_mem = (ADDRINT)memptr;
    tag_clear_reg (ip, REG_RAX, 0, ctxt, false);
    clear_reg_malloc_map (REG_RAX, 0, addr);
    tag_clear_mem (ip, dst_mem, ctxt, false);
    tag_mem_map [dst_mem] = {addr};
    if (is_onstack (dst_mem)) {
        tag_stack_map [dst_mem] = {addr};
    }
    set_mem_malloc_map (dst_mem, addr, ctxt);
    // dump_all_map ();
}

VOID
realloc_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    saved_arg1 =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_arg2 =  PIN_GetContextReg (ctxt, REG_RSI);
    saved_ret_ip = ret_ip;
    DLOG ("realloc_pre_hook: ptr = %lx, size = %ld\n",
          saved_arg1, saved_arg2);
}
VOID
realloc_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    ADDRINT addr = PIN_GetContextReg (ctxt, REG_RAX);
    ADDRINT old_addr =  saved_arg1;
    UINT32 size = (UINT32) saved_arg2;
    DLOG ("realloc_post_hook: old_addr=%lx, addr=%lx, size=%d\n",
          old_addr, addr, size);

    assert (IS_ALIGNED_TO_8BYTE (addr));
    assert (IS_ALIGNED_TO_8BYTE (old_addr));

    if (old_addr == 0) {
        // malloc と
        DLOG ("\tsame behavior as malloc since old_addr == NULL\n");
        register_malloc_map (addr, size, saved_ret_ip, ctxt);
    } else if (size == 0) {
        // free と同じ処理
        DLOG ("\tsame behavior as free since size == 0\n");
        unregister_malloc_map (old_addr, saved_ret_ip, ctxt);
        tag_clear_caller_save_regs (ip, ctxt);
    } else if (old_addr == addr) {
        // 同じアドレスでサイズだけ変更
        DLOG ("\tonly size is updated since old_addr == addr\n");
        register_malloc_map (addr, size, saved_ret_ip, ctxt); // RAXに色を付けるために必要
    } else {
        UINT32 old_size = 0;
        auto found2 = malloc_map.find (old_addr);
        assert (old_addr == 0 || found2 != malloc_map.end ());
        if (old_addr != 0) { // 1回目のrealloc呼び出しの第1引数がNULLなことあり
            old_size= found2->second.size;
        }
        DLOG ("\t%lx, %d <- %lx, %d\n", addr, size, old_addr, old_size);
        register_malloc_map (addr, size, saved_ret_ip, ctxt);
        tag_copy_mem2mem_region (ip, old_addr, addr, old_size, ctxt);
        unregister_malloc_map (old_addr, saved_ret_ip, ctxt);
    }
}

#if 0
// reallocarray は realloc を呼び出すので，realloc でフックする．
// フック関数が入れ子で呼ばれると，saved_ret_ip が壊れるのでコメントアウト．
VOID
reallocarray_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    saved_arg1 =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_arg2 =  PIN_GetContextReg (ctxt, REG_RSI);
    saved_arg3 =  PIN_GetContextReg (ctxt, REG_RDX);
    DLOG ("reallocarray_pre_hook: ptr=%lx, nmemb=%ld, size=%ld\n", saved_arg1, saved_arg2, saved_arg3);
}

VOID
reallocarray_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    ADDRINT addr2 = PIN_GetContextReg (ctxt, REG_RAX);
    ADDRINT addr =  saved_arg1;
    UINT32 nmemb = (UINT32) saved_arg2;
    UINT32 size = (UINT32) saved_arg3;
    DLOG ("reallocarray_post_hook: addr2=%lx, addr=%lx, nmemb=%d, size=%d\n", addr2, addr, nmemb, size);
}
#endif

VOID
strdup_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    saved_arg1 = strlen ((char *)PIN_GetContextReg (ctxt, REG_RDI)) + 1;
    saved_ret_ip = ret_ip;
    DLOG2 ((ADDRINT) ip, "strdup_pre_hook@%lx: size=%ld, ret_ip=%lx\n",
           ip, saved_arg1, ret_ip);
}

VOID
strdup_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    ADDRINT addr = PIN_GetContextReg (ctxt, REG_RAX);
    UINT32 size = (UINT32) saved_arg1;
    DLOG ("strdup_post_hook: addr=%lx, size=%d\n", addr, size);
    register_malloc_map (addr, size, saved_ret_ip, ctxt);
}

VOID
strndup_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    size_t n1 = strlen ((char *)PIN_GetContextReg (ctxt, REG_RDI)) + 1;
    size_t n2 = PIN_GetContextReg (ctxt, REG_RSI);
    saved_arg1 = (n1 < n2 ? n1 : n2);
    saved_ret_ip = ret_ip;
    DLOG2 ((ADDRINT) ip, "strndup_pre_hook@%lx: size=%ld, ret_ip=%lx\n",
           ip, saved_arg1, ret_ip);
}
VOID
strndup_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    ADDRINT addr = PIN_GetContextReg (ctxt, REG_RAX);
    UINT32 size = (UINT32) saved_arg1;
    DLOG ("strndup_post_hook: addr=%lx, size=%d\n", addr, size);
    register_malloc_map (addr, size, saved_ret_ip, ctxt);
}

VOID
wcsdup_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    wchar_t *wcs = (wchar_t *) PIN_GetContextReg (ctxt, REG_RDI);
    saved_arg1 = (wcslen (wcs) + 1) * sizeof (wchar_t);
    saved_ret_ip = ret_ip;
    DLOG2 ((ADDRINT) ip, "wcsdup_pre_hook@%lx: size=%ld, ret_ip=%lx\n",
           ip, saved_arg1, ret_ip);
}
VOID
wcsdup_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    ADDRINT addr = PIN_GetContextReg (ctxt, REG_RAX);
    UINT32 size = (UINT32) saved_arg1;
    DLOG ("wcsdup_post_hook: addr=%lx, size=%d\n", addr, size);
    register_malloc_map (addr, size, saved_ret_ip, ctxt);
}

VOID
asprintf_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    saved_arg1 = PIN_GetContextReg (ctxt, REG_RDI); 
    DLOG2 ((ADDRINT) ip, "asprintf_pre_hook: strp=%lx\n", saved_arg1);
}

VOID
asprintf_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    ADDRINT size  = PIN_GetContextReg (ctxt, REG_RAX);
    ADDRINT addr;
    PIN_SafeCopy ((VOID *)&addr, (VOID *)saved_arg1, sizeof (ADDRINT));
    DLOG2 ((ADDRINT) ip,
           "asprintf_post_hook: addr=%lx, size=%ld\n", addr, size);
    register_malloc_map (addr, size, saved_ret_ip, ctxt);
}

VOID
memcpy_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT dst  = PIN_GetContextReg (ctxt, REG_RDI);
    ADDRINT src  = PIN_GetContextReg (ctxt, REG_RSI);
    ADDRINT size = PIN_GetContextReg (ctxt, REG_RDX);
    saved_arg1 = dst;
    saved_arg2 = src;
    saved_arg3 = size;
    DLOG2 ((ADDRINT) ip, "memcpy_pre_hook: dst = %lx, src = %lx, size = %ld\n",
           dst, src, size);
    tag_copy_mem2mem_region (ip, src, dst, size, ctxt);
    tag_copy_reg2reg_nth (ip, REG_RDI, 0, REG_NONE, 0, true, ctxt);
}

VOID
memcpy_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG2 ((ADDRINT) ip,
           "memcpy_post_hook: dst = %lx, src = %lx, size = %ld\n",
           saved_arg1, saved_arg2, saved_arg3);
    tag_copy_reg2reg_nth (ip, REG_NONE, 0, REG_RAX, 0, true, ctxt);
    tag_clear_reg (ip, REG_NONE, 0, ctxt, false);
}


VOID
mempcpy_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT dst  = PIN_GetContextReg (ctxt, REG_RDI);
    ADDRINT src  = PIN_GetContextReg (ctxt, REG_RSI);
    ADDRINT size = PIN_GetContextReg (ctxt, REG_RDX);
    saved_arg1 = dst;
    saved_arg2 = src;
    saved_arg3 = size;
    DLOG2 ((ADDRINT) ip, "mempcpy_pre_hook: dst = %lx, src = %lx, size = %ld\n",
           dst, src, size);
    tag_copy_mem2mem_region (ip, src, dst, size, ctxt);
}

VOID
mempcpy_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG2 ((ADDRINT) ip,
           "mempcpy_post_hook: dst = %lx, src = %lx, size = %ld\n",
           saved_arg1, saved_arg2, saved_arg3);
}

VOID
memmove_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT dst  = PIN_GetContextReg (ctxt, REG_RDI);
    ADDRINT src  = PIN_GetContextReg (ctxt, REG_RSI);
    ADDRINT size = PIN_GetContextReg (ctxt, REG_RDX);
    saved_arg1 = dst;
    saved_arg2 = src;
    saved_arg3 = size;
    DLOG2 ((ADDRINT) ip, "memmove_pre_hook: dst = %lx, src = %lx, size = %ld\n",
           dst, src, size);
    tag_copy_mem2mem_region (ip, src, dst, size, ctxt);
    tag_copy_reg2reg_nth (ip, REG_RDI, 0, REG_NONE, 0, true, ctxt);
}

VOID
memmove_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG2 ((ADDRINT) ip,
           "memmove_post_hook: dst = %lx, src = %lx, size = %ld\n",
           saved_arg1, saved_arg2, saved_arg3);
    tag_copy_reg2reg_nth (ip, REG_NONE, 0, REG_RAX, 0, true, ctxt);
    tag_clear_reg (ip, REG_NONE, 0, ctxt, false);
}

VOID
memset_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT s  = PIN_GetContextReg (ctxt, REG_RDI);
    ADDRINT c  = PIN_GetContextReg (ctxt, REG_RSI);
    ADDRINT n = PIN_GetContextReg (ctxt, REG_RDX);
    saved_arg1 = s;
    saved_arg2 = c;
    saved_arg3 = n;
    DLOG2 ((ADDRINT) ip, "memset_pre_hook: s = %lx, c = %lx, size = %ld\n",
           s, c, n);
    tag_copy_reg2reg_nth (ip, REG_RDI, 0, REG_NONE, 0, true, ctxt);
    tag_clear_mem_region (ip, s, n, ctxt);
}

VOID
memset_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG2 ((ADDRINT) ip,
           "memset_post_hook: s = %lx, c = %lx, size = %ld\n",
           saved_arg1, saved_arg2, saved_arg3);
    tag_copy_reg2reg_nth (ip, REG_NONE, 0, REG_RAX, 0, true, ctxt);
    tag_clear_reg (ip, REG_NONE, 0, ctxt, false);
}

VOID
strcpy_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT dst  = PIN_GetContextReg (ctxt, REG_RDI);
    ADDRINT src  = PIN_GetContextReg (ctxt, REG_RSI);
    ADDRINT size = strlen ((const char *)src);
    saved_arg1 = dst;
    saved_arg2 = src;
    saved_arg3 = size;
    DLOG2 ((ADDRINT) ip, "strcpy_pre_hook: dst = %lx, src = %lx, size = %ld\n",
           dst, src, size);
    tag_copy_mem2mem_region (ip, src, dst, size, ctxt);
    tag_copy_reg2reg_nth (ip, REG_RDI, 0, REG_NONE, 0, true, ctxt);
}

VOID
strcpy_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG2 ((ADDRINT) ip, "strcpy_post_hook: dst = %lx\n", saved_arg1);
    tag_copy_reg2reg_nth (ip, REG_NONE, 0, REG_RAX, 0, true, ctxt);
    tag_clear_reg (ip, REG_NONE, 0, ctxt, false);
}

VOID
strncpy_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT dst  = PIN_GetContextReg (ctxt, REG_RDI);
    ADDRINT src  = PIN_GetContextReg (ctxt, REG_RSI);
    ADDRINT size = PIN_GetContextReg (ctxt, REG_RDX);
    saved_arg1 = dst;
    saved_arg2 = src;
    saved_arg3 = size;
    DLOG2 ((ADDRINT) ip, "strncpy_pre_hook: dst = %lx, src = %lx, size = %ld\n",
           dst, src, size);
    tag_copy_mem2mem_region (ip, src, dst, size, ctxt);
    tag_copy_reg2reg_nth (ip, REG_RDI, 0, REG_NONE, 0, true, ctxt);
}

VOID
strncpy_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG2 ((ADDRINT) ip, "strncpy_post_hook: dst = %lx\n", saved_arg1);
    tag_copy_reg2reg_nth (ip, REG_NONE, 0, REG_RAX, 0, true, ctxt);
    tag_clear_reg (ip, REG_NONE, 0, ctxt, false);
}

// =========== new系

// operator new [](unsigned long)
VOID
_Znam_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    saved_arg1 =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG2 ((ADDRINT) ip, "new[]_pre_hook@%lx: size=%ld, ret_ip=%lx\n",
           ip, saved_arg1, ret_ip);
}

// operator new [](unsigned long)
VOID
_Znam_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    ADDRINT addr = PIN_GetContextReg (ctxt, REG_RAX);
    UINT32 size = (UINT32) saved_arg1;
    DLOG ("new[]_post_hook: addr=%lx, size=%d\n", addr, size);
    register_malloc_map (addr, size, saved_ret_ip, ctxt);
}

// operator new(unsigned long)
VOID
_Znwm_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    saved_arg1 =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG2 ((ADDRINT) ip, "new_pre_hook@%lx: size=%ld, ret_ip=%lx\n",
           ip, saved_arg1, ret_ip);
#if 0
    fprintf (OUT_FP, "new_pre_hook@%lx: size=%ld, ret_ip=%lx\n",
           ip, saved_arg1, ret_ip);
#endif
}

// operator new(unsigned long)
VOID
_Znwm_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    ADDRINT addr = PIN_GetContextReg (ctxt, REG_RAX);
    UINT32 size = (UINT32) saved_arg1;
    DLOG ("new_post_hook: addr=%lx, size=%d\n", addr, size);
    register_malloc_map (addr, size, saved_ret_ip, ctxt);
}

// operator new[](unsigned long, std::nothrow_t const&)
VOID
_ZnamRKSt9nothrow_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    saved_arg1 =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG2 ((ADDRINT) ip, "new[]_nothrow_pre_hook@%lx: size=%ld, ret_ip=%lx\n",
           ip, saved_arg1, ret_ip);
}

// operator new[](unsigned long, std::nothrow_t const&)
VOID
_ZnamRKSt9nothrow_t_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    ADDRINT addr = PIN_GetContextReg (ctxt, REG_RAX);
    UINT32 size = (UINT32) saved_arg1;
    DLOG ("new[]_nothrow_post_hook: addr=%lx, size=%d\n", addr, size);
    register_malloc_map (addr, size, saved_ret_ip, ctxt);
}

// operator new(unsigned long, std::nothrow_t const&)
VOID
_ZnwmRKSt9nothrow_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    saved_arg1 =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG2 ((ADDRINT) ip, "new_nothrow_pre_hook@%lx: size=%ld, ret_ip=%lx\n",
           ip, saved_arg1, ret_ip);
}

// operator new(unsigned long, std::nothrow_t const&)
VOID
_ZnwmRKSt9nothrow_t_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    ADDRINT addr = PIN_GetContextReg (ctxt, REG_RAX);
    UINT32 size = (UINT32) saved_arg1;
    DLOG ("new_nothrow_post_hook: addr=%lx, size=%d\n", addr, size);
    register_malloc_map (addr, size, saved_ret_ip, ctxt);
}

// operator new(unsigned long, std::align_val_t)
VOID
_ZnwmSt11align_val_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    saved_arg1 =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG2 ((ADDRINT) ip, "new_align_pre_hook@%lx: size=%ld, ret_ip=%lx\n",
           ip, saved_arg1, ret_ip);
}

// operator new(unsigned long, std::align_val_t)
VOID
_ZnwmSt11align_val_t_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    ADDRINT addr = PIN_GetContextReg (ctxt, REG_RAX);
    UINT32 size = (UINT32) saved_arg1;
    DLOG ("new_align_post_hook: addr=%lx, size=%d\n", addr, size);
    register_malloc_map (addr, size, saved_ret_ip, ctxt);
}

// operator new(unsigned long, std::align_val_t, std::nothrow_t const&)
VOID
_ZnwmSt11align_val_tRKSt9nothrow_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    saved_arg1 =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG2 ((ADDRINT) ip, "new_align_nothrow_pre_hook@%lx: size=%ld, ret_ip=%lx\n",
           ip, saved_arg1, ret_ip);
}

// operator new(unsigned long, std::align_val_t, std::nothrow_t const&)
VOID
_ZnwmSt11align_val_tRKSt9nothrow_t_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    ADDRINT addr = PIN_GetContextReg (ctxt, REG_RAX);
    UINT32 size = (UINT32) saved_arg1;
    DLOG ("new_align_nothrow_post_hook: addr=%lx, size=%d\n", addr, size);
    register_malloc_map (addr, size, saved_ret_ip, ctxt);
}

// operator new[](unsigned long, std::align_val_t)
VOID
_ZnamSt11align_val_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    saved_arg1 =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG2 ((ADDRINT) ip, "new[]_align_pre_hook@%lx: size=%ld, ret_ip=%lx\n",
           ip, saved_arg1, ret_ip);
}

// operator new[](unsigned long, std::align_val_t)
VOID
_ZnamSt11align_val_t_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    ADDRINT addr = PIN_GetContextReg (ctxt, REG_RAX);
    UINT32 size = (UINT32) saved_arg1;
    DLOG ("new[]_align_post_hook: addr=%lx, size=%d\n", addr, size);
    register_malloc_map (addr, size, saved_ret_ip, ctxt);
}

// operator new[](unsigned long, std::align_val_t, std::nothrow_t const&)
VOID
_ZnamSt11align_val_tRKSt9nothrow_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    saved_arg1 =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG2 ((ADDRINT) ip, "new[]_align_nothrow_pre_hook@%lx: size=%ld, ret_ip=%lx\n",
           ip, saved_arg1, ret_ip);
}

// operator new[](unsigned long, std::align_val_t, std::nothrow_t const&)
VOID
_ZnamSt11align_val_tRKSt9nothrow_t_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    ADDRINT addr = PIN_GetContextReg (ctxt, REG_RAX);
    UINT32 size = (UINT32) saved_arg1;
    DLOG ("new[]_align_nothrow_post_hook: addr=%lx, size=%d\n", addr, size);
    register_malloc_map (addr, size, saved_ret_ip, ctxt);
}

// =========== delete系

// operator delete(void*)
VOID
_ZdlPv_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT addr =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG ("delete_pre_hook: ptr = %lx\n", addr);
    unregister_malloc_map (addr, ret_ip, ctxt);
}
    
// operator delete(void*)
VOID
_ZdlPv_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG ("delete_post_hook:\n");
    tag_clear_caller_save_regs (ip, ctxt);
}

// operator delete[](void*)
VOID
_ZdaPv_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT addr =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG ("delete[]_pre_hook: ptr = %lx\n", addr);
    unregister_malloc_map (addr, ret_ip, ctxt);
}

// operator delete[](void*)
VOID
_ZdaPv_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG ("delete[]_post_hook:\n");
    tag_clear_caller_save_regs (ip, ctxt);
}

// operator delete[](void*, unsigned long)
VOID
_ZdaPvm_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT addr =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG ("delete[]_sized_pre_hook: ptr = %lx\n", addr);
    unregister_malloc_map (addr, ret_ip, ctxt);
}

// operator delete[](void*, unsigned long)
VOID
_ZdaPvm_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG ("delete[]_sized_post_hook:\n");
    tag_clear_caller_save_regs (ip, ctxt);
}

// operator delete(void*, unsigned long)
VOID
_ZdlPvm_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT addr =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG ("delete_sized_pre_hook: ptr = %lx\n", addr);
    unregister_malloc_map (addr, ret_ip, ctxt);
}

// operator delete(void*, unsigned long)
VOID
_ZdlPvm_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG ("delete_sized_post_hook:\n");
    tag_clear_caller_save_regs (ip, ctxt);
}

// operator delete(void*, unsigned long, std::align_val_t)
VOID
_ZdlPvmSt11align_val_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT addr =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG ("delete_sized_align_pre_hook: ptr = %lx\n", addr);
    unregister_malloc_map (addr, ret_ip, ctxt);
}

// operator delete(void*, unsigned long, std::align_val_t)
VOID
_ZdlPvmSt11align_val_t_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG ("delete_sized_align_post_hook:\n");
    tag_clear_caller_save_regs (ip, ctxt);
}

// operator delete(void*, std::nothrow_t const&)
VOID
_ZdlPvRKSt9nothrow_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT addr =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG ("delete_nothrow_pre_hook: ptr = %lx\n", addr);
    unregister_malloc_map (addr, ret_ip, ctxt);
}

// operator delete(void*, std::nothrow_t const&)
VOID
_ZdlPvRKSt9nothrow_t_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG ("delete_nothrow_post_hook:\n");
    tag_clear_caller_save_regs (ip, ctxt);
}

// operator delete(void*, std::align_val_t)
VOID
_ZdlPvSt11align_val_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT addr =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG ("delete_align_pre_hook: ptr = %lx\n", addr);
    unregister_malloc_map (addr, ret_ip, ctxt);
}

// operator delete(void*, std::align_val_t)
VOID
_ZdlPvSt11align_val_t_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG ("delete_align_post_hook:\n");
    tag_clear_caller_save_regs (ip, ctxt);
}

// operator delete(void*, std::align_val_t, std::nothrow_t const&)
VOID
_ZdlPvSt11align_val_tRKSt9nothrow_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT addr =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG ("delete_align_nothrow_pre_hook: ptr = %lx\n", addr);
    unregister_malloc_map (addr, ret_ip, ctxt);
}

// operator delete(void*, std::align_val_t, std::nothrow_t const&)
VOID
_ZdlPvSt11align_val_tRKSt9nothrow_t_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG ("delete_align_nothrow_post_hook:\n");
    tag_clear_caller_save_regs (ip, ctxt);
}

// operator delete[](void*, unsigned long, std::align_val_t)
VOID
_ZdaPvmSt11align_val_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT addr =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG ("delete[]_sized_align_pre_hook: ptr = %lx\n", addr);
    unregister_malloc_map (addr, ret_ip, ctxt);
}

// operator delete[](void*, unsigned long, std::align_val_t)
VOID
_ZdaPvmSt11align_val_t_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG ("delete[]_sized_align_post_hook:\n");
    tag_clear_caller_save_regs (ip, ctxt);
}

// operator delete[](void*, std::nothrow_t const&)
VOID
_ZdaPvRKSt9nothrow_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT addr =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG ("delete[]_nothrow_pre_hook: ptr = %lx\n", addr);
    unregister_malloc_map (addr, ret_ip, ctxt);
}

// operator delete[](void*, std::nothrow_t const&)
VOID
_ZdaPvRKSt9nothrow_t_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG ("delete[]_nothrow_post_hook:\n");
    tag_clear_caller_save_regs (ip, ctxt);
}

// operator delete[](void*, std::align_val_t)
VOID
 _ZdaPvSt11align_val_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT addr =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG ("delete[]_align_pre_hook: ptr = %lx\n", addr);
    unregister_malloc_map (addr, ret_ip, ctxt);
}

// operator delete[](void*, std::align_val_t)
VOID
 _ZdaPvSt11align_val_t_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG ("delete[]_align_post_hook:\n");
    tag_clear_caller_save_regs (ip, ctxt);
}

// operator delete[](void*, std::align_val_t, std::nothrow_t const&)
VOID
_ZdaPvSt11align_val_tRKSt9nothrow_t_pre_hook (ADDRINT ip, CONTEXT *ctxt, ADDRINT ret_ip)
{
    ADDRINT addr =  PIN_GetContextReg (ctxt, REG_RDI);
    saved_ret_ip = ret_ip;
    DLOG ("delete[]_align_nothrow_pre_hook: ptr = %lx\n", addr);
    unregister_malloc_map (addr, ret_ip, ctxt);
}

// operator delete[](void*, std::align_val_t, std::nothrow_t const&)
VOID
_ZdaPvSt11align_val_tRKSt9nothrow_t_post_hook (ADDRINT ip, CONTEXT *ctxt)
{
    DLOG ("delete[]_align_nothrow_post_hook:\n");
    tag_clear_caller_save_regs (ip, ctxt);
}

/* ================================================== */
void
mark_sweep (void)
{
    std::vector<ADDRINT> stack_work;

    DLOG ("===== mark_sweep =====\n");
    for (auto i: malloc_map) {
        i.second.mark = false;
    }

    DLOG ("===== root =====\n");
    stack_work.clear ();
    for (int i = 0; i < NUM_INDEX_REG; i++) {
        for (int j = 0; j < NUM_TAG_PER_REG; j++) {
            if (!tag_reg_array [i][j].empty ()) {
                for (auto &tag: tag_reg_array [i][j]) {
                    DLOG ("push_back: (%s[%d]=>)%lx\n",
                          INDEX_REG_STR [i], j, tag);
                    stack_work.push_back (tag);
                }
            }
        }
    }
    for (auto i: tag_mem_map) {
        for (auto tag: i.second) {
            if (is_onstack (i.first) || is_ondata (i.first)) {
                DLOG ("push_back: (%lx=>)%lx\n", i.first, tag);
                stack_work.push_back (tag);
            }
        }
    }


#ifdef OUTPUT_LOG
    DLOG ("root: ");
    for (UNUSED auto i: stack_work) {
        DLOG_NOHEADER ("%lx, ", i);
    }
    DLOG_NOHEADER ("\n");
#endif

    DLOG ("===== mark =====\n");
    while (!stack_work.empty ()) {
        auto tag = stack_work.back (); stack_work.pop_back ();
        DLOG ("pop %lx\n", tag);
        auto found = malloc_map.find (tag);
        assert (found != malloc_map.end ());
        auto &addr = found->first;
        auto &meta = found->second;
        if (!meta.mark) {
            DLOG ("mark %lx\n", addr);
            meta.mark = true;
            for (ADDRINT p = addr; p <= addr + meta.size - 8; p += 8) {
                auto found = tag_mem_map.find (p);
                if (found != tag_mem_map.end ()) {
                    for (auto tag2: found->second) {
                        DLOG ("push %lx\n", tag2);
                        stack_work.push_back (tag2);
                    }
                }
            }
        } 
    }
    DLOG ("===== sweep =====\n");
    for (auto i: malloc_map) {
        auto &meta = i.second;
        if (meta.stat == ALLOCATED && !meta.mark) {
            fprintf (OUT_FP, "leak %lx\n", i.first);
        }
    }

    detect_unreachable_cycles ();
    DLOG ("===== end of mark_sweep =====\n");
}

void
detect_unreachable_cycles ()
{
    std::unordered_map<ADDRINT, std::set<ADDRINT>> forw_next, rev_next;
    std::vector<ADDRINT> stack_work, stack_out, stack_out2;
    std::vector<std::vector<ADDRINT>> SCC;

    DLOG ("===== cycle =====\n");

    DLOG ("===== collect unmarked (unreachable) objects =====\n");
    for (auto i: malloc_map) {
        auto &addr = i.first;
        auto &meta = i.second;
        for (ADDRINT p = addr; p <= addr + meta.size - 8; p += 8) {
            auto found = tag_mem_map.find (p);
            if (found != tag_mem_map.end ()) {
                for (auto tag: found->second) {
                    auto found2 = malloc_map.find (tag);
                    assert (found2 != malloc_map.end ());
                    if (!found2->second.mark) {
                        // trivial SCC is excluded here
                        DLOG ("insert %lx=>%lx\n", addr, tag);
                        forw_next [addr].insert (tag);
                        rev_next [tag].insert (addr);
                    }
                }
            }
        }
    }

#ifdef OUTPUT_LOG
    DLOG ("==== forw_next ====\n");
    for (auto i: forw_next) {
        DLOG ("%lx => ", i.first);
        for (UNUSED auto j: i.second) {
            DLOG_NOHEADER ("%lx, ", j);
        }
        DLOG_NOHEADER ("\n");
    }
    DLOG ("==== rev_next ====\n");
    for (auto i: rev_next) {
        DLOG ("%lx => ", i.first);
        for (UNUSED auto j: i.second) {
            DLOG_NOHEADER ("%lx, ", j);
        }
        DLOG_NOHEADER ("\n");
    }
#endif        
    DLOG ("===== DFS (1) =====\n");
    // 初期化
    for (auto i: forw_next) {
        auto found = malloc_map.find (i.first);
        assert (found != malloc_map.end ());
        found->second.visited = false;
        found->second.post_order = -1;
    }

    for (auto i: forw_next) {
        int counter = 0;
        auto found = malloc_map.find (i.first);
        assert (found != malloc_map.end ());

        if (found->second.visited) {
            continue;
        }
        stack_work.push_back (i.first);
        DLOG ("stack_work.push_back: %lx\n", i.first);
        while (!stack_work.empty ()) {
            auto tag = stack_work.back (); stack_work.pop_back ();
            auto found2 = malloc_map.find (tag);
            assert (found2 != malloc_map.end ());
            auto &meta = found2->second;
            if (!meta.visited) {
                DLOG ("stack_out.push_back: %lx\n", tag);
                meta.visited = true;
                stack_out.push_back (tag);
                auto found3 = forw_next.find (tag);
                if (found3 != forw_next.end ()) {
                    for (auto i: found3->second) {
                        DLOG ("stack_work.push_back: (%lx=>)%lx\n", tag, i);
                        stack_work.push_back (i);
                    }
                }
            }
        }
        for (auto it = stack_out.rbegin (); it != stack_out.rend (); it++) {
            found = malloc_map.find (*it);
            assert (found != malloc_map.end ());
            auto &meta = found->second;
            meta.post_order = counter++;
            DLOG ("stack_out: %lx (%d)\n", *it, meta.post_order);
        }
    }

    DLOG ("===== DFS (2) =====\n");
    // 初期化
    for (auto i: stack_out) {
        auto found = malloc_map.find (i);
        assert (found != malloc_map.end ());
        found->second.visited = false;
    }

    for (auto i: stack_out) {
        stack_work.clear ();
        stack_out2.clear ();

        auto found = malloc_map.find (i);
        assert (found != malloc_map.end ());
        if (found->second.visited) {
            continue;
        }

        DLOG ("while top: %lx\n", i);
        stack_work.push_back (i);
        DLOG ("stack_work.push_back: %lx\n", i);
        while (!stack_work.empty ()) {
            auto tag = stack_work.back (); stack_work.pop_back ();
            auto found2 = malloc_map.find (tag);
            assert (found2 != malloc_map.end ());
            auto &meta = found2->second;
            if (!meta.visited) {
                meta.visited = true;
                DLOG ("stack_out2.push_back: %lx\n", tag);
                stack_out2.push_back (tag);
                auto found3 = rev_next.find (tag);
                if (found3 != rev_next.end ()) {
                    for (auto i: found3->second) {
                        DLOG ("stack_work.push_back: (%lx=>)%lx\n", tag, i);
                        stack_work.push_back (i);
                    }
                }
            }
        }
#ifdef OUTPUT_LOG
        DLOG ("stack_out2: ");
        for (UNUSED auto i: stack_out2) {
            DLOG_NOHEADER ("%lx, ", i);
        }
        DLOG_NOHEADER ("\n");
#endif
        SCC.push_back (stack_out2);
    }

    DLOG ("===== SCC =====\n");
    for (auto i: SCC) {
        for (UNUSED auto j: i) {
            DLOG_NOHEADER ("%lx, ", j);
        }
        DLOG_NOHEADER ("\n");
    }

    DLOG ("===== end of cycle =====\n");
}
/* ================================================== */
int
main (int argc, char *argv[])
{
#if 0
    // シェルスクリプトからバイナリを起動する場合に対応できない
    for (int i = 0; i < argc; i++) {
        if (!strcmp (argv [i], "--")) {
            aout_name = strip_dir (argv [i + 1]);
            break;
        }
    }
    DLOG ("aout_name = %s\n", aout_name);
#endif

    // PIN_InitSymbols ();
    // memmove や memcpy は IFUNC なことがあるので必要
    PIN_InitSymbolsAlt (SYMBOL_INFO_MODE (UINT32(IFUNC_SYMBOLS) | UINT32 (DEBUG_OR_EXPORT_SYMBOLS)));
    if (PIN_Init (argc, argv)) {
        DLOG ("PIN_Init error\n");
        exit (1);
    }

    // PIN_AddSyscallEntryFunction (SysenterBefore, 0);
    PIN_AddFollowChildProcessFunction (FollowChild, 0);

    IMG_AddInstrumentFunction (Image, 0);
    IMG_AddUnloadFunction (UnloadImage, 0);

    TRACE_AddInstrumentFunction (Trace, 0);

    PIN_AddApplicationStartFunction (Init, 0);
    PIN_AddFiniFunction (Fini, 0);

    PIN_AddThreadStartFunction (InitThread, 0);

    watched_addr = TraceSpecificHeapObject.Value ();
    extra_images = string_split (InstrumentExtraImages.Value (), ':');
    for (auto &i: extra_images) {
        fprintf (OUT_FP, "extra_image: %s\n", i.c_str ());
    }

    PIN_StartProgram ();
}

/* 変更履歴メモ ================================================== */
#if 0
・フックする関数の追加手順
  - malloc_post_hook, malloc_pre_hook 関数の宣言と定義（命名規則大事）
  - INSTRUMENT_HELPER1 (malloc); 追加
  - ビルドオプションに，-Wl,--wrap=malloc を追加．(a.out と libhook.so 両方)
  - plp_malloc.c 中で，ラップ関数 __wrap_malloc 関数を定義
#endif

