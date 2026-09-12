/*
 * meshterm - an interactive Meshtastic client for the terminal.
 *
 * Speaks the StreamAPI framing directly over a serial port or TCP 4403.
 * No protobuf library, no curses, no dependencies beyond libc and POSIX.
 *
 *   cc -O2 -o meshterm meshterm.c
 *   ./meshterm -p /dev/cuaU0
 *
 * Meshtastic(R) is a registered trademark of Meshtastic LLC. This program
 * is an unofficial third-party client and is not affiliated with, endorsed
 * by, or supported by that project.
 *
 * Copyright (C) 2026 Zach McCardel
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define MAX_FRAME       512     /* firmware treats longer frames as corrupt */
#define WAKE_BYTES      (MAX_FRAME + 16)
#define HANDSHAKE_S     15
#define HS_RETRY_S      3
#define HEARTBEAT_S     30
#define MAX_NODES       256
#define MAX_CHANS       8
#define MAX_INPUT       240
#define MAX_TEXT        200   /* user-visible message text       */
#define MAX_PAYLOAD     237   /* firmware Data.payload ceiling    */
#define START1          0x94
#define START2          0xc3
#define BROADCAST       0xffffffffu

/* ToRadio fields */
#define TR_PACKET               1
#define TR_WANT_CONFIG_ID       3
#define TR_DISCONNECT           4
#define TR_HEARTBEAT            7

/* FromRadio fields */
#define FR_PACKET               2
#define FR_MY_INFO              3
#define FR_NODE_INFO            4
#define FR_CONFIG_COMPLETE      7
#define FR_CONFIG               5
#define FR_METADATA             13
#define FR_CHANNEL              10

/* MeshPacket / Data fields */
#define MP_FROM         1
#define MP_TO           2
#define MP_CHANNEL      3
#define MP_DECODED      4
#define MP_ENCRYPTED    5
#define DATA_PORTNUM      1
#define DATA_PAYLOAD      2
#define DATA_WANT_RESPONSE 3
#define PORT_TEXT         1
#define PORT_NODEINFO     4
#define PORT_ROUTING      5
#define PORT_ADMIN        6

/*
 * AdminMessage field numbers. Verified against the generated descriptors --
 * these are permanent once shipped, so they are safe to hard-code even
 * across firmware versions. The high numbers are the destructive actions;
 * the project deliberately put them out of accidental reach.
 */
#define ADM_GET_CHANNEL_REQ   1
#define ADM_GET_CHANNEL_RESP  2
#define ADM_SET_CHANNEL      33
#define ADM_GET_CONNSTATUS_REQ  16
#define ADM_GET_CONNSTATUS_RESP 17
#define ADM_GET_CONFIG_REQ   5
#define ADM_GET_CONFIG_RESP  6
#define ADM_SET_CONFIG      34
#define ADM_GET_OWNER_REQ    3
#define ADM_GET_OWNER_RESP   4
#define ADM_SET_OWNER       32
#define ADM_REBOOT_SECONDS  97
#define ADM_SESSION_PASSKEY 101

/* User (inside AdminMessage.set_owner / get_owner_response) */
#define USER_LONG_NAME  2
#define USER_SHORT_NAME 3

/*
 * ConfigType selects which sub-config a get/set refers to. The Config
 * oneof field number is always the ConfigType plus one, which is how we
 * find the sub-message inside a get_config_response.
 */
#define CFGTYPE_DEVICE   0
#define CFGTYPE_NETWORK  3
#define CFGTYPE_LORA     5
#define CFGTYPE_BLUETOOTH 6
#define CFG_FIELD(t)     ((t) + 1)

/*
 * DeviceConfig. Note field 9 next door is is_managed, which locks the node
 * against further admin changes -- the read-modify-write below preserves
 * every field it is not explicitly replacing, so it is never touched.
 */
#define DEV_LED_OFF      12

/* LoRaConfig */
#define LORA_REGION      7

/* BluetoothConfig */
#define BT_ENABLED       1

/* Channel / ChannelSettings / ChannelSet */
#define CH_INDEX         1
#define CH_SETTINGS      2
#define CH_ROLE          3
#define CHS_PSK          2
#define CHS_NAME         3
#define CSET_SETTINGS    1
#define CSET_LORA        2
#define ROLE_SECONDARY   2
#define PSK_BYTES       32
#define SHARE_PREFIX "https://meshtastic.org/e/#"

/* NetworkConfig (field 2 is the deprecated wifi_mode) */
#define TCP_PORT 4403       /* StreamAPI over TCP, same framing as serial */

#define NET_WIFI_ENABLED 1
#define NET_WIFI_SSID    3
#define NET_WIFI_PSK     4

/* Routing.error_reason, for admin rejections */
#define ROUTING_ERROR_REASON 3

#define LONGNAME_MAX 39   /* 2.8 shrank this to 25; we warn rather than clip */
#define SHORTNAME_MAX 4

/* Channel roles */
#define ROLE_DISABLED   0
#define ROLE_PRIMARY    1

/* ====================================================================== */
/* state                                                                  */
/* ====================================================================== */

struct node {
  uint32_t num;
  char longname[40];
  char shortname[8];
  int used;
};

struct chan {
  int index;
  char name[20];
  int role;
  int used;
  /*
   * The ChannelSettings exactly as the radio sent them. Sharing has to
   * reproduce the PSK bit-for-bit, and re-encoding from parsed fields
   * would drop anything this build does not know about.
   */
  unsigned char raw[128];
  size_t rawlen;
};

/*
 * Muted nodes. Purely local -- nothing is sent to the radio, the traffic
 * still arrives and is still relayed, we just do not print it.
 */
#define MAX_MUTED 32
static uint32_t muted[MAX_MUTED];
static size_t nmuted;

static struct node nodes[MAX_NODES];
static struct chan chans[MAX_CHANS];
static uint32_t my_num;

/*
 * Config.LoRaConfig. A primary channel with no explicit name is displayed
 * by convention as the modem preset, which is where "LongFast" comes from.
 * Note that a stock node encodes modem_preset = LONG_FAST as an absent
 * field, so seeing Config.lora at all with use_preset set implies LongFast
 * unless told otherwise.
 */
static int lora_seen, lora_use_preset, lora_preset, lora_region = -1;
static unsigned char lora_raw[160];   /* raw LoRaConfig, for share URLs */
static size_t lora_rawlen;

/* Config.network / Config.bluetooth, as reported in the config dump. */
static int net_seen, net_wifi_on, bt_seen, bt_on;
static int dev_seen, dev_led_off;
static char net_ssid[40];

/* Filled in by /net (DeviceConnectionStatus); 0 when we have not asked. */
static uint32_t net_ip;
static int net_connected, net_rssi;

/*
 * FromRadio.metadata (DeviceMetadata). firmware_version is a string, so it
 * is the one field that tells us which protobuf generation we are actually
 * talking to rather than the one we were compiled against.
 */
/*
 * Some firmware requires a session passkey on admin writes. Local admin
 * over the attached interface has historically been exempt, so we send
 * without one and cache whatever the radio hands back, echoing it on
 * subsequent writes. If it is not needed, this stays empty and costs
 * nothing.
 */
static unsigned char session_key[8];
static size_t session_key_len;

static char fw_version[40];
static int hw_model = -1;
static int has_wifi, has_bt, has_eth;

/*
 * Enums are open: firmware adds values (2.8 introduced LongTurbo, TinyFast
 * and TinySlow) and a client compiled against an older set must not pretend
 * they do not exist. Anything past the end of this table is reported by
 * number rather than silently discarded.
 */
static const char *preset_names[] = {
  "LongFast", "LongSlow", "VLongSlow", "MediumSlow", "MediumFast",
  "ShortSlow", "ShortFast", "LongMod", "ShortTurbo"
};
#define NPRESETS ((int)(sizeof(preset_names) / sizeof(preset_names[0])))

/*
 * RegionCode. Open like every other enum -- /region also accepts a bare
 * number so a region added after this build can still be set. The numeric
 * value is always shown alongside the name so a wrong mapping is visible
 * against what the device screen reports.
 */
static const char *region_names[] = {
  "UNSET", "US", "EU_433", "EU_868", "CN", "JP", "ANZ", "KR", "TW", "RU",
  "IN", "NZ_865", "TH", "LORA_24", "UA_433", "UA_868", "MY_433", "MY_919",
  "SG_923", "PH_433", "PH_868", "PH_915", "ANZ_433", "KZ_433", "KZ_863",
  "NP_865", "BR_902"
};
#define NREGIONS ((int)(sizeof(region_names) / sizeof(region_names[0])))

/* Name for the active modem preset, or "preset N" if this build predates it. */
static const char *
preset_str(void)
{
  static char buf[24];

  if (!lora_seen || !lora_use_preset)
    return "custom";
  if (lora_preset >= 0 && lora_preset < NPRESETS)
    return preset_names[lora_preset];
  snprintf(buf, sizeof(buf), "preset%d", lora_preset);
  return buf;
}

/* preferences, settable via -flags, ~/.meshtermrc, or /set */
static int pref_time = 1;       /* show timestamps                      */
static int pref_name = 1;       /* prefer names over hex ids            */
static int pref_hex;            /* show hex id alongside the name       */
static int pref_color = 1;      /* ANSI colour                          */
static int pref_verbose;        /* firmware debug + protocol detail     */
/*
 * Whether to echo the radio's session passkey on admin writes. Local admin
 * over the attached serial port does not require one, and sending a stale
 * key gets every admin message rejected -- silently, since the rejection
 * arrives as a routing error nobody is watching. Off unless asked for.
 */
static int pref_passkey;

/*
 * /whoami asks the radio for everything it shows rather than printing
 * whatever arrived at connect time. Each reply sets its bit; the request
 * loop waits until every expected bit is in or the timeout expires.
 */
#define FRESH_OWNER 0x01
#define FRESH_LORA  0x02
#define FRESH_NET   0x04
#define FRESH_BT    0x08
#define FRESH_CONN  0x10
#define FRESH_DEV   0x20
#define FRESH_WAIT_MS 600
static unsigned fresh_got, fresh_want;
static uint32_t pump_nonce;   /* handshake id pump_ms should watch for */

static const char *dev_path = "/dev/cuaU0";
static speed_t link_baud = B115200;
static int serial_fd = -1;
static int is_tcp;              /* link is a socket, not a tty */
static int rawmode;             /* stdin is a tty and in raw mode       */
static int interactive;         /* stdin is a tty                       */
static volatile sig_atomic_t quitflag;

static struct termios saved_tio;
static int tio_saved;

/* current send target */
static int cur_chan;                    /* channel index                */
static uint32_t cur_dm;                 /* 0 = none, else node num      */

/* input line */
static char ibuf[MAX_INPUT + 1];
static size_t ilen, icur;

/*
 * Command history. hist[0] is the most recent entry; hist_pos is -1 while
 * editing a fresh line and counts backwards through the ring otherwise,
 * with hist_save holding the line that was in progress when browsing began.
 */
#define HIST_MAX 20
static char hist[HIST_MAX][MAX_INPUT + 1];
static char hist_save[MAX_INPUT + 1];
static int hist_n, hist_pos = -1;

/* ====================================================================== */
/* colour                                                                 */
/* ====================================================================== */

/*
 * Basic SGR only -- deliberately not 256-colour. A VT100 parses
 * "\033[38;5;244m" as three separate parameters, and parameter 5 is BLINK,
 * so a 256-colour palette makes the whole session flash on real hardware.
 * The codes below use only 0, 1, 3x and 9x: 0 and 1 mean reset and bold on
 * a VT100, and everything above 7 is silently ignored. Graceful monochrome.
 */
#define C_RESET "\033[0m"
#define C_DIM   "\033[90m"
#define C_TIME  "\033[90m"
#define C_ME    "\033[32m"
#define C_DM    "\033[95m"
#define C_SYS   "\033[33m"
#define C_ERR   "\033[91m"
#define C_CHAN  "\033[36m"
#define C_HDR   "\033[1;36m"

static const char *
col(const char *c)
{
  return pref_color ? c : "";
}

/* ====================================================================== */
/* protobuf                                                               */
/* ====================================================================== */

struct pbfield {
  uint32_t field;
  uint8_t wire;
  uint64_t varint;
  uint32_t fix32;
  const unsigned char *data;
  size_t len;
};

static int
pb_next(const unsigned char **p, const unsigned char *end, struct pbfield *f)
{
  uint64_t key = 0, v = 0;
  int shift = 0;

  if (*p >= end)
    return 0;
  while (*p < end) {
    unsigned char c = *(*p)++;
    key |= (uint64_t)(c & 0x7f) << shift;
    if (!(c & 0x80))
      break;
    if ((shift += 7) > 63)
      return -1;
  }
  memset(f, 0, sizeof(*f));
  f->field = (uint32_t)(key >> 3);
  f->wire = (uint8_t)(key & 7);

  switch (f->wire) {
  case 0:
    shift = 0;
    while (*p < end) {
      unsigned char c = *(*p)++;
      v |= (uint64_t)(c & 0x7f) << shift;
      if (!(c & 0x80))
        break;
      if ((shift += 7) > 63)
        return -1;
    }
    f->varint = v;
    return 1;
  case 2:
    shift = 0;
    while (*p < end) {
      unsigned char c = *(*p)++;
      v |= (uint64_t)(c & 0x7f) << shift;
      if (!(c & 0x80))
        break;
      if ((shift += 7) > 63)
        return -1;
    }
    if ((uint64_t)(end - *p) < v)
      return -1;
    f->data = *p;
    f->len = (size_t)v;
    *p += v;
    return 1;
  case 5:
    if (end - *p < 4)
      return -1;
    f->fix32 = (uint32_t)(*p)[0] | ((uint32_t)(*p)[1] << 8) |
        ((uint32_t)(*p)[2] << 16) | ((uint32_t)(*p)[3] << 24);
    *p += 4;
    return 1;
  case 1:
    if (end - *p < 8)
      return -1;
    *p += 8;
    return 1;
  default:
    return -1;
  }
}

/*
 * Write a field tag. Field numbers above 15 do not fit in a single byte,
 * so the tag is itself a varint -- ADM_SET_OWNER (32) and the action
 * fields in the 90s all need two bytes.
 */
static size_t pb_varint(unsigned char *out, uint64_t v);

static size_t
pb_tag(unsigned char *out, uint32_t field, unsigned wire)
{
  return pb_varint(out, ((uint64_t)field << 3) | wire);
}

static size_t
pb_varint(unsigned char *out, uint64_t v)
{
  size_t i = 0;

  while (v >= 0x80) {
    out[i++] = (unsigned char)(v | 0x80);
    v >>= 7;
  }
  out[i++] = (unsigned char)v;
  return i;
}

/* ====================================================================== */
/* output + input line                                                    */
/* ====================================================================== */



/*
 * Cursor motion has to count characters, not bytes, or an arrow key lands
 * inside a multi-byte sequence and the next keystroke corrupts it. These
 * treat any byte matching 10xxxxxx as a continuation and skip it. No
 * double-width handling -- CJK will be one column short, which misplaces
 * the cursor but never corrupts the buffer.
 */
#define U8_CONT(c) (((unsigned char)(c) & 0xc0) == 0x80)

/* Display columns occupied by the first n bytes of s. */
static size_t
u8_cols(const char *s, size_t n)
{
  size_t i, w = 0;

  for (i = 0; i < n; i++)
    if (!U8_CONT(s[i]))
      w++;
  return w;
}

/* Byte offset `cols` characters before byte offset end. */
static size_t
u8_back(const char *s, size_t end, size_t cols)
{
  size_t i = end;

  while (i > 0 && cols > 0) {
    i--;
    while (i > 0 && U8_CONT(s[i]))
      i--;
    cols--;
  }
  return i;
}

/* Byte offset `cols` characters after byte offset start. */
static size_t
u8_fwd(const char *s, size_t len, size_t start, size_t cols)
{
  size_t i = start;

  while (i < len && cols > 0) {
    i++;
    while (i < len && U8_CONT(s[i]))
      i++;
    cols--;
  }
  return i;
}

static const char *region_str(int r);
static void cmd_net_quiet(void);
static int pump(int secs, uint32_t nonce);
static int pump_ms(int ms);
static uint32_t pump_nonce;
static void cmd_chans(void);
static void handle_channel(const unsigned char *b, size_t n);
static int chan_lookup(const char *s);
static struct chan *chan_find_index(int idx);
static void pend_complete(const unsigned char *cfg, size_t n);
static void handle_config(const unsigned char *b, size_t n);
static int pend_type;

static const char *chan_str(int idx);
static const char *node_str(uint32_t num);

static void
hist_push(const char *line)
{
  int i;

  if (line[0] == '\0')
    return;
  if (hist_n > 0 && strcmp(hist[0], line) == 0)
    return;                             /* skip consecutive duplicates */
  for (i = (hist_n < HIST_MAX ? hist_n : HIST_MAX - 1); i > 0; i--)
    memcpy(hist[i], hist[i - 1], sizeof(hist[0]));
  snprintf(hist[0], sizeof(hist[0]), "%s", line);
  if (hist_n < HIST_MAX)
    hist_n++;
}

static void
ibuf_set(const char *s)
{
  snprintf(ibuf, sizeof(ibuf), "%s", s);
  ilen = strlen(ibuf);
  icur = ilen;
}

static void
hist_up(void)
{
  if (hist_pos + 1 >= hist_n)
    return;
  if (hist_pos < 0)
    snprintf(hist_save, sizeof(hist_save), "%s", ibuf);
  hist_pos++;
  ibuf_set(hist[hist_pos]);
}

static void
hist_down(void)
{
  if (hist_pos < 0)
    return;
  hist_pos--;
  ibuf_set(hist_pos < 0 ? hist_save : hist[hist_pos]);
}

static void
prompt_text(char *out, size_t n)
{
  if (cur_dm != 0)
    snprintf(out, n, "[@%s] ", node_str(cur_dm));
  else
    snprintf(out, n, "[%s] ", chan_str(cur_chan));
}

static void
input_erase(void)
{
  if (rawmode)
    fputs("\r\033[K", stdout);
}

/*
 * Over a real serial line the kernel has no idea how big the terminal is,
 * so TIOCGWINSZ returns zeros. Fall back to $COLUMNS, then to 80 -- which
 * is the right answer for a VT100 anyway. `stty columns N` is the manual
 * override.
 */
static int
term_width(void)
{
  struct winsize ws;
  const char *env;
  int n;

  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 20)
    return ws.ws_col;
  if ((env = getenv("COLUMNS")) != NULL && (n = atoi(env)) > 20)
    return n;
  return 80;
}

/*
 * Redraw the input line. The visible text scrolls horizontally rather than
 * wrapping: a wrapped line cannot be erased by a single \r + EL, so every
 * keystroke past the right margin would leave a stale row behind.
 */
static void
input_draw(void)
{
  char p[64];
  size_t plen, avail, start, shown;
  int w;

  if (!rawmode)
    return;
  prompt_text(p, sizeof(p));
  plen = strlen(p);
  w = term_width();
  if ((size_t)w < plen + 10)
    plen = 0;           /* pathologically narrow: drop the prompt */
  avail = (size_t)w - plen - 1;

  if (u8_cols(ibuf, icur) >= avail)
    start = u8_back(ibuf, icur, avail - 1);
  else
    start = 0;
  shown = u8_fwd(ibuf, ilen, start, avail) - start;

  printf("\r\033[K%s%s%s%.*s", col(C_CHAN), plen ? p : "", col(C_RESET),
      (int)shown, ibuf + start);
  {
    size_t total = u8_cols(ibuf + start, shown);
    size_t at = u8_cols(ibuf + start, icur - start);

    if (total > at)
      printf("\033[%zuD", total - at);
  }
  fflush(stdout);
}

/* Print a line above the input, then redraw the input line. */
static void
emit(const char *fmt, ...)
{
  va_list ap;

  input_erase();
  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
  putchar('\n');
  input_draw();
  if (!rawmode)
    fflush(stdout);
}

static void
sysmsg(const char *fmt, ...)
{
  char buf[512];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  emit("%s-!- %s%s", col(C_SYS), buf, col(C_RESET));
}

static void
errmsg(const char *fmt, ...)
{
  char buf[512];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  emit("%s-!- %s%s", col(C_ERR), buf, col(C_RESET));
}

static void
hdrmsg(const char *fmt, ...)
{
  char buf[512];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  emit("%s=== %s%s", col(C_HDR), buf, col(C_RESET));
}

static void
stamp(char *out, size_t n)
{
  time_t now;
  struct tm tm;

  if (!pref_time) {
    out[0] = '\0';
    return;
  }
  now = time(NULL);
  if (localtime_r(&now, &tm) == NULL) {
    snprintf(out, n, "--:--:-- ");
    return;
  }
  strftime(out, n, "%H:%M:%S ", &tm);
}

/* ====================================================================== */
/* node + channel tables                                                  */
/* ====================================================================== */

static int
is_muted(uint32_t num)
{
  size_t i;

  for (i = 0; i < nmuted; i++)
    if (muted[i] == num)
      return 1;
  return 0;
}

static struct node *
node_find(uint32_t num)
{
  size_t i;

  for (i = 0; i < MAX_NODES; i++)
    if (nodes[i].used && nodes[i].num == num)
      return &nodes[i];
  return NULL;
}

static struct node *
node_intern(uint32_t num)
{
  size_t i;

  for (i = 0; i < MAX_NODES; i++)
    if (nodes[i].used && nodes[i].num == num)
      return &nodes[i];
  for (i = 0; i < MAX_NODES; i++)
    if (!nodes[i].used) {
      nodes[i].used = 1;
      nodes[i].num = num;
      return &nodes[i];
    }
  return NULL;
}

/* Format a node for display, honouring pref_name / pref_hex. */
static const char *
node_str(uint32_t num)
{
  static char buf[4][64];
  static int turn;
  const struct node *nd = node_find(num);
  const char *name = NULL;
  char *out;

  out = buf[turn = (turn + 1) & 3];
  if (nd != NULL) {
    if (nd->shortname[0])
      name = nd->shortname;
    else if (nd->longname[0])
      name = nd->longname;
  }
  if (name != NULL && pref_name) {
    if (pref_hex)
      snprintf(out, sizeof(buf[0]), "%s(!%08x)", name, num);
    else
      snprintf(out, sizeof(buf[0]), "%s", name);
  } else {
    snprintf(out, sizeof(buf[0]), "!%08x", num);
  }
  return out;
}

/* Resolve "!hex", a short name, or a long name to a node number. */
static uint32_t
node_lookup(const char *s)
{
  unsigned long v;
  char *endp;
  size_t i;

  if (s[0] == '!')
    s++;
  if (strlen(s) == 8) {
    v = strtoul(s, &endp, 16);
    if (*endp == '\0')
      return (uint32_t)v;
  }
  for (i = 0; i < MAX_NODES; i++)
    if (nodes[i].used && strcasecmp(nodes[i].shortname, s) == 0)
      return nodes[i].num;
  for (i = 0; i < MAX_NODES; i++)
    if (nodes[i].used && strcasecmp(nodes[i].longname, s) == 0)
      return nodes[i].num;
  return 0;
}

static struct chan *
chan_find_index(int idx)
{
  size_t i;

  for (i = 0; i < MAX_CHANS; i++)
    if (chans[i].used && chans[i].index == idx)
      return &chans[i];
  return NULL;
}

static int
chan_lookup(const char *s)
{
  char *endp;
  long v;
  size_t i;

  if (s[0] == '#')
    s++;
  for (i = 0; i < MAX_CHANS; i++)
    if (chans[i].used && strcasecmp(chans[i].name, s) == 0)
      return chans[i].index;
  v = strtol(s, &endp, 10);
  if (*endp == '\0' && v >= 0 && v < MAX_CHANS)
    return (int)v;
  return -1;
}

/* Display name for a channel: explicit name, else the modem preset for an
 * unnamed primary, else the bare index. */
static const char *
chan_str(int idx)
{
  static char buf[2][32];
  static int turn;
  const struct chan *c = chan_find_index(idx);
  char *out = buf[turn = !turn];

  if (c != NULL && c->name[0])
    snprintf(out, sizeof(buf[0]), "#%s", c->name);
  else if (idx == 0 && lora_seen && lora_use_preset)
    snprintf(out, sizeof(buf[0]), "#%s", preset_str());
  else
    snprintf(out, sizeof(buf[0]), "#ch%d", idx);
  return out;
}

/* ====================================================================== */
/* framing                                                                */
/* ====================================================================== */

static unsigned char rxframe[MAX_FRAME];
static size_t rxlen, rxwant;
static int rxstate;
static unsigned char dbgline[512];
static size_t dbglen;

static void
dbg_flush(void)
{
  if (dbglen == 0)
    return;
  dbgline[dbglen] = '\0';
  if (pref_verbose)
    emit("%sdbg|%s %s%s", col(C_DIM), col(C_RESET), dbgline,
        col(C_RESET));
  dbglen = 0;
}

static int
feed(unsigned char c)
{
  switch (rxstate) {
  case 0:
    if (c == START1) {
      rxstate = 1;
    } else if (c == '\n' || c == '\r') {
      dbg_flush();
    } else if (dbglen < sizeof(dbgline) - 1) {
      /*
       * Keep ESC so the firmware's own SGR colouring
       * survives; drop other control bytes so a stray
       * code cannot scramble the terminal.
       */
      if (c >= 0x20 || c == 0x1b || c == '\t')
        dbgline[dbglen++] = c;
    }
    return 0;
  case 1:
    if (c == START2)
      rxstate = 2;
    else
      rxstate = (c == START1) ? 1 : 0;
    return 0;
  case 2:
    rxwant = (size_t)c << 8;
    rxstate = 3;
    return 0;
  case 3:
    rxwant |= c;
    rxlen = 0;
    if (rxwant == 0 || rxwant > MAX_FRAME) {
      if (pref_verbose)
        errmsg("bogus frame length %zu, resyncing",
            rxwant);
      rxstate = 0;
      return 0;
    }
    rxstate = 4;
    return 0;
  default:
    rxframe[rxlen++] = c;
    if (rxlen >= rxwant) {
      rxstate = 0;
      return 1;
    }
    return 0;
  }
}

static int
send_frame(const unsigned char *pb, size_t n)
{
  unsigned char hdr[4];

  hdr[0] = START1;
  hdr[1] = START2;
  hdr[2] = (unsigned char)(n >> 8);
  hdr[3] = (unsigned char)(n & 0xff);
  if (write(serial_fd, hdr, 4) != 4 ||
      write(serial_fd, pb, n) != (ssize_t)n) {
    errmsg("write: %s", strerror(errno));
    return -1;
  }
  if (!is_tcp && tcdrain(serial_fd) < 0)
    errmsg("tcdrain: %s", strerror(errno));
  return 0;
}

static int
send_want_config(uint32_t nonce)
{
  unsigned char pb[8];
  size_t i = 0;

  pb[i++] = (TR_WANT_CONFIG_ID << 3) | 0;
  i += pb_varint(pb + i, nonce);
  return send_frame(pb, i);
}

static int
send_heartbeat(void)
{
  unsigned char pb[2] = { (TR_HEARTBEAT << 3) | 2, 0 };

  return send_frame(pb, sizeof(pb));
}

static int
send_disconnect(void)
{
  unsigned char pb[2] = { (TR_DISCONNECT << 3) | 0, 1 };

  return send_frame(pb, sizeof(pb));
}

/*
 * Build ToRadio{packet: MeshPacket{to, channel, decoded: Data{portnum,
 * payload, want_response}}} and send it. Text messages and admin messages
 * differ only in portnum and payload, so they share this.
 */
static int
send_packet(int portnum, const unsigned char *payload, size_t l,
    uint32_t dest, int chanidx, int want_response)
{
  unsigned char pb[352], data[256], pkt[304];
  size_t d = 0, k = 0, i = 0;

  if (l > MAX_PAYLOAD) {
    errmsg("payload too long (%zu > %d bytes)", l, MAX_PAYLOAD);
    return -1;
  }

  data[d++] = (DATA_PORTNUM << 3) | 0;
  d += pb_varint(data + d, (uint64_t)portnum);
  data[d++] = (DATA_PAYLOAD << 3) | 2;
  d += pb_varint(data + d, l);
  memcpy(data + d, payload, l);
  d += l;
  if (want_response) {
    data[d++] = (DATA_WANT_RESPONSE << 3) | 0;
    data[d++] = 1;
  }

  pkt[k++] = (MP_TO << 3) | 5;
  pkt[k++] = (unsigned char)(dest & 0xff);
  pkt[k++] = (unsigned char)((dest >> 8) & 0xff);
  pkt[k++] = (unsigned char)((dest >> 16) & 0xff);
  pkt[k++] = (unsigned char)((dest >> 24) & 0xff);
  if (chanidx > 0) {
    pkt[k++] = (MP_CHANNEL << 3) | 0;
    k += pb_varint(pkt + k, (uint64_t)chanidx);
  }
  pkt[k++] = (MP_DECODED << 3) | 2;
  k += pb_varint(pkt + k, d);
  memcpy(pkt + k, data, d);
  k += d;

  pb[i++] = (TR_PACKET << 3) | 2;
  i += pb_varint(pb + i, k);
  memcpy(pb + i, pkt, k);
  i += k;

  return send_frame(pb, i);
}

static int
send_text(const char *msg, uint32_t dest, int chanidx)
{
  if (strlen(msg) > MAX_TEXT) {
    errmsg("message too long (%zu > %d bytes)", strlen(msg), MAX_TEXT);
    return -1;
  }
  return send_packet(PORT_TEXT, (const unsigned char *)msg, strlen(msg),
      dest, chanidx, 0);
}

/*
 * Admin messages are ordinary packets addressed to our own node with
 * portnum ADMIN_APP. want_response is always set so the radio tells us
 * what happened rather than leaving us guessing.
 */
static int
send_admin(const unsigned char *body, size_t n)
{
  unsigned char pb[256];
  size_t i;

  if (my_num == 0) {
    errmsg("node number unknown -- handshake incomplete");
    return -1;
  }
  /*
   * Copy into a local buffer rather than appending to the caller's. The
   * passkey is optional and variable-length, so requiring every call site
   * to reserve headroom for it is a trap -- and one that only springs
   * after a radio hands a passkey back, which is the worst kind.
   */
  if (n + 16 > sizeof(pb)) {
    errmsg("admin message too large (%zu bytes)", n);
    return -1;
  }
  memcpy(pb, body, n);
  i = n;
  if (pref_passkey && session_key_len > 0) {
    i += pb_tag(pb + i, ADM_SESSION_PASSKEY, 2);
    i += pb_varint(pb + i, session_key_len);
    memcpy(pb + i, session_key, session_key_len);
    i += session_key_len;
  }
  return send_packet(PORT_ADMIN, pb, i, my_num, 0, 1);
}

/* ====================================================================== */
/* decode                                                                 */
/* ====================================================================== */

/*
 * Routing packets carry the ack/nak for anything we sent with want_response.
 * A non-zero error_reason is how a rejected admin write reports itself.
 */
static void
handle_routing(const unsigned char *b, size_t n)
{
  const unsigned char *p = b, *end = b + n;
  struct pbfield f;

  while (pb_next(&p, end, &f) == 1) {
    if (f.field != ROUTING_ERROR_REASON || f.wire != 0)
      continue;
    if (f.varint == 0) {
      if (pref_verbose)
        sysmsg("delivered");
    } else {
      errmsg("radio rejected the request (routing error %llu)",
          (unsigned long long)f.varint);
    }
    return;
  }
}

/*
 * DeviceConnectionStatus { wifi = 1 { status = 1 { ip_address = 1,
 * is_connected = 2 }, ssid = 2, rssi = 3 } }. This is the only way to
 * learn the node's IP without walking over and reading the screen.
 */
static void
handle_connstatus(const unsigned char *b, size_t n)
{
  const unsigned char *p = b, *end = b + n;
  struct pbfield f, g, h;
  char ssid[40];
  uint32_t ip = 0;
  int connected = 0, rssi = 0, seen = 0;

  ssid[0] = '\0';
  while (pb_next(&p, end, &f) == 1) {
    if (f.field != 1 || f.wire != 2)          /* wifi */
      continue;
    seen = 1;
    {
      const unsigned char *q = f.data, *qe = f.data + f.len;

      while (pb_next(&q, qe, &g) == 1) {
        if (g.field == 1 && g.wire == 2) {    /* NetworkConnectionStatus */
          const unsigned char *r = g.data, *re = g.data + g.len;

          while (pb_next(&r, re, &h) == 1) {
            if (h.field == 1)
              ip = (h.wire == 5) ? h.fix32 : (uint32_t)h.varint;
            else if (h.field == 2 && h.wire == 0)
              connected = h.varint != 0;
          }
        } else if (g.field == 2 && g.wire == 2) {
          size_t l = g.len < sizeof(ssid) - 1 ? g.len : sizeof(ssid) - 1;

          memcpy(ssid, g.data, l);
          ssid[l] = '\0';
        } else if (g.field == 3 && g.wire == 0) {
          /* int32, so a negative arrives as a sign-extended varint. */
          rssi = (int)(int32_t)g.varint;
        }
      }
    }
  }
  if (!seen)
    return;
  /*
   * Cache only -- never print. The firmware emits these unprompted and
   * repeatedly, so anything printed here shows up as spam nobody asked
   * for. /whoami renders the cached values on demand instead.
   */
  fresh_got |= FRESH_CONN;
  net_ip = ip;
  net_connected = connected;
  net_rssi = rssi;
  if (ssid[0])
    snprintf(net_ssid, sizeof(net_ssid), "%s", ssid);
  if (pref_verbose)
    sysmsg("connection status: %u.%u.%u.%u %s %d dBm",
        ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff,
        connected ? "up" : "down", rssi);
}

static void
handle_admin(const unsigned char *b, size_t n)
{
  const unsigned char *p = b, *end = b + n;
  struct pbfield f, g;

  while (pb_next(&p, end, &f) == 1) {
    switch (f.field) {
    case ADM_SESSION_PASSKEY:
      if (f.wire == 2 && f.len <= sizeof(session_key)) {
        memcpy(session_key, f.data, f.len);
        session_key_len = f.len;
        if (pref_verbose)
          sysmsg("cached session passkey (%zu bytes)", f.len);
      }
      break;
    case ADM_GET_CHANNEL_RESP:
      if (f.wire == 2) {
        handle_channel(f.data, f.len);
        if (pref_verbose)
          sysmsg("channel updated");
      }
      break;
    case ADM_GET_CONNSTATUS_RESP:
      if (f.wire == 2)
        handle_connstatus(f.data, f.len);
      break;
    case ADM_GET_CONFIG_RESP:
      if (f.wire == 2) {
        if (pend_type >= 0)
          pend_complete(f.data, f.len);
        else
          handle_config(f.data, f.len);
      }
      break;
    case ADM_GET_OWNER_RESP:
      if (f.wire != 2)
        break;
      {
        const unsigned char *q = f.data, *qe = f.data + f.len;
        struct node *me = node_intern(my_num);

        /*
         * Fold the reply straight into the node table. /whoami reads from
         * there, so a name set with /name shows up immediately instead of
         * waiting for the radio to re-announce itself on the mesh.
         */
        while (me != NULL && pb_next(&q, qe, &g) == 1) {
          if (g.wire != 2)
            continue;
          if (g.field == USER_LONG_NAME) {
            size_t l = g.len < sizeof(me->longname) - 1 ?
                g.len : sizeof(me->longname) - 1;
            memcpy(me->longname, g.data, l);
            me->longname[l] = '\0';
          } else if (g.field == USER_SHORT_NAME) {
            size_t l = g.len < sizeof(me->shortname) - 1 ?
                g.len : sizeof(me->shortname) - 1;
            memcpy(me->shortname, g.data, l);
            me->shortname[l] = '\0';
          }
        }
        fresh_got |= FRESH_OWNER;
      }
      break;
    default:
      if (pref_verbose)
        sysmsg("AdminMessage field %u (%zu bytes)", f.field, f.len);
      break;
    }
  }
}

static void
handle_data(uint32_t from, uint32_t to, int chanidx,
    const unsigned char *b, size_t n)
{
  const unsigned char *p = b, *end = b + n;
  const unsigned char *payload = NULL;
  size_t plen = 0, i;
  uint64_t portnum = 0;
  struct pbfield f;
  char ts[16], text[MAX_TEXT + 1];

  while (pb_next(&p, end, &f) == 1) {
    if (f.field == DATA_PORTNUM && f.wire == 0)
      portnum = f.varint;
    else if (f.field == DATA_PAYLOAD && f.wire == 2) {
      payload = f.data;
      plen = f.len;
    }
  }
  if (portnum == PORT_NODEINFO && payload != NULL) {
    /*
     * A NODEINFO_APP payload is a bare User. Without this, any node that
     * joins after our config dump stays a bare hex id forever.
     */
    struct node *nd = node_intern(from);
    const unsigned char *q = payload, *qe = payload + plen;
    struct pbfield g;
    int fresh;

    if (nd == NULL)
      return;
    fresh = nd->shortname[0] == '\0';
    while (pb_next(&q, qe, &g) == 1) {
      if (g.wire != 2)
        continue;
      if (g.field == USER_LONG_NAME) {
        size_t l = g.len < sizeof(nd->longname) - 1 ?
            g.len : sizeof(nd->longname) - 1;
        memcpy(nd->longname, g.data, l);
        nd->longname[l] = '\0';
      } else if (g.field == USER_SHORT_NAME) {
        size_t l = g.len < sizeof(nd->shortname) - 1 ?
            g.len : sizeof(nd->shortname) - 1;
        memcpy(nd->shortname, g.data, l);
        nd->shortname[l] = '\0';
      }
    }
    if (fresh && nd->shortname[0])
      sysmsg("%s joined (!%08x)", node_str(from), from);
    else if (pref_verbose)
      sysmsg("nodeinfo from %s", node_str(from));
    return;
  }
  if (portnum == PORT_ADMIN && payload != NULL) {
    handle_admin(payload, plen);
    return;
  }
  if (portnum == PORT_ROUTING && payload != NULL) {
    handle_routing(payload, plen);
    return;
  }
  if (portnum != PORT_TEXT || payload == NULL) {
    if (pref_verbose)
      sysmsg("%s: portnum %llu, %zu bytes", node_str(from),
          (unsigned long long)portnum, plen);
    return;
  }
  if (is_muted(from)) {
    if (pref_verbose)
      sysmsg("(muted %s)", node_str(from));
    return;
  }
  if (plen > MAX_TEXT)
    plen = MAX_TEXT;
  for (i = 0; i < plen; i++)
    text[i] = (payload[i] >= 0x20 || payload[i] == '\t') ?
        (char)payload[i] : '.';
  text[plen] = '\0';

  stamp(ts, sizeof(ts));
  if (to == my_num && my_num != 0)
    emit("%s%s%s*%s*%s %s", col(C_TIME), ts, col(C_DM),
        node_str(from), col(C_RESET), text);
  else
    emit("%s%s%s%s <%s>%s %s", col(C_TIME), ts, col(C_CHAN),
        chan_str(chanidx), node_str(from), col(C_RESET), text);
}

static void
handle_packet(const unsigned char *b, size_t n)
{
  const unsigned char *p = b, *end = b + n;
  const unsigned char *decoded = NULL;
  size_t dlen = 0;
  uint32_t from = 0, to = 0;
  int chanidx = 0, encrypted = 0;
  struct pbfield f;

  while (pb_next(&p, end, &f) == 1) {
    switch (f.field) {
    case MP_FROM:
      if (f.wire == 5)
        from = f.fix32;
      break;
    case MP_TO:
      if (f.wire == 5)
        to = f.fix32;
      break;
    case MP_CHANNEL:
      if (f.wire == 0)
        chanidx = (int)f.varint;
      break;
    case MP_DECODED:
      if (f.wire == 2) {
        decoded = f.data;
        dlen = f.len;
      }
      break;
    case MP_ENCRYPTED:
      encrypted = 1;
      break;
    default:
      break;
    }
  }
  if (decoded != NULL)
    handle_data(from, to, chanidx, decoded, dlen);
  else if (encrypted && pref_verbose)
    sysmsg("encrypted packet from !%08x on channel %d (no key)",
        from, chanidx);
}

static void
handle_nodeinfo(const unsigned char *b, size_t n)
{
  const unsigned char *p = b, *end = b + n;
  const unsigned char *user = NULL;
  size_t ulen = 0;
  uint32_t num = 0;
  struct node *nd;
  struct pbfield f, g;

  while (pb_next(&p, end, &f) == 1) {
    if (f.field == 1 && f.wire == 0)
      num = (uint32_t)f.varint;
    else if (f.field == 2 && f.wire == 2) {
      user = f.data;
      ulen = f.len;
    }
  }
  if (num == 0)
    return;
  nd = node_intern(num);
  if (nd == NULL)
    return;
  if (user == NULL)
    return;

  p = user;
  end = user + ulen;
  while (pb_next(&p, end, &g) == 1) {
    if (g.wire != 2)
      continue;
    if (g.field == 2) { /* long_name */
      size_t l = g.len < sizeof(nd->longname) - 1 ?
          g.len : sizeof(nd->longname) - 1;
      memcpy(nd->longname, g.data, l);
      nd->longname[l] = '\0';
    } else if (g.field == 3) {  /* short_name */
      size_t l = g.len < sizeof(nd->shortname) - 1 ?
          g.len : sizeof(nd->shortname) - 1;
      memcpy(nd->shortname, g.data, l);
      nd->shortname[l] = '\0';
    }
  }
}

static void
handle_channel(const unsigned char *b, size_t n)
{
  const unsigned char *p = b, *end = b + n;
  const unsigned char *set = NULL;
  size_t slen = 0, i;
  int idx = 0, role = 0;
  struct pbfield f, g;
  char name[20];

  name[0] = '\0';
  while (pb_next(&p, end, &f) == 1) {
    if (f.field == 1 && f.wire == 0)
      idx = (int)f.varint;
    else if (f.field == 2 && f.wire == 2) {
      set = f.data;
      slen = f.len;
    } else if (f.field == 3 && f.wire == 0)
      role = (int)f.varint;
  }
  if (set != NULL) {
    p = set;
    end = set + slen;
    while (pb_next(&p, end, &g) == 1)
      if (g.field == 3 && g.wire == 2) {
        size_t l = g.len < sizeof(name) - 1 ?
            g.len : sizeof(name) - 1;
        memcpy(name, g.data, l);
        name[l] = '\0';
      }
  }
  if (role == ROLE_DISABLED) {
    for (i = 0; i < MAX_CHANS; i++)
      if (chans[i].used && chans[i].index == idx)
        chans[i].used = 0;
    return;
  }
  if (idx < 0 || idx >= MAX_CHANS)
    return;
  for (i = 0; i < MAX_CHANS; i++)
    if (!chans[i].used || chans[i].index == idx) {
      chans[i].used = 1;
      chans[i].index = idx;
      chans[i].role = role;
      snprintf(chans[i].name, sizeof(chans[i].name), "%s", name);
      chans[i].rawlen = 0;
      if (set != NULL && slen <= sizeof(chans[i].raw)) {
        memcpy(chans[i].raw, set, slen);
        chans[i].rawlen = slen;
      }
      return;
    }
}

/*
 * FromRadio.config carries exactly one Config oneof member. Field 6 is
 * LoRaConfig; within it field 1 is use_preset and field 2 is modem_preset.
 * Both are absent when zero, so an unadorned LoRaConfig means LongFast.
 */
static void
handle_config(const unsigned char *b, size_t n)
{
  const unsigned char *p = b, *end = b + n;
  struct pbfield f, g;

  while (pb_next(&p, end, &f) == 1) {
    if (f.field == CFG_FIELD(CFGTYPE_DEVICE) && f.wire == 2) {
      const unsigned char *q = f.data, *qe = f.data + f.len;

      dev_seen = 1;
      fresh_got |= FRESH_DEV;
      dev_led_off = 0;
      while (pb_next(&q, qe, &g) == 1)
        if (g.field == DEV_LED_OFF && g.wire == 0)
          dev_led_off = g.varint != 0;
      continue;
    }
    if (f.field == CFG_FIELD(CFGTYPE_NETWORK) && f.wire == 2) {
      const unsigned char *q = f.data, *qe = f.data + f.len;

      net_seen = 1;
      fresh_got |= FRESH_NET;
      net_wifi_on = 0;
      net_ssid[0] = '\0';
      while (pb_next(&q, qe, &g) == 1) {
        if (g.field == NET_WIFI_ENABLED && g.wire == 0)
          net_wifi_on = g.varint != 0;
        else if (g.field == NET_WIFI_SSID && g.wire == 2) {
          size_t l = g.len < sizeof(net_ssid) - 1 ?
              g.len : sizeof(net_ssid) - 1;
          memcpy(net_ssid, g.data, l);
          net_ssid[l] = '\0';
        }
      }
      continue;
    }
    if (f.field == CFG_FIELD(CFGTYPE_BLUETOOTH) && f.wire == 2) {
      const unsigned char *q = f.data, *qe = f.data + f.len;

      bt_seen = 1;
      fresh_got |= FRESH_BT;
      bt_on = 0;
      while (pb_next(&q, qe, &g) == 1)
        if (g.field == BT_ENABLED && g.wire == 0)
          bt_on = g.varint != 0;
      continue;
    }
    if (f.field != CFG_FIELD(CFGTYPE_LORA) || f.wire != 2)
      continue;
    lora_seen = 1;
    fresh_got |= FRESH_LORA;
    if (f.len <= sizeof(lora_raw)) {
      memcpy(lora_raw, f.data, f.len);
      lora_rawlen = f.len;
    }
    lora_use_preset = 0;
    lora_preset = 0;
    p = f.data;
    end = f.data + f.len;
    while (pb_next(&p, end, &g) == 1) {
      if (g.field == 1 && g.wire == 0)
        lora_use_preset = g.varint != 0;
      else if (g.field == 2 && g.wire == 0)
        lora_preset = (int)g.varint;
      else if (g.field == LORA_REGION && g.wire == 0)
        lora_region = (int)g.varint;
    }
    if (pref_verbose)
      sysmsg("lora: use_preset=%d preset=%d (%s)",
          lora_use_preset, lora_preset, preset_str());
    return;
  }
}

static void
handle_metadata(const unsigned char *b, size_t n)
{
  const unsigned char *p = b, *end = b + n;
  struct pbfield f;

  while (pb_next(&p, end, &f) == 1) {
    switch (f.field) {
    case 1:                             /* firmware_version, string */
      if (f.wire == 2) {
        size_t l = f.len < sizeof(fw_version) - 1 ?
            f.len : sizeof(fw_version) - 1;
        memcpy(fw_version, f.data, l);
        fw_version[l] = '\0';
      }
      break;
    case 4:                             /* hasWifi */
      if (f.wire == 0)
        has_wifi = f.varint != 0;
      break;
    case 5:                             /* hasBluetooth */
      if (f.wire == 0)
        has_bt = f.varint != 0;
      break;
    case 6:                             /* hasEthernet */
      if (f.wire == 0)
        has_eth = f.varint != 0;
      break;
    case 9:                             /* hw_model */
      if (f.wire == 0)
        hw_model = (int)f.varint;
      break;
    default:
      break;
    }
  }
}

static uint32_t
handle_fromradio(const unsigned char *b, size_t n)
{
  const unsigned char *p = b, *end = b + n;
  uint32_t complete = 0;
  struct pbfield f, g;

  while (pb_next(&p, end, &f) == 1) {
    switch (f.field) {
    case FR_PACKET:
      if (f.wire == 2)
        handle_packet(f.data, f.len);
      break;
    case FR_MY_INFO:
      if (f.wire == 2) {
        const unsigned char *q = f.data;
        while (pb_next(&q, f.data + f.len, &g) == 1)
          if (g.field == 1 && g.wire == 0)
            my_num = (uint32_t)g.varint;
      }
      break;
    case FR_NODE_INFO:
      if (f.wire == 2)
        handle_nodeinfo(f.data, f.len);
      break;
    case FR_CONFIG:
      if (f.wire == 2)
        handle_config(f.data, f.len);
      break;
    case FR_METADATA:
      if (f.wire == 2)
        handle_metadata(f.data, f.len);
      break;
    case FR_CHANNEL:
      if (f.wire == 2)
        handle_channel(f.data, f.len);
      break;
    case FR_CONFIG_COMPLETE:
      if (f.wire == 0)
        complete = (uint32_t)f.varint;
      break;
    default:
      if (pref_verbose)
        sysmsg("FromRadio field %u (%zu bytes)",
            f.field, f.len);
      break;
    }
  }
  return complete;
}

/* ====================================================================== */
/* base64url                                                              */
/* ====================================================================== */

static const char b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* URL-safe alphabet, no padding -- what meshtastic.org/e/# uses. */
static size_t
b64url_encode(char *out, size_t outsz, const unsigned char *in, size_t n)
{
  size_t i, o = 0;

  for (i = 0; i < n; i += 3) {
    unsigned long v = (unsigned long)in[i] << 16;
    int have = 1;

    if (i + 1 < n) { v |= (unsigned long)in[i + 1] << 8; have = 2; }
    if (i + 2 < n) { v |= in[i + 2]; have = 3; }
    if (o + 4 >= outsz)
      break;
    out[o++] = b64chars[(v >> 18) & 0x3f];
    out[o++] = b64chars[(v >> 12) & 0x3f];
    if (have > 1)
      out[o++] = b64chars[(v >> 6) & 0x3f];
    if (have > 2)
      out[o++] = b64chars[v & 0x3f];
  }
  out[o] = '\0';
  return o;
}

/* Accepts both alphabets and tolerates missing or present padding. */
static int
b64url_decode(unsigned char *out, size_t outsz, const char *in)
{
  unsigned long v = 0;
  int bits = 0;
  size_t o = 0;

  for (; *in != '\0'; in++) {
    const char *pos;
    int d;

    if (*in == '=' || *in == '\n' || *in == '\r')
      continue;
    if (*in == '-')
      d = 62;
    else if (*in == '_')
      d = 63;
    else if (*in == '+')
      d = 62;
    else if (*in == '/')
      d = 63;
    else if ((pos = strchr(b64chars, *in)) != NULL && *in != '\0')
      d = (int)(pos - b64chars);
    else
      return -1;
    v = (v << 6) | (unsigned)d;
    if ((bits += 6) >= 8) {
      bits -= 8;
      if (o >= outsz)
        return -1;
      out[o++] = (unsigned char)((v >> bits) & 0xff);
    }
  }
  return (int)o;
}

/* ====================================================================== */
/* config read-modify-write                                               */
/* ====================================================================== */

/*
 * set_config replaces the WHOLE sub-config, so writing a LoRaConfig that
 * contains only `region` would silently wipe the modem preset, TX power
 * and hop limit. Every write therefore has to be read-modify-write:
 *
 *   get_config_request(type) -> get_config_response -> edit -> set_config
 *
 * The edit is done on the raw protobuf bytes: copy every field except the
 * ones being replaced, then append the new values. That needs no schema,
 * which means fields belonging to firmware newer than this build survive
 * untouched instead of being destroyed.
 */
static int pend_type = -1;              /* ConfigType we asked for       */
static uint32_t pend_drop;              /* bitmask of fields to replace  */
static unsigned char pend_new[192];     /* their new encodings           */
static size_t pend_newlen;
static char pend_desc[80];

static void
pend_clear(void)
{
  pend_type = -1;
  pend_drop = 0;
  pend_newlen = 0;
  pend_desc[0] = '\0';
}

/* Queue a field replacement for the edit in progress. */
static int
pend_set_bytes(uint32_t field, unsigned wire, const unsigned char *val,
    size_t vlen)
{
  size_t need = 10 + vlen;

  if (field >= 32 || pend_newlen + need > sizeof(pend_new))
    return -1;
  pend_drop |= 1u << field;
  pend_newlen += pb_tag(pend_new + pend_newlen, field, wire);
  if (wire == 2)
    pend_newlen += pb_varint(pend_new + pend_newlen, vlen);
  memcpy(pend_new + pend_newlen, val, vlen);
  pend_newlen += vlen;
  return 0;
}

static int
pend_set_varint(uint32_t field, uint64_t v)
{
  unsigned char tmp[10];
  size_t n = pb_varint(tmp, v);

  return pend_set_bytes(field, 0, tmp, n);
}

static int
pend_set_string(uint32_t field, const char *sv)
{
  return pend_set_bytes(field, 2, (const unsigned char *)sv, strlen(sv));
}

/* Ask the radio for a sub-config; the reply completes the edit. */
static int
pend_begin(int cfgtype, const char *desc)
{
  unsigned char pb[8];
  size_t n = 0;

  n += pb_tag(pb + n, ADM_GET_CONFIG_REQ, 0);
  n += pb_varint(pb + n, (uint64_t)cfgtype);
  pend_type = cfgtype;
  if (desc != pend_desc)
    snprintf(pend_desc, sizeof(pend_desc), "%s", desc);
  if (send_admin(pb, n) < 0) {
    pend_clear();
    return -1;
  }
  return 0;
}

/*
 * A get_config_response arrived while an edit was pending. Rebuild the
 * sub-config with our replacements and send it back.
 */
static void
pend_complete(const unsigned char *cfg, size_t n)
{
  const unsigned char *p = cfg, *end = cfg + n, *sub = NULL;
  unsigned char out[320], wrapped[352], pb[384];
  size_t sublen = 0, o = 0, w = 0, i = 0;
  uint32_t want = CFG_FIELD(pend_type);
  struct pbfield f;

  while (pb_next(&p, end, &f) == 1)
    if (f.field == want && f.wire == 2) {
      sub = f.data;
      sublen = f.len;
    }
  if (sub == NULL) {
    errmsg("radio returned no config for type %d", pend_type);
    pend_clear();
    return;
  }

  /* Copy every field we are not replacing, verbatim. */
  p = sub;
  end = sub + sublen;
  while (pb_next(&p, end, &f) == 1) {
    if (f.field < 32 && (pend_drop & (1u << f.field)))
      continue;
    if (o + 24 + f.len > sizeof(out)) {
      errmsg("config too large to edit safely");
      pend_clear();
      return;
    }
    o += pb_tag(out + o, f.field, f.wire);
    switch (f.wire) {
    case 0:
      o += pb_varint(out + o, f.varint);
      break;
    case 2:
      o += pb_varint(out + o, f.len);
      memcpy(out + o, f.data, f.len);
      o += f.len;
      break;
    case 5:
      out[o++] = (unsigned char)(f.fix32 & 0xff);
      out[o++] = (unsigned char)((f.fix32 >> 8) & 0xff);
      out[o++] = (unsigned char)((f.fix32 >> 16) & 0xff);
      out[o++] = (unsigned char)((f.fix32 >> 24) & 0xff);
      break;
    default:
      /* Cannot re-encode what we cannot decode -- refuse rather than lose it. */
      errmsg("config contains wire type %u; refusing to rewrite", f.wire);
      pend_clear();
      return;
    }
  }

  if (o + pend_newlen > sizeof(out)) {
    errmsg("config too large to edit safely");
    pend_clear();
    return;
  }
  memcpy(out + o, pend_new, pend_newlen);
  o += pend_newlen;

  /* Config { <sub> = out } */
  w += pb_tag(wrapped + w, want, 2);
  w += pb_varint(wrapped + w, o);
  memcpy(wrapped + w, out, o);
  w += o;

  /* AdminMessage { set_config = Config } */
  i += pb_tag(pb + i, ADM_SET_CONFIG, 2);
  i += pb_varint(pb + i, w);
  memcpy(pb + i, wrapped, w);
  i += w;

  sysmsg("%s (%zu bytes preserved, %zu replaced)", pend_desc,
      o - pend_newlen, pend_newlen);
  if (send_admin(pb, i) == 0) {
    int t = pend_type;
    unsigned char req[8];
    size_t r = 0;

    /*
     * Read the sub-config back. pend_type is cleared first so the reply
     * lands in handle_config (refreshing the local cache) rather than
     * starting another edit cycle. Without this /whoami keeps reporting
     * whatever arrived during the initial config dump.
     */
    pend_clear();
    r += pb_tag(req + r, ADM_GET_CONFIG_REQ, 0);
    r += pb_varint(req + r, (uint64_t)t);
    send_admin(req, r);
    return;
  }
  pend_clear();
}

/* ====================================================================== */
/* commands                                                               */
/* ====================================================================== */

static void
cmd_help(void)
{
  hdrmsg("%-17s %s", "command", "description");
  sysmsg("%-17s %s", "/join #chan|N", "switch channel");
  sysmsg("%-17s %s", "/query @node", "direct-message a node (bare /query clears)");
  sysmsg("%-17s %s", "/msg @node text", "one-off direct message");
  sysmsg("%-17s %s", "/nodes", "list known nodes");
  sysmsg("%-17s %s", "/chans", "list channels");
  sysmsg("%-17s %s", "/chan add <name>", "create a channel with a random key");
  sysmsg("%-17s %s", "/chan del <ch>", "disable a channel slot");
  sysmsg("%-17s %s", "/chan share [ch]", "print a URL others can join with");
  sysmsg("%-17s %s", "/chan join <url>", "join a channel from a shared URL");
  sysmsg("%-17s %s", "/mute [node]", "hide a node; /mute clear [node] to undo");
  sysmsg("%-17s %s", "/whoami", "read this node's settings from the radio");
  sysmsg("%-17s %s", "/set [key val]",
      "local prefs: time|names|hex|color|verbose|passkey");
  hdrmsg("%-17s %s", "radio config", "writes to the node");
  sysmsg("%-17s %s", "/name <long> [sh]", "set the node's long and short name");
  sysmsg("%-17s %s", "/region [name]", "set LoRa region (bare /region lists them)");
  sysmsg("%-17s %s", "/wifi <ssid> [pw]", "join a network; /wifi off to disable");
  sysmsg("%-17s %s", "/bt on|off", "enable or disable bluetooth");
  sysmsg("%-17s %s", "/led on|off", "the onboard heartbeat LED");
  sysmsg("%-17s %s", "/reboot [secs]", "reboot the node (default 5s)");
  sysmsg("%-17s %s", "/save", "write settings to ~/.meshtermrc");
  sysmsg("%-17s %s", "/quit", "disconnect and exit");
}

static void
cmd_nodes(void)
{
  size_t i, count = 0;

  hdrmsg("%-10s %-8s %s", "id", "short", "long name");
  for (i = 0; i < MAX_NODES; i++) {
    if (!nodes[i].used)
      continue;
    count++;
    sysmsg("!%08x  %-8s %s%s", nodes[i].num,
        nodes[i].shortname[0] ? nodes[i].shortname : "-",
        nodes[i].longname,
        nodes[i].num == my_num ? "  (this node)" : "");
  }
  sysmsg("%zu node%s known", count, count == 1 ? "" : "s");
}

static void
cmd_chans(void)
{
  size_t i;

  hdrmsg("%-2s %-16s %s", "#", "name", "role");
  for (i = 0; i < MAX_CHANS; i++) {
    if (!chans[i].used)
      continue;
    sysmsg("%-2d %-16s %s%s", chans[i].index,
        chans[i].name[0] ? chans[i].name : chan_str(chans[i].index),
        chans[i].role == ROLE_PRIMARY ? "primary" : "secondary",
        chans[i].index == cur_chan ? "  *" : "");
  }
}

static int
setpref(const char *key, const char *val)
{
  int on;

  if (strcasecmp(val, "on") == 0 || strcasecmp(val, "yes") == 0 ||
      strcmp(val, "1") == 0)
    on = 1;
  else if (strcasecmp(val, "off") == 0 || strcasecmp(val, "no") == 0 ||
      strcmp(val, "0") == 0)
    on = 0;
  else
    return -1;

  if (strcasecmp(key, "time") == 0 || strcasecmp(key, "timestamps") == 0)
    pref_time = on;
  else if (strcasecmp(key, "names") == 0)
    pref_name = on;
  else if (strcasecmp(key, "hex") == 0)
    pref_hex = on;
  else if (strcasecmp(key, "color") == 0 ||
      strcasecmp(key, "colour") == 0)
    pref_color = on;
  else if (strcasecmp(key, "verbose") == 0 ||
      strcasecmp(key, "debug") == 0)
    pref_verbose = on;
  else if (strcasecmp(key, "passkey") == 0)
    pref_passkey = on;
  else
    return -1;
  return 0;
}

static void
cmd_mute(char *args)
{
  uint32_t n;
  size_t i, j;
  char *target;

  if (args == NULL || *args == '\0') {
    hdrmsg("muted nodes");
    if (nmuted == 0) {
      sysmsg("(none)");
      return;
    }
    for (i = 0; i < nmuted; i++)
      sysmsg("!%08x  %s", muted[i], node_str(muted[i]));
    return;
  }

  if (strncasecmp(args, "clear", 5) == 0) {
    target = args + 5;
    while (*target == ' ' || *target == '\t')
      target++;
    if (*target == '\0') {
      nmuted = 0;
      sysmsg("unmuted everyone");
      return;
    }
    if (*target == '@')
      target++;
    if ((n = node_lookup(target)) == 0) {
      errmsg("unknown node: %s", target);
      return;
    }
    for (i = 0, j = 0; i < nmuted; i++)
      if (muted[i] != n)
        muted[j++] = muted[i];
    if (j == nmuted)
      errmsg("%s was not muted", node_str(n));
    else
      sysmsg("unmuted %s", node_str(n));
    nmuted = j;
    return;
  }

  target = args;
  if (*target == '@')
    target++;
  if ((n = node_lookup(target)) == 0) {
    errmsg("unknown node: %s -- try !hexid, or /nodes to list", target);
    return;
  }
  if (n == my_num) {
    errmsg("refusing to mute this node");
    return;
  }
  if (is_muted(n)) {
    sysmsg("%s is already muted", node_str(n));
    return;
  }
  if (nmuted >= MAX_MUTED) {
    errmsg("mute list full (%d)", MAX_MUTED);
    return;
  }
  muted[nmuted++] = n;
  sysmsg("muted %s", node_str(n));
}

static void
cmd_set(char *args)
{
  char *key, *val;

  if (args == NULL || *args == '\0') {
    hdrmsg("settings");
    sysmsg("time %s   names %s   hex %s   color %s   verbose %s   passkey %s",
        pref_time ? "on" : "off", pref_name ? "on" : "off",
        pref_hex ? "on" : "off", pref_color ? "on" : "off",
        pref_verbose ? "on" : "off", pref_passkey ? "on" : "off");
    return;
  }
  key = strtok(args, " \t");
  val = strtok(NULL, " \t");
  if (key == NULL || val == NULL) {
    errmsg("usage: /set <time|names|hex|color|verbose> <on|off>");
    return;
  }
  if (setpref(key, val) < 0)
    errmsg("unknown setting or value: %s %s", key, val);
  else
    sysmsg("%s = %s", key, val);
}

static void
rcpath(char *out, size_t n)
{
  const char *home = getenv("HOME");

  snprintf(out, n, "%s/.meshtermrc", home != NULL ? home : ".");
}

static void
load_rc(const char *path)
{
  char line[256], p[512];
  FILE *fp;

  if (path == NULL) {
    rcpath(p, sizeof(p));
    path = p;
  }
  if ((fp = fopen(path, "r")) == NULL)
    return;
  while (fgets(line, sizeof(line), fp) != NULL) {
    char *key, *val, *hash;

    if ((hash = strchr(line, '#')) != NULL)
      *hash = '\0';
    key = strtok(line, " \t\r\n");
    val = strtok(NULL, " \t\r\n");
    if (key == NULL || val == NULL)
      continue;
    if (strcasecmp(key, "mute") == 0) {
      unsigned long v = strtoul(val[0] == '!' ? val + 1 : val, NULL, 16);

      if (v != 0 && nmuted < MAX_MUTED)
        muted[nmuted++] = (uint32_t)v;
      continue;
    }
    setpref(key, val);
  }
  fclose(fp);
}

static void
cmd_save(void)
{
  char p[512];
  FILE *fp;

  rcpath(p, sizeof(p));
  if ((fp = fopen(p, "w")) == NULL) {
    errmsg("%s: %s", p, strerror(errno));
    return;
  }
  fprintf(fp, "# meshterm settings\n");
  fprintf(fp, "time %s\n", pref_time ? "on" : "off");
  fprintf(fp, "names %s\n", pref_name ? "on" : "off");
  fprintf(fp, "hex %s\n", pref_hex ? "on" : "off");
  fprintf(fp, "color %s\n", pref_color ? "on" : "off");
  fprintf(fp, "verbose %s\n", pref_verbose ? "on" : "off");
  fprintf(fp, "passkey %s\n", pref_passkey ? "on" : "off");
  {
    size_t i;

    for (i = 0; i < nmuted; i++)
      fprintf(fp, "mute !%08x\n", muted[i]);
  }
  fclose(fp);
  sysmsg("saved %s", p);
}

static void
send_get_owner(void)
{
  unsigned char pb[8];
  size_t n = 0;

  n += pb_tag(pb + n, ADM_GET_OWNER_REQ, 0);
  pb[n++] = 1;
  send_admin(pb, n);
}

static void
send_get_config(int cfgtype)
{
  unsigned char pb[8];
  size_t n = 0;

  n += pb_tag(pb + n, ADM_GET_CONFIG_REQ, 0);
  n += pb_varint(pb + n, (uint64_t)cfgtype);
  send_admin(pb, n);
}

/*
 * Ask for everything /whoami displays and wait briefly for the replies.
 * Skipped while a config edit is in flight, since those replies belong to
 * the edit rather than to us.
 */
static void
refresh_status(void)
{
  int waited;

  if (pend_type >= 0 || my_num == 0)
    return;
  fresh_got = 0;
  fresh_want = FRESH_OWNER | FRESH_LORA | FRESH_NET | FRESH_BT | FRESH_DEV;
  if (has_wifi)
    fresh_want |= FRESH_CONN;

  send_get_owner();
  send_get_config(CFGTYPE_DEVICE);
  send_get_config(CFGTYPE_LORA);
  send_get_config(CFGTYPE_NETWORK);
  send_get_config(CFGTYPE_BLUETOOTH);
  if (has_wifi)
    cmd_net_quiet();

  /*
   * Wait only briefly. Not every firmware answers every admin request --
   * anything unanswered would otherwise stall the command for the whole
   * timeout, which is worse than showing a cached value.
   */
  for (waited = 0; waited < FRESH_WAIT_MS && !quitflag &&
      (fresh_got & fresh_want) != fresh_want; waited += 100) {
    if (pump_ms(100) < 0)
      break;
  }
  fresh_want = 0;
}

/*
 * set_owner takes a whole User. We send only the name fields; the firmware
 * merges them into the existing record rather than replacing it, so the
 * node id, key and hardware model are left alone.
 */
static void
cmd_owner_set(char *args)
{
  unsigned char pb[128], user[96];
  size_t n = 0, u = 0, ll, sl;
  char *longn, *shortn;

  if (args == NULL || *args == '\0') {
    errmsg("usage: /name <long name> [short]");
    return;
  }
  longn = args;
  shortn = strrchr(args, ' ');
  /* A trailing word of <= 4 chars is taken as the short name. */
  if (shortn != NULL && strlen(shortn + 1) <= SHORTNAME_MAX &&
      shortn != args) {
    *shortn++ = '\0';
  } else {
    shortn = NULL;
  }

  ll = strlen(longn);
  if (ll == 0 || ll > LONGNAME_MAX) {
    errmsg("long name must be 1-%d bytes", LONGNAME_MAX);
    return;
  }
  if (ll > 25)
    sysmsg("note: firmware 2.8+ truncates long names to 25 bytes");

  u += pb_tag(user + u, USER_LONG_NAME, 2);
  u += pb_varint(user + u, ll);
  memcpy(user + u, longn, ll);
  u += ll;
  if (shortn != NULL && (sl = strlen(shortn)) > 0) {
    u += pb_tag(user + u, USER_SHORT_NAME, 2);
    u += pb_varint(user + u, sl);
    memcpy(user + u, shortn, sl);
    u += sl;
  }

  n += pb_tag(pb + n, ADM_SET_OWNER, 2);
  n += pb_varint(pb + n, u);
  memcpy(pb + n, user, u);
  n += u;

  if (send_admin(pb, n) == 0) {
    struct node *me = node_intern(my_num);

    sysmsg("set owner: long=\"%s\"%s%s%s", longn,
        shortn ? " short=\"" : "", shortn ? shortn : "",
        shortn ? "\"" : "");
    /*
     * Record what we sent. Not every firmware answers get_owner_request,
     * so waiting for a read-back before believing our own write leaves
     * /whoami showing the old name indefinitely. The request still goes
     * out and will correct us if the radio disagrees.
     */
    if (me != NULL) {
      snprintf(me->longname, sizeof(me->longname), "%s", longn);
      if (shortn != NULL)
        snprintf(me->shortname, sizeof(me->shortname), "%s", shortn);
    }
    send_get_owner();
  }
}

static const char *
region_str(int r)
{
  static char buf[24];

  if (r >= 0 && r < NREGIONS)
    return region_names[r];
  snprintf(buf, sizeof(buf), "region%d", r);
  return buf;
}

static void
cmd_region(char *args)
{
  char *endp;
  long v = -1;
  int i;

  if (args == NULL || *args == '\0') {
    hdrmsg("regions");
    for (i = 0; i < NREGIONS; i += 6)
      sysmsg("%s %s %s %s %s %s",
          region_names[i],
          i + 1 < NREGIONS ? region_names[i + 1] : "",
          i + 2 < NREGIONS ? region_names[i + 2] : "",
          i + 3 < NREGIONS ? region_names[i + 3] : "",
          i + 4 < NREGIONS ? region_names[i + 4] : "",
          i + 5 < NREGIONS ? region_names[i + 5] : "");
    sysmsg("usage: /region <name|number>");
    return;
  }
  for (i = 0; i < NREGIONS; i++)
    if (strcasecmp(args, region_names[i]) == 0) {
      v = i;
      break;
    }
  if (v < 0) {
    v = strtol(args, &endp, 10);
    if (*endp != '\0' || v < 0 || v > 255) {
      errmsg("unknown region %s -- /region with no argument lists them",
          args);
      return;
    }
  }
  pend_clear();
  if (pend_set_varint(LORA_REGION, (uint64_t)v) < 0) {
    errmsg("internal: edit buffer full");
    return;
  }
  snprintf(pend_desc, sizeof(pend_desc), "region -> %s (%ld)",
      region_str((int)v), v);
  sysmsg("confirm on the device screen that it reads %s", region_str((int)v));
  pend_begin(CFGTYPE_LORA, pend_desc);
}

static void
cmd_wifi(char *args)
{
  char *ssid, *psk;

  if (args == NULL || *args == '\0') {
    errmsg("usage: /wifi <ssid> [password]   |   /wifi off");
    return;
  }
  pend_clear();

  if (strcasecmp(args, "off") == 0) {
    static time_t confirm_until;

    /*
     * Over TCP this is the branch we are sitting on. Warn once and make
     * the operator repeat the command -- refusing outright would remove a
     * legitimate capability (switching a tower node back to serial before
     * driving out to it).
     */
    if (is_tcp && time(NULL) > confirm_until) {
      errmsg("you are connected over TCP; this will disconnect you");
      sysmsg("the node will only be reachable over serial afterwards");
      sysmsg("repeat /wifi off within 10s to confirm");
      confirm_until = time(NULL) + 10;
      pend_clear();
      return;
    }
    confirm_until = 0;
    if (pend_set_varint(NET_WIFI_ENABLED, 0) < 0) {
      errmsg("internal: edit buffer full");
      return;
    }
    sysmsg("disabling wifi -- the node will reboot");
    pend_begin(CFGTYPE_NETWORK, "wifi -> off");
    return;
  }

  ssid = args;
  psk = strchr(args, ' ');
  if (psk != NULL)
    *psk++ = '\0';
  if (strlen(ssid) > 32) {
    errmsg("ssid too long (max 32)");
    return;
  }
  if (psk != NULL && strlen(psk) > 64) {
    errmsg("password too long (max 64)");
    return;
  }
  if (pend_set_varint(NET_WIFI_ENABLED, 1) < 0 ||
      pend_set_string(NET_WIFI_SSID, ssid) < 0 ||
      pend_set_string(NET_WIFI_PSK, psk != NULL ? psk : "") < 0) {
    errmsg("internal: edit buffer full");
    return;
  }
  sysmsg("enabling wifi for \"%s\" -- this DISABLES bluetooth and reboots", ssid);
  sysmsg("the node takes 20-30s longer to boot the first time");
  sysmsg("when it comes back up, /whoami reports its address");
  pend_begin(CFGTYPE_NETWORK, "wifi -> on");
}

/* Lowest slot index 1..7 that no enabled channel occupies. */
static int
chan_free_slot(void)
{
  int idx;
  size_t i;

  for (idx = 1; idx < MAX_CHANS; idx++) {
    int taken = 0;

    for (i = 0; i < MAX_CHANS; i++)
      if (chans[i].used && chans[i].index == idx)
        taken = 1;
    if (!taken)
      return idx;
  }
  return -1;
}

static int
send_set_channel(int idx, int role, const unsigned char *settings, size_t slen)
{
  unsigned char pb[192], chn[160];
  size_t c = 0, n = 0;

  if (slen + 24 > sizeof(chn))
    return -1;
  c += pb_tag(chn + c, CH_INDEX, 0);
  c += pb_varint(chn + c, (uint64_t)idx);
  if (settings != NULL && slen > 0) {
    c += pb_tag(chn + c, CH_SETTINGS, 2);
    c += pb_varint(chn + c, slen);
    memcpy(chn + c, settings, slen);
    c += slen;
  }
  if (role != 0) {
    c += pb_tag(chn + c, CH_ROLE, 0);
    c += pb_varint(chn + c, (uint64_t)role);
  }
  n += pb_tag(pb + n, ADM_SET_CHANNEL, 2);
  n += pb_varint(pb + n, c);
  memcpy(pb + n, chn, c);
  n += c;
  return send_admin(pb, n);
}

/*
 * The channel index in get_channel_request is sent one-based: the firmware
 * subtracts one. A bare zero in that oneof would be indistinguishable from
 * an unset field.
 */
static void
send_get_channel(int idx)
{
  unsigned char pb[8];
  size_t n = 0;

  n += pb_tag(pb + n, ADM_GET_CHANNEL_REQ, 0);
  n += pb_varint(pb + n, (uint64_t)idx + 1);
  send_admin(pb, n);
}

static int
random_psk(unsigned char *out, size_t n)
{
  FILE *fp = fopen("/dev/urandom", "rb");
  size_t got;

  if (fp == NULL)
    return -1;
  got = fread(out, 1, n, fp);
  fclose(fp);
  return got == n ? 0 : -1;
}

static void
chan_add(char *name)
{
  unsigned char psk[PSK_BYTES], set[128];
  size_t l, c = 0;
  int idx;

  if (name == NULL || *name == '\0') {
    errmsg("usage: /chan add <name>");
    return;
  }
  if (*name == '#')
    name++;
  if ((l = strlen(name)) > 11) {
    errmsg("channel name must be 11 bytes or fewer");
    return;
  }
  if ((idx = chan_free_slot()) < 0) {
    errmsg("all 8 channel slots are in use");
    return;
  }
  if (random_psk(psk, sizeof(psk)) < 0) {
    errmsg("cannot read /dev/urandom for a key");
    return;
  }

  c += pb_tag(set + c, CHS_PSK, 2);
  c += pb_varint(set + c, sizeof(psk));
  memcpy(set + c, psk, sizeof(psk));
  c += sizeof(psk);
  c += pb_tag(set + c, CHS_NAME, 2);
  c += pb_varint(set + c, l);
  memcpy(set + c, name, l);
  c += l;

  if (send_set_channel(idx, ROLE_SECONDARY, set, c) == 0) {
    sysmsg("created #%s in slot %d with a random AES-256 key", name, idx);
    sysmsg("share it with /chan share %d -- others cannot join without the key",
        idx);
    send_get_channel(idx);
  }
}

static void
chan_del(const char *arg)
{
  int idx;

  if (arg == NULL || (idx = chan_lookup(arg)) < 0) {
    errmsg("usage: /chan del <#name|index>");
    return;
  }
  if (idx == 0) {
    errmsg("refusing to delete the primary channel");
    return;
  }
  if (send_set_channel(idx, ROLE_DISABLED, NULL, 0) == 0) {
    sysmsg("disabled slot %d", idx);
    if (cur_chan == idx) {
      cur_chan = 0;
      sysmsg("moved you to %s", chan_str(0));
    }
    send_get_channel(idx);
  }
}

static void
chan_share(const char *arg)
{
  unsigned char cset[320];
  char url[512];
  const struct chan *c;
  size_t n = 0;
  int idx = arg != NULL && *arg != '\0' ? chan_lookup(arg) : cur_chan;

  if (idx < 0 || (c = chan_find_index(idx)) == NULL || c->rawlen == 0) {
    errmsg("no settings cached for that channel -- try /chans");
    return;
  }
  n += pb_tag(cset + n, CSET_SETTINGS, 2);
  n += pb_varint(cset + n, c->rawlen);
  memcpy(cset + n, c->raw, c->rawlen);
  n += c->rawlen;
  if (lora_rawlen > 0 && n + lora_rawlen + 8 < sizeof(cset)) {
    /* Include the radio settings; without a matching preset and region
     * the other node is on a different waveform and hears nothing. */
    n += pb_tag(cset + n, CSET_LORA, 2);
    n += pb_varint(cset + n, lora_rawlen);
    memcpy(cset + n, lora_raw, lora_rawlen);
    n += lora_rawlen;
  }

  snprintf(url, sizeof(url), "%s", SHARE_PREFIX);
  b64url_encode(url + strlen(url), sizeof(url) - strlen(url), cset, n);
  hdrmsg("share %s", chan_str(idx));
  sysmsg("%s", url);
  sysmsg("anyone who opens this joins the channel -- treat it as the key");
}

static void
chan_join(char *url)
{
  unsigned char raw[512];
  const unsigned char *p, *end;
  struct pbfield f;
  char *frag, *q;
  int len, idx, added = 0;

  if (url == NULL || *url == '\0') {
    errmsg("usage: /chan join <meshtastic url>");
    return;
  }
  frag = strchr(url, '#');
  frag = (frag != NULL) ? frag + 1 : url;
  if ((q = strchr(frag, '?')) != NULL)
    *q = '\0';

  if ((len = b64url_decode(raw, sizeof(raw), frag)) <= 0) {
    errmsg("that does not decode as a channel URL");
    return;
  }
  p = raw;
  end = raw + len;
  while (pb_next(&p, end, &f) == 1) {
    if (f.field != CSET_SETTINGS || f.wire != 2)
      continue;
    if ((idx = chan_free_slot()) < 0) {
      errmsg("all 8 channel slots are in use");
      return;
    }
    if (send_set_channel(idx, ROLE_SECONDARY, f.data, f.len) == 0) {
      sysmsg("joined channel into slot %d", idx);
      send_get_channel(idx);
      added++;
    }
  }
  if (added == 0)
    errmsg("no channel settings found in that URL");
  else
    sysmsg("if you cannot hear anyone, check /whoami -- region and preset "
        "must match the sender");
}

static void
cmd_chan(char *args)
{
  char *verb, *rest;

  if (args == NULL || *args == '\0') {
    cmd_chans();
    return;
  }
  verb = strtok(args, " \t");
  rest = strtok(NULL, "");
  while (rest != NULL && (*rest == ' ' || *rest == '\t'))
    rest++;

  if (strcasecmp(verb, "add") == 0)
    chan_add(rest);
  else if (strcasecmp(verb, "del") == 0 || strcasecmp(verb, "rm") == 0)
    chan_del(rest);
  else if (strcasecmp(verb, "share") == 0)
    chan_share(rest);
  else if (strcasecmp(verb, "join") == 0)
    chan_join(rest);
  else
    errmsg("usage: /chan add|del|share|join");
}

static void
cmd_bt(char *args)
{
  int on;

  if (args == NULL || *args == '\0') {
    errmsg("usage: /bt on|off");
    return;
  }
  if (strcasecmp(args, "on") == 0)
    on = 1;
  else if (strcasecmp(args, "off") == 0)
    on = 0;
  else {
    errmsg("usage: /bt on|off");
    return;
  }
  pend_clear();
  if (pend_set_varint(BT_ENABLED, (uint64_t)on) < 0) {
    errmsg("internal: edit buffer full");
    return;
  }
  if (!on)
    sysmsg("disabling bluetooth frees memory and skips the boot-time wait");
  sysmsg("the node will reboot; serial is unaffected");
  pend_begin(CFGTYPE_BLUETOOTH, on ? "bluetooth -> on" : "bluetooth -> off");
}

static void
cmd_led(char *args)
{
  int on;

  if (args == NULL || *args == '\0') {
    errmsg("usage: /led on|off");
    return;
  }
  if (strcasecmp(args, "on") == 0)
    on = 1;
  else if (strcasecmp(args, "off") == 0)
    on = 0;
  else {
    errmsg("usage: /led on|off");
    return;
  }
  pend_clear();
  /* The stored field is inverted: led_heartbeat_disabled. */
  if (pend_set_varint(DEV_LED_OFF, on ? 0 : 1) < 0) {
    errmsg("internal: edit buffer full");
    return;
  }
  pend_begin(CFGTYPE_DEVICE, on ? "led -> on" : "led -> off");
}

static void
cmd_net_quiet(void)
{
  unsigned char pb[8];
  size_t n = 0;

  n += pb_tag(pb + n, ADM_GET_CONNSTATUS_REQ, 0);
  pb[n++] = 1;
  send_admin(pb, n);
}

static void
cmd_reboot(char *args)
{
  unsigned char pb[8];
  size_t n = 0;
  int secs = 5;

  if (args != NULL && *args != '\0')
    secs = atoi(args);
  if (secs < 0 || secs > 3600) {
    errmsg("reboot delay must be 0-3600 seconds");
    return;
  }
  n += pb_tag(pb + n, ADM_REBOOT_SECONDS, 0);
  n += pb_varint(pb + n, (uint64_t)secs);
  if (send_admin(pb, n) == 0)
    sysmsg("reboot requested in %ds -- the session will drop", secs);
}

static void
say(const char *text)
{
  char ts[16];

  if (text[0] == '\0')
    return;
  if (send_text(text, cur_dm != 0 ? cur_dm : BROADCAST,
      cur_dm != 0 ? 0 : cur_chan) < 0)
    return;
  stamp(ts, sizeof(ts));
  if (cur_dm != 0)
    emit("%s%s%s*-> %s*%s %s", col(C_TIME), ts, col(C_DM),
        node_str(cur_dm), col(C_RESET), text);
  else
    emit("%s%s%s%s <%s>%s %s", col(C_TIME), ts, col(C_ME),
        chan_str(cur_chan), my_num ? node_str(my_num) : "me",
        col(C_RESET), text);
}

/* Returns 1 if the caller should quit. */
static int
do_command(char *line)
{
  char *cmd, *args;

  cmd = strtok(line, " \t");
  args = strtok(NULL, "");
  while (args != NULL && (*args == ' ' || *args == '\t'))
    args++;

  if (cmd == NULL)
    return 0;

  if (strcasecmp(cmd, "/quit") == 0 || strcasecmp(cmd, "/exit") == 0)
    return 1;
  if (strcasecmp(cmd, "/help") == 0) {
    cmd_help();
  } else if (strcasecmp(cmd, "/nodes") == 0 ||
      strcasecmp(cmd, "/names") == 0) {
    cmd_nodes();
  } else if (strcasecmp(cmd, "/chans") == 0 ||
      strcasecmp(cmd, "/channels") == 0) {
    cmd_chans();
  } else if (strcasecmp(cmd, "/whoami") == 0) {
    refresh_status();
    {
      const struct node *me = node_find(my_num);

      hdrmsg("this node");
      sysmsg("id        !%08x", my_num);
      sysmsg("long      %s",
          (me != NULL && me->longname[0]) ? me->longname : "(unset)");
      sysmsg("short     %s",
          (me != NULL && me->shortname[0]) ? me->shortname : "(unset)");
      sysmsg("firmware  %s", fw_version[0] ? fw_version : "(not reported)");
      if (hw_model >= 0)
        sysmsg("hw model  %d", hw_model);
      sysmsg("channel   %s", chan_str(cur_chan));
    }
    sysmsg("region    %s%s", lora_region >= 0 ? region_str(lora_region) :
        "not reported",
        (lora_region == 0) ? "  (UNSET -- the node will not transmit)" : "");
    sysmsg("preset    %s%s", preset_str(),
        (lora_seen && lora_use_preset && lora_preset >= NPRESETS) ?
        "  (newer than this build knows)" : "");
    if (dev_seen)
      sysmsg("led       %s", dev_led_off ? "off" : "on");
    if (has_bt) {
      /*
       * Config.bluetooth.enabled is the stored setting, not the live
       * state. ESP32 cannot run WiFi and BLE at once -- the firmware
       * frees the Bluetooth stack when WiFi comes up -- so reporting the
       * setting alone would be true but misleading.
       */
      if (!bt_seen)
        sysmsg("bluetooth unknown");
      else if (bt_on && has_wifi && net_wifi_on)
        sysmsg("bluetooth on  (inactive: wifi has the radio)");
      else
        sysmsg("bluetooth %s", bt_on ? "on" : "off");
    }
    if (has_wifi) {
      if (!net_seen) {
        sysmsg("wifi      unknown");
      } else if (!net_wifi_on) {
        sysmsg("wifi      off");
      } else if (net_ip != 0) {
        sysmsg("wifi      on  \"%s\"  %u.%u.%u.%u:%d%s", net_ssid,
            net_ip & 0xff, (net_ip >> 8) & 0xff, (net_ip >> 16) & 0xff,
            (net_ip >> 24) & 0xff, TCP_PORT,
            net_connected ? "" : "  (not associated)");
        if (net_rssi != 0)
          sysmsg("signal    %d dBm", net_rssi);
      } else {
        sysmsg("wifi      on  \"%s\"  (no address -- not associated?)",
            net_ssid[0] ? net_ssid : "?");
      }
    }
  } else if (strcasecmp(cmd, "/name") == 0) {
    cmd_owner_set(args);
  } else if (strcasecmp(cmd, "/region") == 0) {
    cmd_region(args);
  } else if (strcasecmp(cmd, "/wifi") == 0) {
    cmd_wifi(args);
  } else if (strcasecmp(cmd, "/led") == 0) {
    cmd_led(args);
  } else if (strcasecmp(cmd, "/bt") == 0) {
    cmd_bt(args);
  } else if (strcasecmp(cmd, "/reboot") == 0) {
    cmd_reboot(args);
  } else if (strcasecmp(cmd, "/chan") == 0) {
    cmd_chan(args);
  } else if (strcasecmp(cmd, "/mute") == 0) {
    cmd_mute(args);
  } else if (strcasecmp(cmd, "/set") == 0) {
    cmd_set(args);
  } else if (strcasecmp(cmd, "/save") == 0) {
    cmd_save();
  } else if (strcasecmp(cmd, "/join") == 0) {
    int idx;

    if (args == NULL) {
      errmsg("usage: /join #channel|index");
    } else if ((idx = chan_lookup(args)) < 0) {
      errmsg("no such channel: %s", args);
    } else {
      cur_chan = idx;
      cur_dm = 0;
      sysmsg("now on %s", chan_str(idx));
    }
  } else if (strcasecmp(cmd, "/query") == 0) {
    uint32_t n;

    if (args == NULL || *args == '\0') {
      cur_dm = 0;
      sysmsg("back to %s", chan_str(cur_chan));
    } else {
      if (*args == '@')
        args++;
      if ((n = node_lookup(args)) == 0)
        errmsg("unknown node: %s", args);
      else {
        cur_dm = n;
        sysmsg("messaging %s", node_str(n));
      }
    }
  } else if (strcasecmp(cmd, "/msg") == 0) {
    char *target, *text;
    uint32_t n;
    char ts[16];

    target = strtok(args, " \t");
    text = strtok(NULL, "");
    if (target == NULL || text == NULL) {
      errmsg("usage: /msg @node text");
    } else {
      if (*target == '@')
        target++;
      if ((n = node_lookup(target)) == 0) {
        errmsg("unknown node: %s", target);
      } else if (send_text(text, n, 0) == 0) {
        stamp(ts, sizeof(ts));
        emit("%s%s%s*-> %s*%s %s", col(C_TIME), ts,
            col(C_DM), node_str(n), col(C_RESET), text);
      }
    }
  } else {
    errmsg("unknown command: %s  (try /help)", cmd);
  }
  return 0;
}

/* ====================================================================== */
/* terminal                                                               */
/* ====================================================================== */

static void
tty_restore(void)
{
  if (tio_saved) {
    tcsetattr(STDIN_FILENO, TCSANOW, &saved_tio);
    tio_saved = 0;
  }
  if (rawmode) {
    fputs("\r\033[K", stdout);
    fflush(stdout);
    rawmode = 0;
  }
}

static void
on_signal(int sig)
{
  (void)sig;
  quitflag = 1;
}

static int
tty_raw(void)
{
  struct termios t;

  if (tcgetattr(STDIN_FILENO, &saved_tio) < 0)
    return -1;
  tio_saved = 1;
  t = saved_tio;
  /*
   * Only disable line buffering and echo. OPOST stays on so "\n"
   * still produces a carriage return, and ISIG stays on so ctrl-C
   * reaches the signal handler that restores the terminal.
   */
  t.c_lflag &= ~(ICANON | ECHO);
  t.c_cc[VMIN] = 1;
  t.c_cc[VTIME] = 0;
  if (tcsetattr(STDIN_FILENO, TCSANOW, &t) < 0)
    return -1;
  rawmode = 1;
  return 0;
}

/* Handle one keystroke. Returns 1 when the caller should quit. */
static int
key(unsigned char c)
{
  static int esc;
  char line[MAX_INPUT + 1];

  if (esc == 1) {
    esc = (c == '[' || c == 'O') ? 2 : 0;
    return 0;
  }
  if (esc == 2) {
    /*
     * Consume CSI parameter and intermediate bytes so a modified arrow
     * such as ESC [ 1 ; 5 A is recognised rather than having its digits
     * fall through and land in the input line as literal text.
     */
    if ((c >= '0' && c <= '9') || c == ';' || c == '?')
      return 0;
    esc = 0;
    if (c == 'A')                       /* up */
      hist_up();
    else if (c == 'B')                  /* down */
      hist_down();
    else if (c == 'D' && icur > 0)      /* left */
      icur = u8_back(ibuf, icur, 1);
    else if (c == 'C' && icur < ilen)   /* right */
      icur = u8_fwd(ibuf, ilen, icur, 1);
    else if (c == 'H')                  /* home */
      icur = 0;
    else if (c == 'F')                  /* end */
      icur = ilen;
    input_draw();
    return 0;
  }

  switch (c) {
  case 0x1b:
    esc = 1;
    return 0;
  case '\r':
  case '\n':
    memcpy(line, ibuf, ilen);
    line[ilen] = '\0';
    hist_push(line);
    hist_pos = -1;
    ilen = icur = 0;
    ibuf[0] = '\0';
    input_draw();
    if (line[0] == '/')
      return do_command(line);
    say(line);
    return 0;
  case 0x7f:
  case 0x08:
    if (icur > 0) {
      size_t prev = u8_back(ibuf, icur, 1);

      memmove(ibuf + prev, ibuf + icur, ilen - icur + 1);
      ilen -= icur - prev;
      icur = prev;
    }
    break;
  case 0x01:    /* ctrl-A */
    icur = 0;
    break;
  case 0x05:    /* ctrl-E */
    icur = ilen;
    break;
  case 0x15:    /* ctrl-U */
    ilen = icur = 0;
    ibuf[0] = '\0';
    hist_pos = -1;
    break;
  case 0x17:    /* ctrl-W */
    while (icur > 0 && isspace((unsigned char)ibuf[icur - 1])) {
      memmove(ibuf + icur - 1, ibuf + icur, ilen - icur + 1);
      icur--;
      ilen--;
    }
    while (icur > 0 && !isspace((unsigned char)ibuf[icur - 1])) {
      memmove(ibuf + icur - 1, ibuf + icur, ilen - icur + 1);
      icur--;
      ilen--;
    }
    break;
  case 0x0c:    /* ctrl-L */
    fputs("\033[2J\033[H", stdout);
    break;
  case 0x04:    /* ctrl-D */
    if (ilen == 0)
      return 1;
    break;
  default:
    if (c < 0x20 || ilen >= MAX_INPUT)
      break;
    memmove(ibuf + icur + 1, ibuf + icur, ilen - icur + 1);
    ibuf[icur++] = (char)c;
    ilen++;
    break;
  }
  input_draw();
  return 0;
}

/* ====================================================================== */
/* main                                                                   */
/* ====================================================================== */

/*
 * TCP 4403 carries byte-for-byte the same StreamAPI framing as the serial
 * port, so everything above the transport is unchanged. A receive timeout
 * stands in for the tty's VTIME so reads return instead of blocking.
 */
static const struct {
  const char *name;
  speed_t code;
} bauds[] = {
  { "9600", B9600 }, { "19200", B19200 }, { "38400", B38400 },
  { "57600", B57600 }, { "115200", B115200 }, { "230400", B230400 },
#ifdef B460800
  { "460800", B460800 },
#endif
#ifdef B921600
  { "921600", B921600 },
#endif
};

static int
set_baud(const char *arg)
{
  size_t i;

  for (i = 0; i < sizeof(bauds) / sizeof(bauds[0]); i++)
    if (strcmp(arg, bauds[i].name) == 0) {
      link_baud = bauds[i].code;
      return 0;
    }
  fprintf(stderr, "meshterm: unsupported baud %s (try", arg);
  for (i = 0; i < sizeof(bauds) / sizeof(bauds[0]); i++)
    fprintf(stderr, " %s", bauds[i].name);
  fprintf(stderr, ")\n");
  return -1;
}

static int
open_tcp(const char *spec)
{
  struct addrinfo hints, *res, *rp;
  struct timeval tv;
  char host[128], *colon;
  const char *port = "4403";
  int fd = -1, err, one = 1;

  snprintf(host, sizeof(host), "%s", spec);
  colon = strrchr(host, ':');
  if (colon != NULL && strchr(host, ':') == colon) {   /* not a bare IPv6 */
    *colon = '\0';
    port = colon + 1;
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if ((err = getaddrinfo(host, port, &hints, &res)) != 0) {
    fprintf(stderr, "meshterm: %s: %s\n", host, gai_strerror(err));
    return -1;
  }
  for (rp = res; rp != NULL; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0)
      continue;
    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
      break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) {
    fprintf(stderr, "meshterm: connect %s:%s: %s\n", host, port,
        strerror(errno));
    return -1;
  }

  /* Frames are small and latency matters more than packing. */
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  tv.tv_sec = 0;
  tv.tv_usec = 200000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  is_tcp = 1;
  return fd;
}

static int
open_port(const char *dev)
{
  struct termios t;
  int fd, flags;

  if (strncmp(dev, "tcp:", 4) == 0)
    return open_tcp(dev + 4);

  fd = open(dev, O_RDWR | O_NOCTTY | O_NONBLOCK);
  if (fd < 0) {
    fprintf(stderr, "meshterm: %s: %s\n", dev, strerror(errno));
    return -1;
  }
  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
    perror("fcntl");
    close(fd);
    return -1;
  }
  if (tcgetattr(fd, &t) < 0) {
    perror("tcgetattr");
    close(fd);
    return -1;
  }
  cfmakeraw(&t);
  t.c_cflag |= (CLOCAL | CREAD);
  t.c_cflag &= ~(CRTSCTS | HUPCL);
  t.c_cflag &= ~(CSIZE | PARENB | CSTOPB);
  t.c_cflag |= CS8;
  t.c_cc[VMIN] = 0;
  t.c_cc[VTIME] = 1;
  if (cfsetispeed(&t, link_baud) < 0 || cfsetospeed(&t, link_baud) < 0 ||
      tcsetattr(fd, TCSANOW, &t) < 0) {
    perror("termios");
    close(fd);
    return -1;
  }
  tcflush(fd, TCIOFLUSH);
  return fd;
}

/* Drain the port for up to `secs`, decoding frames. Returns 1 if the
 * nonce came back as config_complete_id. */
/*
 * Read and decode for roughly ms milliseconds. Returns 1 if the handshake
 * nonce came back, 2 if everything refresh_status is waiting on arrived,
 * 0 on timeout, -1 on a link error.
 */
static int
pump_ms(int ms)
{
  unsigned char buf[512];
  struct timeval tv;
  fd_set rfds;
  ssize_t n;
  size_t i;
  int left = ms;

  while (left > 0 && !quitflag) {
    int slice = left < 100 ? left : 100;

    FD_ZERO(&rfds);
    FD_SET(serial_fd, &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = slice * 1000;
    if (select(serial_fd + 1, &rfds, NULL, NULL, &tv) < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    left -= slice;
    if (!FD_ISSET(serial_fd, &rfds))
      continue;
    n = read(serial_fd, buf, sizeof(buf));
    if (n < 0) {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
        continue;
      return -1;
    }
    if (n == 0 && is_tcp)
      return -1;
    for (i = 0; i < (size_t)n; i++) {
      if (!feed(buf[i]))
        continue;
      dbg_flush();
      if (handle_fromradio(rxframe, rxlen) == pump_nonce && pump_nonce != 0)
        return 1;
      if (fresh_want != 0 && (fresh_got & fresh_want) == fresh_want)
        return 2;
    }
  }
  return 0;
}

static int
pump(int secs, uint32_t nonce)
{
  unsigned char buf[512];
  time_t end = time(NULL) + secs;
  ssize_t n;
  size_t i;

  while (time(NULL) < end && !quitflag) {
    n = read(serial_fd, buf, sizeof(buf));
    if (n < 0) {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
        continue;
      errmsg("read: %s", strerror(errno));
      return -1;
    }
    if (n == 0 && is_tcp) {
      errmsg("connection closed by peer");
      return -1;
    }
    for (i = 0; i < (size_t)n; i++) {
      if (!feed(buf[i]))
        continue;
      dbg_flush();
      if (handle_fromradio(rxframe, rxlen) == nonce && nonce != 0)
        return 1;
      if (fresh_want != 0 && (fresh_got & fresh_want) == fresh_want)
        return 2;
    }
  }
  return 0;
}

/*
 * Open the link, resync the parser, and complete the handshake. Used both
 * at startup and after a drop -- /reboot, /wifi and /region all restart the
 * node, so losing the link is a normal event rather than an error.
 */
static int
link_up(void)
{
  unsigned char *wake;
  uint32_t nonce;
  time_t end;
  int ok = 0;

  rxstate = 0;
  rxlen = rxwant = 0;
  dbglen = 0;
  session_key_len = 0;
  pend_clear();

  if ((serial_fd = open_port(dev_path)) < 0)
    return -1;

  if ((wake = malloc(WAKE_BYTES)) == NULL) {
    perror("malloc");
    close(serial_fd);
    serial_fd = -1;
    return -1;
  }
  memset(wake, START2, WAKE_BYTES);
  if (write(serial_fd, wake, WAKE_BYTES) != (ssize_t)WAKE_BYTES)
    perror("write (wake)");
  free(wake);
  if (!is_tcp)
    tcdrain(serial_fd);
  usleep(100000);

  nonce = (uint32_t)rand() | 1u;
  sysmsg("connecting to %s", dev_path);
  end = time(NULL) + HANDSHAKE_S;
  while (time(NULL) < end && !quitflag) {
    if (send_want_config(nonce) < 0)
      break;
    if ((ok = pump(HS_RETRY_S, nonce)) != 0)
      break;
    sysmsg("no reply, retrying...");
  }
  if (ok != 1) {
    errmsg("handshake failed");
    close(serial_fd);
    serial_fd = -1;
    return -1;
  }
  sysmsg("connected as %s", my_num ? node_str(my_num) : "unknown");
  if (has_wifi)
    cmd_net_quiet();
  return 0;
}

/*
 * Reconnect with backoff. Returns 0 once the link is back, -1 if the user
 * gave up. A node that has just been told to reboot takes a few seconds to
 * come back, and a TCP node considerably longer.
 */
static int
link_retry(void)
{
  int delay = 2;

  if (serial_fd >= 0) {
    close(serial_fd);
    serial_fd = -1;
  }
  while (!quitflag) {
    int i;

    sysmsg("link lost -- reconnecting in %ds (ctrl-c to give up)", delay);
    for (i = 0; i < delay && !quitflag; i++)
      sleep(1);
    if (quitflag)
      break;
    if (link_up() == 0)
      return 0;
    if ((delay *= 2) > 30)
      delay = 30;
  }
  return -1;
}

static void
usage(void)
{
  fprintf(stderr,
      "usage: meshterm [-p port] [-b baud] [-c rcfile] [-v] [-t|-T] [-x]\n"
      "                [-C] [-m message]\n"
      "  -p port     serial device (default /dev/cuaU0), or\n"
      "              tcp:HOST[:PORT] for a networked node (default port 4403)\n"
      "  -b baud     serial speed (default 115200)\n"
      "  -c rcfile   settings file (default ~/.meshtermrc)\n"
      "  -v          verbose: firmware debug and protocol detail\n"
      "  -t / -T     timestamps on / off\n"
      "  -x          show hex node ids alongside names\n"
      "  -C          disable colour\n"
      "  -m message  send one message and exit\n");
  exit(2);
}

int
main(int argc, char **argv)
{
  const char *rc = NULL;
  const char *oneshot = NULL;
  time_t next_hb;
  int ch, rc_time = -1, rc_hex = -1, rc_color = -1, rc_verbose = -1;

  while ((ch = getopt(argc, argv, "p:b:c:vtTxCm:h")) != -1) {
    switch (ch) {
    case 'p': dev_path = optarg; break;
    case 'c': rc = optarg; break;
    case 'v': rc_verbose = 1; break;
    case 't': rc_time = 1; break;
    case 'T': rc_time = 0; break;
    case 'x': rc_hex = 1; break;
    case 'C': rc_color = 0; break;
    case 'b':
      if (set_baud(optarg) < 0)
        return 2;
      break;
    case 'm': oneshot = optarg; break;
    default: usage();
    }
  }

  load_rc(rc);
  /* explicit flags win over the rc file */
  if (rc_time >= 0) pref_time = rc_time;
  if (rc_hex >= 0) pref_hex = rc_hex;
  if (rc_verbose >= 0) pref_verbose = rc_verbose;

  interactive = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
  if (!interactive)
    pref_color = 0;
  {
    /* No TERM, or TERM=dumb, means emit no escapes at all. */
    const char *term = getenv("TERM");

    if (term == NULL || *term == '\0' || strcmp(term, "dumb") == 0)
      pref_color = 0;
    if (rc_color >= 0)
      pref_color = rc_color;    /* an explicit flag beats TERM */
  }

  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  signal(SIGHUP, on_signal);

  srand((unsigned)time(NULL) ^ (unsigned)getpid());

  if (link_up() < 0)
    return 1;
  if (interactive)
    sysmsg("/help for commands");

  if (oneshot != NULL) {
    say(oneshot);
    pump(1, 0);
    send_disconnect();
    close(serial_fd);
    return 0;
  }

  if (interactive && tty_raw() == 0)
    atexit(tty_restore);
  input_draw();

  next_hb = time(NULL) + HEARTBEAT_S;
  while (!quitflag) {
    unsigned char buf[512];
    struct timeval tv = { 1, 0 };
    fd_set rfds;
    int maxfd;
    ssize_t n;
    size_t i;

    FD_ZERO(&rfds);
    FD_SET(serial_fd, &rfds);
    FD_SET(STDIN_FILENO, &rfds);
    maxfd = serial_fd > STDIN_FILENO ? serial_fd : STDIN_FILENO;

    if (select(maxfd + 1, &rfds, NULL, NULL, &tv) < 0) {
      if (errno == EINTR)
        continue;
      errmsg("select: %s", strerror(errno));
      break;
    }

    if (FD_ISSET(serial_fd, &rfds)) {
      n = read(serial_fd, buf, sizeof(buf));
      if ((n < 0 && errno != EINTR && errno != EAGAIN &&
          errno != EWOULDBLOCK) || (n == 0 && is_tcp)) {
        if (n == 0)
          errmsg("connection closed by peer");
        else
          errmsg("read: %s", strerror(errno));
        if (link_retry() < 0)
          break;
        next_hb = time(NULL) + HEARTBEAT_S;
        continue;
      }
      for (i = 0; i < (size_t)(n > 0 ? n : 0); i++)
        if (feed(buf[i])) {
          dbg_flush();
          handle_fromradio(rxframe, rxlen);
        }
    }

    if (FD_ISSET(STDIN_FILENO, &rfds)) {
      n = read(STDIN_FILENO, buf, sizeof(buf));
      if (n <= 0)
        break;          /* EOF on stdin */
      if (rawmode) {
        for (i = 0; i < (size_t)n; i++)
          if (key(buf[i]))
            goto done;
      } else {
        /* line mode: pipe-friendly */
        for (i = 0; i < (size_t)n; i++) {
          if (buf[i] == '\n') {
            ibuf[ilen] = '\0';
            ilen = 0;
            if (ibuf[0] == '/') {
              if (do_command(ibuf))
                goto done;
            } else
              say(ibuf);
          } else if (ilen < MAX_INPUT)
            ibuf[ilen++] = (char)buf[i];
        }
      }
    }

    if (time(NULL) >= next_hb) {
      send_heartbeat();
      next_hb = time(NULL) + HEARTBEAT_S;
    }
  }
done:
  tty_restore();
  sysmsg("disconnecting");
  send_disconnect();
  close(serial_fd);
  return 0;
}

